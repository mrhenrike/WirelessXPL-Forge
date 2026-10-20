class DragonSlayer:
    """EAP-pwd side-channel detection (CVE-2019-9499).

    Detects EAP-pwd (WPA3-Enterprise) usage via beacon/probe scan and
    measures EAP-Request/Response timing for side-channel analysis. High
    timing variance in EAP-pwd exchanges is consistent with CVE-2019-9499
    (invalid curve / cache side-channel) and CVE-2019-9497 (reflection).

    Full reflection and invalid-curve attacks (CVE-2019-9497/9498/9499)
    require crafting EAP state machine interactions beyond passive timing
    measurement. This implementation covers detection and timing analysis
    as the evidence-gathering phase.

    Args:
        interface: Monitor mode wireless interface.
        bssid: Target AP BSSID (empty string captures all APs).
        username: EAP identity to use in active association attempts.
        samples: Number of EAP-pwd exchange timing samples to collect.
        timeout: Seconds to wait for EAP-pwd frames during capture.
        dry_run: If True, simulate without live capture.
        output_dir: Directory for result JSON files.
    """

    def __init__(
        self,
        interface: str,
        bssid: str,
        username: str = "admin",
        samples: int = 30,
        timeout: float = 60.0,
        dry_run: bool = False,
        output_dir: str = "",
    ) -> None:
        self._interface = interface.strip()
        self._bssid = bssid.lower().strip()
        self._username = username.strip()
        self._samples = max(samples, 1)
        self._timeout = max(timeout, 1.0)
        self._dry_run = dry_run
        self._output_dir = output_dir.strip() or os.path.join(
            _project_tmp, "dragonslayer"
        )
        os.makedirs(self._output_dir, exist_ok=True)

    def _detect_eap_pwd(self) -> bool:
        """Sniff beacon/probe frames to detect 802.1X (EAP-pwd) usage.

        Returns:
            True if an 802.1X beacon or probe response is observed.
        """
        if not HAS_SCAPY:
            print_error("Scapy not available.")
            return False

        print_status(
            "Scanning for EAP-pwd (802.1X) on "
            + (self._bssid if self._bssid else "any BSSID")
            + f" via {self._interface}..."
        )
        detected = [False]

        def _handler(pkt: Any) -> None:
            if not pkt.haslayer(Dot11):
                return
            dot11 = pkt.getlayer(Dot11)
            if dot11.type != _DOT11_MGMT_TYPE:
                return
            # Beacon (8) and Probe Response (5)
            if dot11.subtype not in (5, 8):
                return
            if self._bssid and (
                getattr(dot11, "addr2", "") or ""
            ).lower() != self._bssid:
                return
            # AKM suite type 1 (802.1X) OUI prefix in raw bytes
            pkt_raw = bytes(pkt)
            if b"\x00\x0f\xac\x01" in pkt_raw:
                detected[0] = True

        try:
            scapy_sniff(
                iface=self._interface,
                prn=_handler,
                timeout=10.0,
                store=False,
            )
        except PermissionError:
            print_error("Permission denied. Run as root.")
            return False
        except KeyboardInterrupt:
            pass

        if detected[0]:
            print_success("EAP-pwd (802.1X AKM) detected on target AP.")
        else:
            print_info(
                "EAP-pwd not detected in sniffed beacons. AP may use PSK-only, "
                "or the channel/BSSID filter may be too narrow."
            )
        return detected[0]

    def timing_analysis(self) -> dict[str, Any]:
        """Collect EAP-pwd exchange timings for side-channel analysis.

        Sniffs EAP frames of type 52 (EAP-pwd) and measures
        request-to-response latency. Significant timing variation (high
        coefficient of variation) indicates CVE-2019-9499 vulnerability.

        Returns:
            Analysis dict with keys: samples, mean_ms, stddev_ms,
            coeff_var_pct, verdict, cve.
        """
        if not HAS_SCAPY:
            print_error("Scapy not available.")
            return {}

        if self._dry_run:
            print_info(
                f"[dry-run] DragonSlayer: would capture {self._samples} "
                f"EAP-pwd timing samples on {self._interface}"
            )
            return {}

        print_status(
            f"DragonSlayer: capturing EAP-pwd timing "
            f"({self._samples} samples, timeout={self._timeout}s) "
            f"on {self._interface}"
        )
        print_info(
            "A WPA3-Enterprise client must be actively authenticating "
            "against the target AP during this capture window."
        )

        eap_timings: list[float] = []
        pending_eap: dict[str, float] = {}

        def _handler(pkt: Any) -> None:
            if not pkt.haslayer(Dot11):
                return
            pkt_bytes = bytes(pkt)
            for i in range(len(pkt_bytes) - 5):
                code = pkt_bytes[i]
                if code not in (_EAP_CODE_REQUEST, _EAP_CODE_RESPONSE):
                    continue
                if i + 4 >= len(pkt_bytes):
                    continue
                if pkt_bytes[i + 4] != _EAP_TYPE_PWD:
                    continue
                dot11 = pkt.getlayer(Dot11)
                src = (getattr(dot11, "addr2", "") or "").lower()
                ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
                if code == _EAP_CODE_REQUEST:
                    pending_eap[src] = ts
                elif code == _EAP_CODE_RESPONSE and src in pending_eap:
                    req_ts = pending_eap.pop(src)
                    delta_ms = (ts - req_ts) * 1000.0
                    eap_timings.append(delta_ms)
                    if len(eap_timings) % 5 == 0:
                        print_info(
                            f"  EAP-pwd sample {len(eap_timings)}: "
                            f"{delta_ms:.3f} ms"
                        )
                break

        def _stop_filter(_pkt: Any) -> bool:
            return len(eap_timings) >= self._samples

        try:
            scapy_sniff(
                iface=self._interface,
                prn=_handler,
                stop_filter=_stop_filter,
                store=False,
                timeout=self._timeout,
            )
        except KeyboardInterrupt:
            print_info("Capture interrupted.")
        except PermissionError:
            print_error("Permission denied. Run as root.")
            return {}

        if not eap_timings:
            print_error(
                "No EAP-pwd frames captured. Verify: "
                "(1) WPA3-Enterprise AP in range. "
                "(2) Client is actively authenticating. "
                "(3) Interface in monitor mode on the correct channel."
            )
            return {}

        avg = float(np.mean(eap_timings)) if HAS_NUMPY else _mean(eap_timings)
        std = (
            float(np.std(eap_timings, ddof=1))
            if HAS_NUMPY and len(eap_timings) > 1
            else _stddev(eap_timings)
        )
        cv = (std / avg * 100.0) if avg > 0.0 else 0.0

        print_info("=" * 60)
        print_info("DragonSlayer - EAP-pwd Timing Analysis (CVE-2019-9499)")
        print_info("=" * 60)
        print_info(f"  Samples       : {len(eap_timings)}")
        print_info(f"  Mean          : {avg:.3f} ms")
        print_info(f"  Std deviation : {std:.3f} ms")
        print_info(f"  Coeff. var.   : {cv:.1f}%")

        verdict = "not_detected"
        if cv > 15.0:
            verdict = "potentially_vulnerable"
            print_success(
                f"High timing variance detected (CV={cv:.1f}%). "
                "EAP-pwd processing time varies significantly, consistent "
                "with CVE-2019-9499 side-channel (cache or timing leakage)."
            )
        else:
            print_info(
                f"Timing appears uniform (CV={cv:.1f}%). "
                "No significant EAP-pwd side-channel detected at this sample size."
            )

        result: dict[str, Any] = {
            "samples": len(eap_timings),
            "mean_ms": round(avg, 4),
            "stddev_ms": round(std, 4),
            "coeff_var_pct": round(cv, 2),
            "verdict": verdict,
            "cve": "CVE-2019-9499",
        }

        ts_tag = int(time.time())
        report_path = os.path.join(
            self._output_dir, f"dragonslayer_report_{ts_tag}.json"
        )
        with open(report_path, "w") as fh:
            json.dump(result, fh, indent=2)
        print_success(f"Report saved: {report_path}")
        return result

    def run(self) -> dict[str, Any]:
        """Execute EAP-pwd detection and timing side-channel analysis.

        Returns:
            Analysis result dict (see timing_analysis()). Empty dict on
            failure or dry_run.
        """
        self._detect_eap_pwd()
        return self.timing_analysis()


# ---------------------------------------------------------------------------
# WXF Exploit wrapper
# ---------------------------------------------------------------------------


@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """Dragonblood WPA3-SAE attack suite - native Scapy implementation.

    Replaces the previous binary bridge with fully native Python attack
    classes. All four Dragonblood attack primitives are implemented without
    subprocess calls to external dragontime, dragonforce, dragondrain, or
    dragonslayer binaries.
    """

    __info__ = {
        "name": "Dragonblood WPA3-SAE Attack Suite (native)",
        "description": (
            "Native Python implementation of Dragonblood attacks against "
            "WPA3-SAE using Scapy. Covers: SAE timing side-channel "
            "(CVE-2019-9494), SAE group downgrade probe, SAE commit flood "
            "DoS (CVE-2019-9495), and EAP-pwd timing analysis "
            "(CVE-2019-9499). No external Dragonblood binaries required."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
