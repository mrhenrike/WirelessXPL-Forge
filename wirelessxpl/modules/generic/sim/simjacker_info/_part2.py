class Exploit(Exploit):
    """SIMJacker, WIBattack, and SIM Toolkit attack research and detection."""

    __info__ = {
        "name": "SIMJacker / WIBattack Detection and Analysis",
        "description": (
            "Comprehensive reference and detection module for SIM-based OTA attacks: "
            "SIMJacker (CVE-2019-16256/57), WIBattack (GSMA CVD-2019-0026), and SIM "
            "Toolkit exploitation vectors. Detects S@T Browser and WIB applets on "
            "SIM cards, enumerates STK applications, analyzes OTA SMS structure, "
            "maintains a CVE database, and provides mitigation guidance."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://simjacker.com/",
            "https://ginnoslab.org/wibattack/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-16256",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-16257",
        ),
        "devices": ("sim", "usim", "cellular"),
    }

    mode = OptString(
        "info",
        "Mode: info, simjacker_detail, wibattack_detail, stk_attacks, "
        "ota_sms_analysis, detect_vulnerable, scan_stk_apps, cve_database, mitigation",
    )
    reader_index = OptInteger(0, "PC/SC reader index for SIM card")
    output_dir = OptString(".tmp", "Output directory for results")
    i_know_scope = OptBool(False, "Confirm authorized lab and SIM ownership")

    def _get_reader(self) -> Any | None:
        """Get PC/SC reader connection."""
        if not HAS_PYSCARD:
            print_error("pyscard not installed. Install with: pip install pyscard")
            return None
        available = sc_readers()
        idx = int(self.reader_index)
        if idx >= len(available):
            print_error(
                f"Reader index {idx} not found. Available: "
                f"{[str(r) for r in available]}"
            )
            return None
        reader = available[idx]
        print_status(f"Using reader: {reader}")
        try:
            connection = reader.createConnection()
            connection.connect()
            return connection
        except Exception as exc:
            print_error(f"Failed to connect to reader: {exc}")
            return None

    def _send_apdu(self, connection: Any, apdu: list[int]) -> tuple[list[int], int]:
        """Send APDU command and return (data, sw)."""
        data, sw1, sw2 = connection.transmit(apdu)
        sw = (sw1 << 8) | sw2
        return data, sw

    def _try_select_aid(
        self, connection: Any, aid_hex: str, label: str
    ) -> bool:
        """Attempt to SELECT an applet by AID. Returns True if found."""
        aid_bytes = [int(aid_hex[i:i + 2], 16) for i in range(0, len(aid_hex), 2)]
        apdu = CMD_SELECT_AID + [len(aid_bytes)] + aid_bytes
        data, sw = self._send_apdu(connection, apdu)
        if sw == 0x9000:
            print_error(f"  FOUND: {label} (AID: {aid_hex}) - SIM is VULNERABLE")
            return True
        elif (sw >> 8) == 0x61:
            print_error(f"  FOUND: {label} (AID: {aid_hex}) - SIM is VULNERABLE")
            return True
        else:
            print_info(f"  Not found: {label} (AID: {aid_hex}, SW={sw:04X})")
            return False

    def _info(self) -> None:
        """Complete technical overview of SIM-based OTA attacks."""
        print_info("SIMJacker, WIBattack, and SIM Toolkit Attack Reference")
        print_info("=" * 58)
        print_info("")
        print_info("SIMJacker (CVE-2019-16256, CVE-2019-16257):")
        print_info("  Discovered by AdaptiveMobile Security (Sep 2019).")
        print_info("  Exploits the S@T Browser (SIMalliance Toolbox Browser)")
        print_info("  pre-installed on SIM cards by some operators.")
        print_info("  Attack: send crafted binary SMS -> S@T Browser executes")
        print_info("  STK commands -> exfiltrate location/IMEI via SMS response.")
        print_info("  Actively exploited in the wild for surveillance.")
        print_info("  Affected: ~1 billion SIM cards across 30+ countries.")
        print_info("")
        print_info("WIBattack (GSMA CVD-2019-0026):")
        print_info("  Discovered by Ginno Security Lab (Sep 2019).")
        print_info("  Same class of attack targeting the WIB (Wireless Internet")
        print_info("  Browser) applet instead of S@T Browser.")
        print_info("  WIB is deployed by different SIM vendors/operators.")
        print_info("")
        print_info("SIM Toolkit (STK) Attack Surface:")
        print_info("  STK enables SIM-resident applets to execute proactive commands:")
        print_info("  SETUP CALL, SEND SMS, PROVIDE LOCAL INFO, OPEN CHANNEL, etc.")
        print_info("  Any SIM applet with OTA access can be exploited similarly.")
        print_info("")
        print_info("MODES:")
        print_info("  info               - This overview")
        print_info("  simjacker_detail   - Deep dive on SIMJacker attack flow")
        print_info("  wibattack_detail   - Deep dive on WIBattack")
        print_info("  stk_attacks        - All STK attack vectors")
        print_info("  ota_sms_analysis   - OTA SMS structure breakdown")
        print_info("  detect_vulnerable  - Check SIM for S@T/WIB applets")
        print_info("  scan_stk_apps      - Enumerate STK apps on SIM")
        print_info("  cve_database       - List all related CVEs")
        print_info("  mitigation         - Operator and user mitigations")

    def _simjacker_detail(self) -> None:
        """Deep dive on SIMJacker attack flow."""
        print_info("SIMJacker Attack - Detailed Technical Breakdown")
        print_info("=" * 50)
        print_info("")
        print_info("PREREQUISITES:")
        print_info("  - Target SIM has S@T Browser installed")
        print_info("  - Operator network delivers binary SMS (UDH port addressing)")
        print_info("  - OTA security level set to minimum (no crypto, or weak KIC/KID)")
        print_info("")
        print_info("ATTACK FLOW:")
        print_info("  1. Attacker sends binary SMS to target MSISDN")
        print_info("     - SMS contains SIM Toolkit Security Header (SPI, KIC, KID)")
        print_info("     - TAR (Toolkit Application Reference) targets S@T Browser")
        print_info("     - Payload: STK commands wrapped in OTA envelope")
        print_info("")
        print_info("  2. SIM card processes the binary SMS:")
        print_info("     a. Baseband passes SMS to SIM via proactive polling")
        print_info("     b. SIM checks OTA security headers (if any)")
        print_info("     c. S@T Browser interprets the STK command sequence")
        print_info("")
        print_info("  3. S@T Browser executes proactive commands:")
        print_info("     a. PROVIDE LOCAL INFO -> retrieves Cell-ID, IMEI")
        print_info("     b. SEND SMS -> sends data to attacker's number")
        print_info("     c. All transparent to user (no notification)")
        print_info("")
        print_info("  4. Response SMS with location/IMEI arrives at attacker")
        print_info("")
        print_info("OTA SECURITY LEVELS (SPI byte):")
        print_info("  0x00: No security (fully vulnerable)")
        print_info("  0x01: RC (Redundancy Check only)")
        print_info("  0x02: CC (Cryptographic Checksum - DES/3DES/AES)")
        print_info("  0x06: CC + Encryption")
        print_info("  Many deployed S@T cards use level 0x00 or 0x01.")
        print_info("")
        print_info("EXTENDED CAPABILITIES:")
        print_info("  - SETUP CALL: initiate phone calls silently")
        print_info("  - SEND USSD: execute USSD codes (balance drain)")
        print_info("  - OPEN CHANNEL: establish data connection (GPRS/LTE)")
        print_info("  - LAUNCH BROWSER: open URL on device")
        print_info("  - PLAY TONE: trigger audio on device")

    def _wibattack_detail(self) -> None:
        """Deep dive on WIBattack."""
        print_info("WIBattack - Detailed Technical Breakdown")
        print_info("=" * 45)
        print_info("")
        print_info("WIB (Wireless Internet Browser):")
        print_info("  Developed by SmartTrust (now Giesecke+Devrient)")
        print_info("  WAP browser embedded on SIM cards for OTA services")
        print_info("  Deployed independently from S@T Browser")
        print_info("")
        print_info("ATTACK SIMILARITIES WITH SIMJACKER:")
        print_info("  - Same binary SMS OTA delivery mechanism")
        print_info("  - Same STK proactive command execution")
        print_info("  - Same data exfiltration via SEND SMS")
        print_info("  - Same lack of user notification")
        print_info("")
        print_info("KEY DIFFERENCES:")
        print_info("  - Different TAR (targets WIB applet, not S@T)")
        print_info("  - Different AID for applet selection")
        print_info("  - Different vendor deployment (SmartTrust vs SIMalliance)")
        print_info("  - WIB supports additional WML/WAP commands")
        print_info("")
        print_info("WIB CAPABILITIES EXPLOITABLE VIA OTA:")
        print_info("  - PROVIDE LOCAL INFO (Cell-ID, IMEI, IMSI)")
        print_info("  - SEND SMS (data exfiltration)")
        print_info("  - SETUP CALL (silent call initiation)")
        print_info("  - SEND SS/USSD (supplementary service abuse)")
        print_info("  - OPEN CHANNEL (data channel via bearer)")
        print_info("  - DISPLAY TEXT (social engineering on device)")
        print_info("")
        print_info("DETECTION:")
        print_info("  - Check EF_DIR for WIB AID entries")
        print_info("  - Attempt SELECT of known WIB AIDs")
        print_info("  - Use detect_vulnerable mode for automated check")

    def _stk_attacks(self) -> None:
        """Overview of all SIM Toolkit attack vectors."""
        print_info("SIM Toolkit (STK) Attack Vectors")
        print_info("=" * 40)
        print_info("")
        print_info("STK proactive commands usable for attacks:")
        print_info("")

        attacks = [
            ("SETUP CALL (0x10)", [
                "Initiate phone call to premium/attacker number",
                "Silent call for audio surveillance",
                "Call forwarding setup via SS codes",
            ]),
            ("SEND SMS (0x13)", [
                "Exfiltrate location, IMEI, IMSI data",
                "Send premium SMS for financial fraud",
                "Relay commands to other targets",
            ]),
            ("SEND SS (0x14)", [
                "Enable call forwarding to attacker",
                "Modify supplementary services",
                "Query account balance/info",
            ]),
            ("SEND USSD (0x15)", [
                "Execute operator USSD codes",
                "Mobile money transfer (M-Pesa, etc.)",
                "Account information exfiltration",
            ]),
            ("PROVIDE LOCAL INFO (0x26)", [
                "Cell-ID: coarse location tracking",
                "IMEI: device fingerprinting",
                "IMSI: subscriber identification",
                "Network measurement data: signal analysis",
                "Language, date/time, battery status",
            ]),
            ("OPEN CHANNEL (0x35)", [
                "Establish data connection (TCP/UDP)",
                "Exfiltrate data over IP (bypass SMS)",
                "Connect to C2 server",
                "Download additional payloads",
            ]),
            ("LAUNCH BROWSER (0x15)", [
                "Open malicious URL",
                "Phishing page display",
                "Exploit browser vulnerabilities",
            ]),
            ("DISPLAY TEXT (0x43)", [
                "Social engineering messages",
                "Fake operator notifications",
                "Credential harvesting prompts",
            ]),
            ("SETUP EVENT LIST (0x20)", [
                "Monitor call events",
                "Track location updates",
                "Persistent surveillance trigger",
            ]),
        ]

        for cmd_name, descriptions in attacks:
            print_info(f"  {cmd_name}:")
            for desc in descriptions:
                print_info(f"    - {desc}")
            print_info("")

    def _ota_sms_analysis(self) -> None:
        """Explain OTA SMS structure for SIM Toolkit attacks."""
        print_info("OTA SMS Structure Analysis")
        print_info("=" * 35)
        print_info("")
        print_info("BINARY SMS (TP-User-Data):")
        print_info("  Delivered via SMS-PP (Point-to-Point) with UDH")
        print_info("  TP-PID: 0x7F (SIM Data Download)")
        print_info("  TP-DCS: 0xF6 (Class 2, binary)")
        print_info("")
        print_info("OTA ENVELOPE STRUCTURE:")
        print_info("  +-----+-----+-----+-----+---------+----------+")
        print_info("  | CPI | CPL | SPI | KIC | KID/TAR | SEC DATA |")
        print_info("  +-----+-----+-----+-----+---------+----------+")
        print_info("")
        print_info("  CPI (1 byte): Command Packet Identifier")
        print_info("    0x02: indicates OTA command packet")
        print_info("")
        print_info("  CPL (2 bytes): Command Packet Length")
        print_info("")
        print_info("  SPI (2 bytes): Security Parameter Indicator")
        print_info("    Byte 1: encryption/integrity mode")
        print_info("      Bit 0-1: 00=no integrity, 01=RC, 10=CC, 11=DS")
        print_info("      Bit 2: 0=no encryption, 1=encrypt")
        print_info("    Byte 2: counter/PoR settings")
        print_info("")
        print_info("  KIC (1 byte): Key Identifier for Ciphering")
        print_info("    Bits 0-1: algorithm (01=DES, 05=AES)")
        print_info("    Bits 2-3: key number")
        print_info("")
        print_info("  KID (1 byte): Key Identifier for RC/CC/DS")
        print_info("    Same structure as KIC")
        print_info("")
        print_info("  TAR (3 bytes): Toolkit Application Reference")
        print_info("    Identifies target applet on SIM")
        print_info("    S@T Browser TAR varies by operator")
        print_info("    WIB TAR varies by vendor")
        print_info("")
        print_info("  COUNTER (5 bytes): Replay protection counter")
        print_info("    If SPI indicates counter checking")
        print_info("")
        print_info("  PCNTR (1 byte): Padding counter")
        print_info("")
        print_info("  SECURED DATA: STK command(s) wrapped in envelope")
        print_info("")
        print_info("ATTACK INSIGHT:")
        print_info("  If SPI=0x0000 (no security), any binary SMS with correct")
        print_info("  TAR reaches the target applet without authentication.")
        print_info("  The applet then executes the embedded STK commands.")

    def _detect_vulnerable(self) -> None:
        """Check if SIM has S@T Browser or WIB Browser installed."""
        conn = self._get_reader()
        if not conn:
            return

        print_status("Scanning SIM for vulnerable applets...")
        print_info("")

        found_vulnerable = False

        # Check S@T Browser AIDs
        print_status("Checking S@T Browser (SIMJacker target)...")
        for aid in SAT_BROWSER_AIDS:
            if self._try_select_aid(conn, aid, f"S@T Browser ({aid})"):
                found_vulnerable = True

        print_info("")

        # Check WIB Browser AIDs
        print_status("Checking WIB Browser (WIBattack target)...")
        for aid in WIB_BROWSER_AIDS:
            if self._try_select_aid(conn, aid, f"WIB Browser ({aid})"):
                found_vulnerable = True

        print_info("")

        # Read EF_SST to check service allocation table
        print_status("Reading EF_SST (Service Table)...")
        select_apdu = CMD_SELECT_FILE + [len(EF_SST_PATH)] + EF_SST_PATH
        data, sw = self._send_apdu(conn, select_apdu)

        if sw == 0x9000 or (sw >> 8) == 0x61:
            read_apdu = CMD_READ_BINARY + [0x10]
            data, sw = self._send_apdu(conn, read_apdu)
            if sw == 0x9000 and data:
                sst_hex = "".join(f"{b:02X}" for b in data)
                print_info(f"  EF_SST: {sst_hex}")
                # Service 27 (byte 14, bit 1): OTA
                if len(data) > 13:
                    ota_byte = data[13]
                    if ota_byte & 0x01:
                        print_info("  OTA service is ALLOCATED and ACTIVATED")
                    else:
                        print_info("  OTA service not active in service table")
        else:
            print_info(f"  EF_SST not readable (SW={sw:04X})")

        # Check EF_DIR for application directory
        print_info("")
        print_status("Reading EF_DIR (Application Directory)...")
        dir_select = CMD_SELECT_FILE + [len(EF_DIR_PATH)] + EF_DIR_PATH
        data, sw = self._send_apdu(conn, dir_select)

        if sw == 0x9000 or (sw >> 8) == 0x61:
            read_apdu = CMD_READ_BINARY + [0x40]
            data, sw = self._send_apdu(conn, read_apdu)
            if sw == 0x9000 and data:
                dir_hex = "".join(f"{b:02X}" for b in data)
                print_info(f"  EF_DIR entries (raw): {dir_hex[:80]}...")
                for sat_aid in SAT_BROWSER_AIDS:
                    if sat_aid.upper() in dir_hex.upper():
                        print_error(f"  S@T Browser AID found in EF_DIR: {sat_aid}")
                        found_vulnerable = True
                for wib_aid in WIB_BROWSER_AIDS:
                    if wib_aid.upper() in dir_hex.upper():
                        print_error(f"  WIB Browser AID found in EF_DIR: {wib_aid}")
                        found_vulnerable = True
        else:
            print_info(f"  EF_DIR not readable (SW={sw:04X})")

        print_info("")
        if found_vulnerable:
            print_error("SIM card has VULNERABLE applets installed.")
            print_error("Recommend: contact operator for S@T/WIB removal or SIM replacement.")
        else:
            print_success("No known S@T Browser or WIB Browser AIDs detected.")
            print_info("Note: vendor-specific AIDs may differ from checked patterns.")

        conn.disconnect()

    def _scan_stk_apps(self) -> None:
        """Enumerate STK applications on the SIM via GET STATUS and SELECT."""
        conn = self._get_reader()
        if not conn:
            return

        print_status("Enumerating STK applications on SIM...")
        print_info("")

        # GET STATUS for card manager
        data, sw = self._send_apdu(conn, CMD_GET_STATUS)
        apps_found: list[str] = []

        if sw == 0x9000 and data:
            hex_data = "".join(f"{b:02X}" for b in data)
            print_success(f"GET STATUS response: {hex_data}")
            print_info("Parse TLV to extract individual application AIDs")
        elif (sw >> 8) == 0x61:
            remaining = sw & 0xFF
            get_resp = [0x00, 0xC0, 0x00, 0x00, remaining]
            data2, sw2 = self._send_apdu(conn, get_resp)
            if sw2 == 0x9000 and data2:
                hex_data = "".join(f"{b:02X}" for b in data2)
                print_success(f"GET STATUS response: {hex_data}")
        else:
            print_info(f"GET STATUS returned SW={sw:04X}")
            print_info("Card may not support GlobalPlatform GET STATUS.")

        # Probe common STK-related AIDs
        print_info("")
        print_status("Probing common STK/OTA application AIDs...")
        probe_aids = [
            ("A0000000090001", "S@T Browser v1"),
            ("A0000000090002", "S@T Browser v2"),
            ("A0000000090003", "S@T Browser v3"),
            ("A0000000871001", "WIB v1"),
            ("A0000000871002", "WIB v2"),
            ("A0000000871004", "WIB OTA"),
            ("A0000000030001", "USIM (3GPP)"),
            ("A0000000030002", "ISIM (3GPP)"),
            ("A0000000871003", "OTA Platform"),
            ("A000000018434D", "SCWS (Smart Card Web Server)"),
            ("A0000001510000", "GlobalPlatform Card Manager"),
        ]

        for aid, label in probe_aids:
            aid_bytes = [int(aid[i:i + 2], 16) for i in range(0, len(aid), 2)]
            apdu = CMD_SELECT_AID + [len(aid_bytes)] + aid_bytes
            data, sw = self._send_apdu(conn, apdu)
            if sw == 0x9000 or (sw >> 8) == 0x61:
                print_success(f"  PRESENT: {label} (AID: {aid})")
                apps_found.append(f"{label} ({aid})")
            else:
                print_info(f"  absent:  {label} (AID: {aid})")

        print_info("")
        if apps_found:
            print_info(f"Total applications found: {len(apps_found)}")
            for app in apps_found:
                print_info(f"  - {app}")
        else:
            print_info("No probed applications found on this SIM.")

        out_dir = _ensure_tmp(str(self.output_dir))
        report = {"apps_found": apps_found, "reader": int(self.reader_index)}
        report_file = os.path.join(out_dir, "stk_scan_report.json")
        with open(report_file, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print_info(f"Scan report saved to {report_file}")

        conn.disconnect()

    def _cve_database(self) -> None:
        """List all relevant CVEs with details."""
        print_info("SIM Security CVE / Vulnerability Database")
        print_info("=" * 45)
        print_info("")

        for entry in CVE_DATABASE:
            print_info(f"[{entry['id']}] {entry['name']}")
            print_info(f"  Severity: {entry['severity']} | CVSS: {entry['cvss']} | Year: {entry['year']}")
            print_info(f"  Vector: {entry['attack_vector']}")
            print_info(f"  Impact: {entry['impact']}")
            # Wrap description lines
            desc = entry["description"]
            while desc:
                chunk = desc[:78]
                if len(desc) > 78:
                    last_space = chunk.rfind(" ")
                    if last_space > 40:
                        chunk = desc[:last_space]
                print_info(f"  {chunk}")
                desc = desc[len(chunk):].lstrip()
            for ref in entry["references"]:
                print_info(f"  Ref: {ref}")
            print_info("")

        out_dir = _ensure_tmp(str(self.output_dir))
        cve_file = os.path.join(out_dir, "sim_cve_database.json")
        with open(cve_file, "w", encoding="utf-8") as fh:
            json.dump(CVE_DATABASE, fh, indent=2)
        print_info(f"CVE database exported to {cve_file}")

    def _mitigation(self) -> None:
        """Explain operator-side and user-side mitigations."""
        print_info("SIMJacker / WIBattack / STK Attack Mitigations")
        print_info("=" * 50)
        print_info("")
        print_info("OPERATOR-SIDE MITIGATIONS:")
        print_info("  1. SMS Firewall / Binary SMS Filtering")
        print_info("     - Block binary SMS with SIM Toolkit headers at SMSC")
        print_info("     - Filter SMS-PP messages targeting known vulnerable TARs")
        print_info("     - Rate-limit binary SMS per subscriber")
        print_info("")
