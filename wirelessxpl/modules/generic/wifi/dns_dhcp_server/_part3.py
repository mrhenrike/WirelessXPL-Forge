class Exploit(Exploit):
    """Native DNS/DHCP stack for captive portal rogue AP attacks."""

    __info__ = {
        "name": "Captive DNS/DHCP Server",
        "description": (
            "Pure-Python DNS and DHCP stack that replaces dnsmasq for captive "
            "portal deployments. CaptiveDNSServer (dnslib) redirects all DNS "
            "queries to the portal IP. CaptiveDHCPServer (Scapy BOOTP) allocates "
            "client IPs from a configurable range and advertises the portal as "
            "gateway and DNS. Both servers run as daemon threads and are managed "
            "together via CaptiveNetwork."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/paulc/dnslib",
            "https://scapy.net/",
            "https://datatracker.ietf.org/doc/html/rfc2131",
        ),
        "devices": ("wifi", "802.11"),
    }

    mode = OptString("info", "Mode: info, start, status")
    interface = OptString("wlan1", "AP interface for DHCP sniff/inject")
    portal_ip = OptString("10.0.0.1", "Captive portal IP (gateway and DNS)")
    ip_range_start = OptString("10.0.0.100", "First IP to allocate to clients")
    ip_range_end = OptString("10.0.0.200", "Last IP to allocate to clients")
    lease_time = OptInteger(86400, "DHCP lease time in seconds")
    dns_port = OptInteger(53, "UDP port for DNS server (53 requires root)")
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    def _info(self) -> None:
        print_info("Captive DNS/DHCP Server")
        print_info("=" * 50)
        print_info("")
        print_info("Pure-Python DNS (dnslib) and DHCP (Scapy) stack for captive portals.")
        print_info("")
        print_info("Components:")
        print_info("  CaptiveDNSServer  - Redirects all DNS queries to portal IP")
        print_info("  CaptiveDHCPServer - Allocates client IPs, advertises portal as GW/DNS")
        print_info("  CaptiveNetwork    - Manages both servers together")
        print_info("")
        print_info("Dependencies:")
        print_info("  dnslib : {}".format("installed" if HAS_DNSLIB else "MISSING  ->  pip install dnslib"))
        print_info("  scapy  : {}".format("installed" if HAS_SCAPY else "MISSING  ->  pip install scapy"))
        print_info("")
        print_info("Quick start:")
        print_info("  set interface wlan1; set portal_ip 10.0.0.1; set mode start; run")

    def _status(self) -> None:
        print_info("Dependency status:")
        print_info("  dnslib : {}".format("available" if HAS_DNSLIB else "unavailable"))
        print_info("  scapy  : {}".format("available" if HAS_SCAPY else "unavailable"))
        print_info("")
        print_info("Current configuration:")
        print_info(f"  interface     : {self.interface}")
        print_info(f"  portal_ip     : {self.portal_ip}")
        print_info(f"  ip_range      : {self.ip_range_start} - {self.ip_range_end}")
        print_info(f"  lease_time    : {self.lease_time}s")
        print_info(f"  dns_port      : {self.dns_port}")

    def _start(self) -> None:
        iface = str(self.interface).strip()
        if not iface:
            print_error("Set interface before running.")
            return

        portal_ip = str(self.portal_ip).strip()

        dns = CaptiveDNSServer(portal_ip=portal_ip, port=int(self.dns_port))
        dhcp = CaptiveDHCPServer(
            portal_ip=portal_ip,
            interface=iface,
            ip_range_start=str(self.ip_range_start).strip(),
            ip_range_end=str(self.ip_range_end).strip(),
            lease_time=int(self.lease_time),
        )

        errors: list[str] = []
        try:
            dns.start()
        except ImportError as exc:
            errors.append(f"DNS: {exc}")

        try:
            dhcp.start()
        except ImportError as exc:
            errors.append(f"DHCP: {exc}")

        if errors:
            print_error("Startup failed:")
            for msg in errors:
                print_error(f"  {msg}")
            dns.stop()
            dhcp.stop()
            return

        print_success("Captive network started.")
        print_info(f"  DNS  : UDP/{self.dns_port} redirecting all queries to {portal_ip}")
        print_info(f"  DHCP : {iface} (pool {str(self.ip_range_start).strip()} - {str(self.ip_range_end).strip()})")
        print_info("  Press Ctrl+C to stop.")

        try:
            while True:
                time.sleep(10)
                leases = dhcp.get_leases()
                if leases:
                    print_status(f"Active leases: {len(leases)}")
        except KeyboardInterrupt:
            print_status("Stopping captive network...")
        finally:
            dhcp.stop()
            dns.stop()

        total = len(dhcp.get_leases())
        print_info(f"Total clients served: {total}")

    def check(self) -> str:
        """Verify that required dependencies are installed."""
        missing = []
        if not HAS_DNSLIB:
            missing.append("dnslib (pip install dnslib)")
        if not HAS_SCAPY:
            missing.append("scapy (pip install scapy)")
        if missing:
            return "Missing dependencies: {}".format(", ".join(missing))
        return "All dependencies present - ready to start captive network"

    def run(self) -> None:
        """Dispatch to the selected operational mode."""
        op = str(self.mode).strip().lower()

        if op == "info":
            self._info()
            return
        if op == "status":
            self._status()
            return

        if not bool(self.i_know_scope):
            print_error("Set i_know_scope = true to confirm authorized lab environment.")
            return
        require_authorised_lab()

        if op == "start":
            self._start()
        else:
            print_error(f"Unknown mode: {op}. Valid: info, start, status")
