class CaptiveDHCPServer:
    """DHCP server for rogue AP captive portal environments.

    Listens for DHCP DISCOVER and REQUEST packets using Scapy, allocates
    IPs from a configurable range, and responds with gateway and DNS
    options pointing at the captive portal IP.

    The lease table maps client MAC strings to allocated IP strings and
    is protected by a threading.Lock for concurrent access safety.

    Example:
        dhcp = CaptiveDHCPServer(portal_ip="10.0.0.1", interface="wlan1")
        dhcp.start()
        leases = dhcp.get_leases()
        dhcp.stop()
    """

    def __init__(
        self,
        portal_ip: str = "10.0.0.1",
        interface: str = "wlan1",
        ip_range_start: str = "10.0.0.100",
        ip_range_end: str = "10.0.0.200",
        subnet_mask: str = "255.255.255.0",
        lease_time: int = 86400,
    ) -> None:
        """Initialize the DHCP server.

        Args:
            portal_ip: Gateway and DNS IP advertised in DHCP options.
            interface: AP interface to sniff and inject frames on.
            ip_range_start: First IP available in the allocation pool.
            ip_range_end: Last IP available in the allocation pool.
            subnet_mask: Subnet mask advertised to clients.
            lease_time: DHCP lease duration in seconds.
        """
        self._portal_ip = portal_ip
        self._interface = interface
        self._ip_start = ipaddress.IPv4Address(ip_range_start)
        self._ip_end = ipaddress.IPv4Address(ip_range_end)
        self._subnet_mask = subnet_mask
        self._lease_time = lease_time
        self._leases: dict[str, str] = {}
        self._lock = threading.Lock()
        self._running: bool = False
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        """Return True while the DHCP daemon thread is alive."""
        return self._running and self._thread is not None and self._thread.is_alive()

    def get_leases(self) -> dict[str, str]:
        """Return a thread-safe snapshot of active MAC-to-IP leases.

        Returns:
            Dict mapping MAC address strings to assigned IP strings.
        """
        with self._lock:
            return dict(self._leases)

    # ------------------------------------------------------------------
    # Internal IP allocation
    # ------------------------------------------------------------------

    def _next_available_ip(self) -> str | None:
        """Scan the pool for an unallocated IP.

        Returns:
            IP string if available, None if the pool is exhausted.
        """
        with self._lock:
            allocated = set(self._leases.values())
            current = self._ip_start
            while current <= self._ip_end:
                ip_str = str(current)
                if ip_str not in allocated:
                    return ip_str
                current += 1
        return None

    def _get_or_assign_ip(self, mac: str) -> str | None:
        """Return the existing lease for a MAC or allocate a new IP.

        Args:
            mac: Normalized lowercase MAC address string.

        Returns:
            Assigned IP string or None if the pool is exhausted.
        """
        with self._lock:
            if mac in self._leases:
                return self._leases[mac]

        ip = self._next_available_ip()
        if ip is not None:
            with self._lock:
                self._leases[mac] = ip
        return ip

    # ------------------------------------------------------------------
    # Packet helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_mac(chaddr: bytes) -> str:
        """Convert a 16-byte BOOTP chaddr field to a MAC string.

        Args:
            chaddr: Raw chaddr bytes; only the first 6 are used.

        Returns:
            Colon-separated lowercase hex MAC string.
        """
        return ":".join(f"{b:02x}" for b in chaddr[:6])

    def _server_mac(self) -> str:
        """Retrieve the hardware MAC of the AP interface.

        Returns:
            MAC address string or a safe placeholder on failure.
        """
        if not HAS_SCAPY:
            return "02:00:00:00:00:01"
        try:
            return get_if_hwaddr(self._interface)
        except Exception:
            return "02:00:00:00:00:01"

    def _send_offer(self, pkt: object) -> None:
        """Send a DHCP OFFER in response to a DISCOVER.

        Args:
            pkt: Scapy BOOTP/DHCP DISCOVER packet from the client.
        """
        if not HAS_SCAPY:
            return

        mac = self._parse_mac(pkt[BOOTP].chaddr)
        offered_ip = self._get_or_assign_ip(mac)
        if offered_ip is None:
            logger.warning("DHCP pool exhausted; cannot offer IP to %s", mac)
            return

        server_mac = self._server_mac()
        offer = (
            Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src=self._portal_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(
                op=2,
                yiaddr=offered_ip,
                siaddr=self._portal_ip,
                chaddr=pkt[BOOTP].chaddr,
                xid=pkt[BOOTP].xid,
            )
            / DHCP(
                options=[
                    ("message-type", "offer"),
                    ("server_id", self._portal_ip),
                    ("lease_time", self._lease_time),
                    ("subnet_mask", self._subnet_mask),
                    ("router", self._portal_ip),
                    ("name_server", self._portal_ip),
                    "end",
                ]
            )
        )
        sendp(offer, iface=self._interface, verbose=False)
        logger.debug("DHCP OFFER: %s -> %s", mac, offered_ip)

    def _send_ack(self, pkt: object) -> None:
        """Send a DHCP ACK in response to a REQUEST.

        Args:
            pkt: Scapy BOOTP/DHCP REQUEST packet from the client.
        """
        if not HAS_SCAPY:
            return

        mac = self._parse_mac(pkt[BOOTP].chaddr)
        acked_ip = self._get_or_assign_ip(mac)
        if acked_ip is None:
            return

        server_mac = self._server_mac()
        ack = (
            Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src=self._portal_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(
                op=2,
                yiaddr=acked_ip,
                siaddr=self._portal_ip,
                chaddr=pkt[BOOTP].chaddr,
                xid=pkt[BOOTP].xid,
            )
            / DHCP(
                options=[
                    ("message-type", "ack"),
                    ("server_id", self._portal_ip),
                    ("lease_time", self._lease_time),
                    ("subnet_mask", self._subnet_mask),
                    ("router", self._portal_ip),
                    ("name_server", self._portal_ip),
                    "end",
                ]
            )
        )
        sendp(ack, iface=self._interface, verbose=False)
        logger.debug("DHCP ACK: %s -> %s", mac, acked_ip)

    def _handle_packet(self, pkt: object) -> None:
        """Route DHCP DISCOVER and REQUEST frames to the right handler.

        Args:
            pkt: Raw Scapy packet captured on the DHCP port.
        """
        if not HAS_SCAPY:
            return
        if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)):
            return
        if pkt[BOOTP].op != 1:
            return

        msg_type = None
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                msg_type = opt[1]
                break

        if msg_type == 1:
            self._send_offer(pkt)
        elif msg_type == 3:
            self._send_ack(pkt)

    def _sniff_loop(self) -> None:
        """Main loop executed in the DHCP daemon thread.

        Sniffs UDP/67 in 2-second windows so the stop event is checked
        frequently without blocking indefinitely.
        """
        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=self._interface,
                    filter="udp and port 67",
                    prn=self._handle_packet,
                    store=False,
                    timeout=2.0,
                    stop_filter=lambda _pkt: self._stop_event.is_set(),
                )
            except Exception as exc:
                if not self._stop_event.is_set():
                    logger.error("DHCP sniff error: %s", exc)
                    time.sleep(1.0)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the DHCP server in a background daemon thread.

        Raises:
            ImportError: If Scapy is not installed.
            RuntimeError: If the server is already running.
        """
        if not HAS_SCAPY:
            raise ImportError(
                "Scapy is required for CaptiveDHCPServer. "
                "Install with: pip install scapy"
            )
        if self._running:
            raise RuntimeError("CaptiveDHCPServer is already running.")

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="CaptiveDHCP",
        )
        self._thread.start()
        self._running = True
        logger.info(
            "CaptiveDHCPServer started on %s (pool %s-%s, gw %s)",
            self._interface,
            str(self._ip_start),
            str(self._ip_end),
            self._portal_ip,
        )

    def stop(self) -> None:
        """Signal the server to stop and wait for the thread to exit."""
        if not self._running:
            return
        self._stop_event.set()
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        self._thread = None
        logger.info("CaptiveDHCPServer stopped; total leases: %d", len(self._leases))


# ---------------------------------------------------------------------------
# CaptiveNetwork
# ---------------------------------------------------------------------------


class CaptiveNetwork:
    """Convenience class that starts DNS and DHCP servers together.

    Combines CaptiveDNSServer and CaptiveDHCPServer into a single object
    for simpler lifecycle management in captive portal deployments.

    Example:
        net = CaptiveNetwork(portal_ip="10.0.0.1", interface="wlan1")
        net.start()
        print(net.status())
        net.stop()
    """

    def __init__(
        self,
        portal_ip: str = "10.0.0.1",
        interface: str = "wlan1",
    ) -> None:
        """Initialize with a shared portal IP and AP interface.

        Args:
            portal_ip: IP that DNS redirects to and DHCP advertises.
            interface: AP interface name for DHCP sniff/inject.
        """
        self._portal_ip = portal_ip
        self._interface = interface
        self.dns: CaptiveDNSServer = CaptiveDNSServer(portal_ip=portal_ip)
        self.dhcp: CaptiveDHCPServer = CaptiveDHCPServer(
            portal_ip=portal_ip,
            interface=interface,
        )

    def start(self) -> None:
        """Start both DNS and DHCP servers.

        Raises:
            ImportError: If a required dependency is missing.
        """
        self.dns.start()
        self.dhcp.start()
        logger.info(
            "CaptiveNetwork started (portal=%s, iface=%s)",
            self._portal_ip,
            self._interface,
        )

    def stop(self) -> None:
        """Stop both DHCP and DNS servers in order."""
        self.dhcp.stop()
        self.dns.stop()
        logger.info("CaptiveNetwork stopped")

    def status(self) -> dict[str, object]:
        """Return operational status for both servers.

        Returns:
            Dict with keys: dns_running, dhcp_running, leases,
            portal_ip, interface.
        """
        return {
            "dns_running": self.dns.is_running,
            "dhcp_running": self.dhcp.is_running,
            "leases": self.dhcp.get_leases(),
            "portal_ip": self._portal_ip,
            "interface": self._interface,
        }


# ---------------------------------------------------------------------------
# Exploit class
# ---------------------------------------------------------------------------


@requires_os(OSRequirement.LINUX_ONLY)
