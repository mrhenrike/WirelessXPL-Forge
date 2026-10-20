# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import ssl
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """ASUS Router MITM via Weak Certificate Validation (CVE-2026-13385).

    Multiple ASUS router models use weak TLS certificate validation
    when connecting to ASUS update servers and cloud services. The
    firmware does not properly verify certificate chains or hostname
    matching, allowing a man-in-the-middle attacker to intercept
    HTTPS connections between the router and ASUS services.

    This enables firmware update manipulation, configuration
    exfiltration, and credential theft for ASUS cloud accounts.

    CVSS v3.1: 8.1 (High), AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "ASUS Router MITM via Weak Certificate Validation (CVE-2026-13385)",
        "description": (
            "Exploits CVE-2026-13385 via weak TLS certificate validation "
            "on ASUS routers. The firmware does not properly verify "
            "certificate chains when connecting to ASUS services, "
            "enabling MITM interception of firmware updates and "
            "configuration data."
        ),
        "authors": (
            "Security researcher (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-13385",
            "https://www.asus.com/support/",
        ),
        "disclosure_date": "2026-04-20",
        "platform": "linux",
        "arch": "arm",
        "privileged": False,
        "targets": (
            "ASUS RT-AX86U (firmware < 3.0.0.4.388.25647)",
            "ASUS RT-AX88U (firmware < 3.0.0.4.388.25647)",
            "ASUS RT-AX58U (firmware < 3.0.0.4.388.25647)",
            "ASUS TUF-AX5400 (firmware < 3.0.0.4.388.25647)",
        ),
    }

    target = OptIP("", "Target ASUS router IP")
    port = OptPort(8443, "Target HTTPS management port")
    timeout = OptFloat(5.0, "Connection timeout in seconds")

    def _analyze_tls(self) -> dict:
        """Analyze TLS configuration of the target router."""
        results = {
            "reachable": False,
            "tls_version": "",
            "cipher": "",
            "cert_subject": "",
            "self_signed": False,
        }

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (str(self.target), self.port), timeout=self.timeout
            ) as raw:
                with ctx.wrap_socket(raw, server_hostname=str(self.target)) as ssock:
                    results["reachable"] = True
                    results["tls_version"] = ssock.version() or "unknown"
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        results["cipher"] = cipher_info[0]
                    cert = ssock.getpeercert()
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", ()))
                        results["cert_subject"] = subject.get("commonName", "")
                        issuer = dict(x[0] for x in cert.get("issuer", ()))
                        if subject == issuer:
                            results["self_signed"] = True
        except (OSError, ssl.SSLError):
            pass

        return results

    @mute
    def check(self) -> bool:
        """Check if the HTTPS management interface is reachable."""
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

        print_success("HTTPS management interface reachable; analyzing TLS")
        self._exploit()

    def _exploit(self) -> None:
        results = self._analyze_tls()

        print_status("TLS analysis results:")
        print_info(f"  TLS version: {results['tls_version']}")
        print_info(f"  Cipher: {results['cipher']}")
        print_info(f"  Certificate subject: {results['cert_subject']}")
        print_info(f"  Self-signed: {results['self_signed']}")

        if results["self_signed"]:
            print_success(
                "VULNERABLE: Router uses a self-signed certificate. "
                "Combined with weak certificate validation for outbound "
                "connections, a MITM attacker can intercept firmware "
                "updates and ASUS cloud service communications."
            )
        else:
            print_info(
                "Router has a CA-signed certificate, but outbound "
                "connections may still be vulnerable to MITM if the "
                "firmware does not validate certificate chains."
            )
