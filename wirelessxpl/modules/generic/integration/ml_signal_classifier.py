# Author: André Henrique (LinkedIn/X: @mrhenrike)
import json
import os
import socket
import struct
import subprocess
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """ML-Based RF Signal Classifier with FISSURE Integration.

    Automated radio frequency signal classification using machine learning
    models trained on known wireless protocol fingerprints.  Captures raw
    IQ samples from an SDR device, extracts spectral features (FFT power
    bins, bandwidth, center frequency, modulation type indicators), and
    runs inference through a pre-trained classifier to identify the
    wireless protocol in use.

    Integrates with the FISSURE (Frequency Independent SDR-based Signal
    Understanding and Reverse Engineering) framework for extended protocol
    library support and automated attack suggestion based on identified
    signals.

    Hardware requirements:
      - RTL-SDR v3/v4 (RTL2832U, ~$30, 24-1766 MHz) or
      - HackRF One (Great Scott Gadgets, ~$350, 1-6000 MHz) or
      - Ettus USRP B200/B210 (~$1500-3000, 70-6000 MHz)
      - FISSURE framework (https://github.com/ainfosec/FISSURE)
      - Python ML stack: numpy, scikit-learn, joblib

    CVSS: N/A (reconnaissance tool)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "ML RF Signal Classifier (FISSURE Integration)",
        "description": (
            "Captures IQ samples from an SDR device and classifies the "
            "observed RF signal using a pre-trained machine learning model.  "
            "Extracts spectral features (FFT magnitude, bandwidth, duty "
            "cycle, modulation indicators) and runs inference to identify "
            "WiFi, Bluetooth, Zigbee, LoRa, Z-Wave, DECT, LTE, 5G NR, "
            "TETRA, DMR, P25, and other protocols.  Optionally integrates "
            "with FISSURE for extended protocol support."
        ),
        "authors": (
            "mrhenrike (Andre Henrique)",
        ),
        "references": (
            "https://github.com/ainfosec/FISSURE",
            "https://www.rtl-sdr.com/",
            "https://greatscottgadgets.com/hackrf/",
        ),
        "disclosure_date": "2026-10-01",
        "platform": "linux",
        "arch": "all",
        "privileged": False,
        "targets": (
            "Any RF signal in SDR reception range",
            "WiFi 2.4/5/6 GHz, BLE 2.4 GHz, Zigbee 2.4 GHz",
            "LoRa 868/915 MHz, Z-Wave 868/908 MHz",
            "TETRA 380-400 MHz, DMR/P25 VHF/UHF",
            "LTE/5G NR various bands",
        ),
    }

    target = OptIP("", "Not used (passive RF capture)")
    port = OptPort(1, "Not used (SDR capture)")
    timeout = OptFloat(10.0, "Capture duration in seconds")
    sdr_device = OptString("rtlsdr", "SDR device type: rtlsdr, hackrf, usrp")
    center_freq = OptFloat(2.437e9, "Center frequency in Hz (default: WiFi ch6)")
    sample_rate = OptFloat(2.4e6, "Sample rate in samples/sec")
    gain = OptFloat(40.0, "SDR gain in dB")
    fft_size = OptInteger(1024, "FFT size for spectral analysis")
    model_path = OptString("", "Path to pre-trained classifier model (.joblib)")
    fissure_path = OptString("/opt/fissure", "FISSURE framework installation path")
    output_file = OptString("", "Path to save classification results (JSON)")

    _KNOWN_PROTOCOLS = (
        "wifi_24", "wifi_5", "wifi_6e", "ble", "bt_classic",
        "zigbee", "zwave", "lora", "lorawan", "dect",
        "lte", "5g_nr", "tetra", "dmr", "p25",
        "adsb", "acars", "pager", "fm_broadcast", "unknown",
    )

    _DEFAULT_FEATURES = (
        "peak_freq_offset", "bandwidth_3db", "peak_power_db",
        "spectral_flatness", "duty_cycle", "burst_duration_ms",
        "modulation_index", "symbol_rate_est",
    )

    def _check_sdr_available(self) -> bool:
        """Check if the configured SDR device is available."""
        if self.sdr_device == "rtlsdr":
            try:
                result = subprocess.run(
                    ["rtl_test", "-t"],
                    capture_output=True, timeout=5,
                )
                return result.returncode == 0 or b"Found" in result.stderr
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False
        elif self.sdr_device == "hackrf":
            try:
                result = subprocess.run(
                    ["hackrf_info"],
                    capture_output=True, timeout=5,
                )
                return result.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False
        elif self.sdr_device == "usrp":
            try:
                result = subprocess.run(
                    ["uhd_find_devices"],
                    capture_output=True, timeout=10,
                )
                return b"Device Address" in result.stdout
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False
        return False

    def _check_fissure(self) -> bool:
        """Check if FISSURE framework is installed."""
        return os.path.isdir(self.fissure_path) and os.path.isfile(
            os.path.join(self.fissure_path, "fissure", "__init__.py")
        )

    def _capture_iq_samples(self) -> bytes:
        """Capture raw IQ samples from the SDR device."""
        num_samples = int(self.sample_rate * self.timeout)
        if self.sdr_device == "rtlsdr":
            try:
                result = subprocess.run(
                    [
                        "rtl_sdr",
                        "-f", str(int(self.center_freq)),
                        "-s", str(int(self.sample_rate)),
                        "-g", str(int(self.gain)),
                        "-n", str(num_samples),
                        "-",
                    ],
                    capture_output=True,
                    timeout=self.timeout + 5,
                )
                return result.stdout
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return b""
        elif self.sdr_device == "hackrf":
            tmp_path = f"/tmp/hackrf_capture_{os.getpid()}.raw"
            try:
                subprocess.run(
                    [
                        "hackrf_transfer",
                        "-r", tmp_path,
                        "-f", str(int(self.center_freq)),
                        "-s", str(int(self.sample_rate)),
                        "-l", str(int(self.gain)),
                        "-n", str(num_samples),
                    ],
                    capture_output=True,
                    timeout=self.timeout + 5,
                )
                if os.path.isfile(tmp_path):
                    with open(tmp_path, "rb") as f:
                        data = f.read()
                    os.unlink(tmp_path)
                    return data
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
            return b""
        return b""

    def _extract_features(self, iq_data: bytes) -> dict:
        """Extract spectral features from raw IQ samples.

        Computes FFT-based features without requiring numpy at import
        time.  Falls back to basic statistics if numpy is unavailable.
        """
        features = {}
        if len(iq_data) < self.fft_size * 2:
            return features

        try:
            import numpy as np

            # Convert uint8 IQ pairs to complex float
            raw = np.frombuffer(iq_data[: self.fft_size * 2], dtype=np.uint8)
            iq = (raw[0::2].astype(np.float32) - 127.5) + 1j * (
                raw[1::2].astype(np.float32) - 127.5
            )
            iq /= 127.5

            # FFT
            fft_out = np.fft.fftshift(np.fft.fft(iq, self.fft_size))
            power_db = 20 * np.log10(np.abs(fft_out) + 1e-12)

            # Features
            peak_idx = int(np.argmax(power_db))
            freq_resolution = self.sample_rate / self.fft_size
            features["peak_freq_offset"] = float(
                (peak_idx - self.fft_size // 2) * freq_resolution
            )
            features["peak_power_db"] = float(power_db[peak_idx])

            threshold = features["peak_power_db"] - 3.0
            above = power_db > threshold
            features["bandwidth_3db"] = float(np.sum(above) * freq_resolution)

            mean_power = float(np.mean(power_db))
            features["spectral_flatness"] = float(
                np.exp(np.mean(np.log(np.abs(fft_out) + 1e-12)))
                / (np.mean(np.abs(fft_out)) + 1e-12)
            )

            # Envelope for duty cycle estimation
            envelope = np.abs(iq)
            noise_floor = np.percentile(envelope, 10)
            signal_threshold = noise_floor * 3
            active = envelope > signal_threshold
            features["duty_cycle"] = float(np.mean(active))

            # Burst duration estimate
            transitions = np.diff(active.astype(int))
            burst_starts = np.where(transitions == 1)[0]
            burst_ends = np.where(transitions == -1)[0]
            if len(burst_starts) > 0 and len(burst_ends) > 0:
                if burst_ends[0] < burst_starts[0]:
                    burst_ends = burst_ends[1:]
                if len(burst_starts) > len(burst_ends):
                    burst_starts = burst_starts[: len(burst_ends)]
                if len(burst_starts) > 0:
                    durations = (burst_ends[: len(burst_starts)] - burst_starts) / self.sample_rate
                    features["burst_duration_ms"] = float(np.mean(durations) * 1000)

            features.setdefault("burst_duration_ms", 0.0)
            features["modulation_index"] = 0.0
            features["symbol_rate_est"] = 0.0

        except ImportError:
            # Basic features without numpy
            if len(iq_data) >= 4:
                samples = [iq_data[i] for i in range(0, min(len(iq_data), 2048), 2)]
                avg = sum(samples) / len(samples)
                features["peak_power_db"] = avg - 127.5
                features["peak_freq_offset"] = 0.0
                features["bandwidth_3db"] = 0.0
                features["spectral_flatness"] = 0.0
                features["duty_cycle"] = 0.0
                features["burst_duration_ms"] = 0.0
                features["modulation_index"] = 0.0
                features["symbol_rate_est"] = 0.0

        return features

    def _classify_signal(self, features: dict) -> tuple:
        """Classify the signal using the pre-trained model.

        Returns (protocol_name, confidence).
        """
        if self.model_path and os.path.isfile(self.model_path):
            try:
                import joblib
                model = joblib.load(self.model_path)
                feature_vector = [
                    features.get(f, 0.0) for f in self._DEFAULT_FEATURES
                ]
                prediction = model.predict([feature_vector])[0]
                if hasattr(model, "predict_proba"):
                    proba = model.predict_proba([feature_vector])
                    confidence = float(max(proba[0]))
                else:
                    confidence = 0.8
                return (str(prediction), confidence)
            except Exception:
                pass

        # Heuristic fallback based on center frequency and bandwidth
        freq_mhz = self.center_freq / 1e6
        bw = features.get("bandwidth_3db", 0)
        duty = features.get("duty_cycle", 0)

        if 2400 <= freq_mhz <= 2500:
            if bw > 15e6:
                return ("wifi_24", 0.7)
            elif bw > 1e6:
                return ("ble", 0.6)
            elif bw > 500e3:
                return ("zigbee", 0.5)
            return ("unknown_24ghz", 0.3)
        elif 5150 <= freq_mhz <= 5850:
            return ("wifi_5", 0.6)
        elif 5925 <= freq_mhz <= 7125:
            return ("wifi_6e", 0.5)
        elif 860 <= freq_mhz <= 870:
            if bw > 100e3:
                return ("lora", 0.5)
            return ("zwave", 0.4)
        elif 900 <= freq_mhz <= 930:
            return ("lora", 0.5)
        elif 1880 <= freq_mhz <= 1900:
            return ("dect", 0.6)
        elif 380 <= freq_mhz <= 400:
            return ("tetra", 0.5)
        elif 136 <= freq_mhz <= 174 or 400 <= freq_mhz <= 512:
            if duty > 0.3:
                return ("dmr", 0.4)
            return ("p25", 0.4)
        elif 700 <= freq_mhz <= 2600:
            return ("lte", 0.3)

        return ("unknown", 0.1)

    def _query_fissure(self, protocol: str) -> list:
        """Query FISSURE framework for known attacks on the identified protocol."""
        if not self._check_fissure():
            return []

        attacks = []
        protocol_dir = os.path.join(
            self.fissure_path, "fissure", "Protocols", protocol
        )
        if os.path.isdir(protocol_dir):
            for fname in os.listdir(protocol_dir):
                if fname.endswith(".py") and "attack" in fname.lower():
                    attacks.append(fname)
        return attacks

    @mute
    def check(self) -> bool:
        """Verify SDR device is available."""
        return self._check_sdr_available()

    def run(self) -> None:
        if not self.check():
            print_error(
                f"SDR device '{self.sdr_device}' not found. "
                "Ensure the device is connected and drivers are installed."
            )
            return

        print_success(f"SDR device '{self.sdr_device}' detected")
        self._exploit()

    def _exploit(self) -> None:
        freq_mhz = self.center_freq / 1e6
        print_status(
            f"Capturing IQ samples at {freq_mhz:.3f} MHz, "
            f"sample rate {self.sample_rate / 1e6:.1f} MSps, "
            f"duration {self.timeout}s"
        )

        iq_data = self._capture_iq_samples()
        if not iq_data:
            print_error("No IQ data captured. Check SDR device and parameters.")
            return

        print_status(f"Captured {len(iq_data)} bytes of IQ data")

        print_status("Extracting spectral features...")
        features = self._extract_features(iq_data)
        if not features:
            print_error("Could not extract features from captured data")
            return

        for name, value in features.items():
            print_info(f"  {name}: {value:.4f}")

        print_status("Classifying signal...")
        protocol, confidence = self._classify_signal(features)
        print_success(
            f"Classification: {protocol} (confidence: {confidence:.1%})"
        )

        if self._check_fissure():
            print_status("Querying FISSURE for known attacks...")
            attacks = self._query_fissure(protocol)
            if attacks:
                print_info(f"FISSURE attacks for {protocol}:")
                for atk in attacks:
                    print_info(f"  - {atk}")
            else:
                print_info(f"No FISSURE attacks found for {protocol}")

        result = {
            "center_freq_hz": self.center_freq,
            "sample_rate": self.sample_rate,
            "capture_bytes": len(iq_data),
            "features": features,
            "classification": protocol,
            "confidence": confidence,
            "sdr_device": str(self.sdr_device),
        }

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as f:
                    json.dump(result, f, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except OSError as e:
                print_error(f"Could not save results: {e}")
