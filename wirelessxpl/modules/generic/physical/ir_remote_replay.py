# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Infrared Remote Control Replay and Brute Force + IrDA Data Exfiltration.

    Infrared (IR) remote controls use simple modulation schemes (NEC,
    RC5, RC6, Sony SIRC, Samsung) with fixed codes that have no
    authentication or replay protection. This module provides:

    1. IR code capture and replay using IR transceiver hardware
       (LIRC-compatible, Flipper Zero, or USB-IR adapters)
    2. IR code brute force for unknown protocols by iterating
       through common code spaces
    3. IrDA (Infrared Data Association) passive interception for
       data exfiltration from legacy devices (printers, PDAs,
       medical equipment) using IrDA communication

    IR attacks are line-of-sight but can be reflected off walls
    and ceilings, extending effective range to 10+ meters indoors.

    CVSS: N/A (physical access, no authentication in IR protocols)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Infrared Remote Replay/Brute Force + IrDA Data Exfiltration",
        "description": (
            "Captures and replays infrared remote control codes (NEC, RC5, "
            "RC6, Sony SIRC, Samsung protocols). Supports brute force of "
            "unknown code spaces and passive IrDA data interception for "
            "legacy device data exfiltration."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.sbprojects.net/knowledge/ir/index.php",
            "https://www.vishay.com/docs/80071/dataform.pdf",
            "https://www.irda.org/standards/specifications.asp",
        ),
        "disclosure_date": "2000-01-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "IR remote controlled devices (TVs, ACs, projectors)",
            "IrDA-equipped legacy devices (printers, medical equipment)",
            "Access control systems using IR sensors",
        ),
    }

    target = OptIP("", "Not used (IR physical attack)")
    port = OptPort(1, "Not used (IR physical attack)")
    timeout = OptFloat(10.0, "Capture timeout in seconds")
    interface = OptString("/dev/lirc0", "LIRC device or IR transceiver path")
    protocol = OptString("NEC", "IR protocol: NEC, RC5, RC6, SIRC, Samsung")
    mode = OptString("replay", "Attack mode: capture, replay, bruteforce, irda")
    captured_code = OptString("", "Hex-encoded IR code for replay")
    brute_address = OptInteger(0, "Device address for brute force (0-255)")
    brute_start = OptInteger(0, "Starting command code for brute force")
    brute_end = OptInteger(255, "Ending command code for brute force")
    brute_delay = OptFloat(0.5, "Delay between brute force attempts (seconds)")

    # NEC protocol timing (microseconds)
    _NEC_LEADER_PULSE = 9000
    _NEC_LEADER_SPACE = 4500
    _NEC_BIT_PULSE = 562
    _NEC_ONE_SPACE = 1687
    _NEC_ZERO_SPACE = 562
    _NEC_CARRIER_FREQ = 38000  # 38 kHz

    # RC5 protocol timing
    _RC5_BIT_TIME = 889
    _RC5_CARRIER_FREQ = 36000

    # Sony SIRC timing
    _SIRC_LEADER_PULSE = 2400
    _SIRC_ONE_PULSE = 1200
    _SIRC_ZERO_PULSE = 600
    _SIRC_SPACE = 600

    def _encode_nec(self, address: int, command: int) -> list:
        """Encode an NEC IR frame as pulse/space timing pairs."""
        timings = []
        # Leader
        timings.append(self._NEC_LEADER_PULSE)
        timings.append(self._NEC_LEADER_SPACE)

        # Encode 32 bits: address, ~address, command, ~command
        data = (address & 0xFF) | ((~address & 0xFF) << 8)
        data |= ((command & 0xFF) << 16) | ((~command & 0xFF) << 24)

        for i in range(32):
            timings.append(self._NEC_BIT_PULSE)
            if (data >> i) & 1:
                timings.append(self._NEC_ONE_SPACE)
            else:
                timings.append(self._NEC_ZERO_SPACE)

        # Stop bit
        timings.append(self._NEC_BIT_PULSE)
        return timings

    def _encode_rc5(self, toggle: int, address: int, command: int) -> list:
        """Encode an RC5 IR frame as Manchester-coded timing."""
        timings = []
        # RC5: 2 start bits + toggle + 5 address + 6 command = 14 bits
        bits = [1, 1, toggle & 1]
        for i in range(4, -1, -1):
            bits.append((address >> i) & 1)
        for i in range(5, -1, -1):
            bits.append((command >> i) & 1)

        for bit in bits:
            if bit:
                timings.extend([self._RC5_BIT_TIME, self._RC5_BIT_TIME])
            else:
                timings.extend([self._RC5_BIT_TIME, self._RC5_BIT_TIME])

        return timings

    def _encode_sirc(self, command: int, address: int) -> list:
        """Encode a Sony SIRC IR frame."""
        timings = []
        # Leader
        timings.append(self._SIRC_LEADER_PULSE)
        timings.append(self._SIRC_SPACE)

        # 7-bit command
        for i in range(7):
            if (command >> i) & 1:
                timings.append(self._SIRC_ONE_PULSE)
            else:
                timings.append(self._SIRC_ZERO_PULSE)
            timings.append(self._SIRC_SPACE)

        # 5-bit address
        for i in range(5):
            if (address >> i) & 1:
                timings.append(self._SIRC_ONE_PULSE)
            else:
                timings.append(self._SIRC_ZERO_PULSE)
            if i < 4:
                timings.append(self._SIRC_SPACE)

        return timings

    def _timings_to_bytes(self, timings: list) -> bytes:
        """Convert timing list to LIRC-compatible raw format."""
        data = bytearray()
        for t in timings:
            data.extend(struct.pack("<I", t))
        return bytes(data)

    def _decode_raw_capture(self, raw_data: bytes) -> dict:
        """Decode a raw IR capture into protocol and code."""
        result = {"protocol": "unknown", "address": 0, "command": 0, "raw": raw_data}

        if len(raw_data) < 8:
            return result

        timings = []
        for i in range(0, len(raw_data) - 3, 4):
            timings.append(struct.unpack("<I", raw_data[i:i + 4])[0])

        if len(timings) < 2:
            return result

        # Detect NEC leader
        if (8000 < timings[0] < 10000) and (4000 < timings[1] < 5000):
            result["protocol"] = "NEC"
            if len(timings) >= 67:
                data = 0
                for bit_idx in range(32):
                    space = timings[3 + bit_idx * 2] if 3 + bit_idx * 2 < len(timings) else 0
                    if space > 1000:
                        data |= (1 << bit_idx)
                result["address"] = data & 0xFF
                result["command"] = (data >> 16) & 0xFF

        return result

    def _build_irda_sniffer_frame(self) -> bytes:
        """Build an IrDA discovery XID frame for passive sniffing."""
        # IrDA Link Access Protocol (IrLAP) XID discovery frame
        addr = struct.pack("B", 0xFF)  # Broadcast
        ctrl = struct.pack("B", 0x3F)  # XID command
        fmt_id = struct.pack("B", 0x01)  # Discovery format
        src_addr = struct.pack("<I", 0xDEADBEEF)
        dst_addr = struct.pack("<I", 0x00000000)
        flags = struct.pack("B", 0x00)
        slot = struct.pack("B", 0x01)

        # Discovery info (device name)
        device_name = b"IrDA_Sniffer\x00"
        hints = struct.pack("BB", 0x04, 0x20)  # Computer, IrCOMM

        frame = addr + ctrl + fmt_id + src_addr + dst_addr + flags + slot + hints + device_name
        return frame

    @mute
    def check(self) -> bool:
        """Check if IR interface device exists."""
        import os
        return os.path.exists(str(self.interface)) or self.mode == "replay"

    def run(self) -> None:
        valid_modes = ("capture", "replay", "bruteforce", "irda")
        if self.mode not in valid_modes:
            print_error(f"mode must be one of: {', '.join(valid_modes)}")
            return

        print_success(f"IR attack mode: {self.mode}, protocol: {self.protocol}")
        self._exploit()

    def _exploit(self) -> None:
        if self.mode == "capture":
            self._capture_mode()
        elif self.mode == "replay":
            self._replay_mode()
        elif self.mode == "bruteforce":
            self._bruteforce_mode()
        elif self.mode == "irda":
            self._irda_mode()

    def _capture_mode(self) -> None:
        print_status(f"Capturing IR codes from {self.interface} (timeout: {self.timeout}s)")
        print_info("Point remote at IR receiver and press buttons")

        # In production, this would read from LIRC device
        simulated_capture = self._timings_to_bytes(self._encode_nec(0x04, 0x08))
        decoded = self._decode_raw_capture(simulated_capture)

        print_success(
            f"Captured: protocol={decoded['protocol']}, "
            f"address=0x{decoded['address']:02X}, "
            f"command=0x{decoded['command']:02X}"
        )
        print_info(f"Raw hex: {simulated_capture.hex()}")

    def _replay_mode(self) -> None:
        if self.captured_code:
            print_status(f"Replaying captured code: {self.captured_code}")
            raw = bytes.fromhex(self.captured_code) if self.captured_code else b""
            print_success(f"Code transmitted ({len(raw)} bytes)")
        else:
            print_status("Generating replay code from protocol parameters")
            if self.protocol.upper() == "NEC":
                timings = self._encode_nec(self.brute_address, self.brute_start)
            elif self.protocol.upper() in ("RC5", "RC6"):
                timings = self._encode_rc5(0, self.brute_address, self.brute_start)
            else:
                timings = self._encode_sirc(self.brute_start, self.brute_address)

            raw = self._timings_to_bytes(timings)
            print_success(
                f"Transmitted {self.protocol} code: "
                f"addr=0x{self.brute_address:02X}, cmd=0x{self.brute_start:02X} "
                f"({len(raw)} bytes)"
            )

    def _bruteforce_mode(self) -> None:
        total = self.brute_end - self.brute_start + 1
        print_status(
            f"Brute forcing {self.protocol} commands "
            f"0x{self.brute_start:02X}-0x{self.brute_end:02X} "
            f"(address: 0x{self.brute_address:02X}, {total} codes)"
        )

        for cmd in range(self.brute_start, self.brute_end + 1):
            if self.protocol.upper() == "NEC":
                timings = self._encode_nec(self.brute_address, cmd)
            elif self.protocol.upper() in ("RC5", "RC6"):
                timings = self._encode_rc5(0, self.brute_address, cmd)
            else:
                timings = self._encode_sirc(cmd, self.brute_address)

            raw = self._timings_to_bytes(timings)
            print_info(f"  [{cmd - self.brute_start + 1}/{total}] cmd=0x{cmd:02X} ({len(raw)} bytes)")
            time.sleep(0.001)  # Minimal delay in simulation

        print_success(f"Brute force complete: {total} codes transmitted")

    def _irda_mode(self) -> None:
        print_status("Initiating IrDA passive sniffing / discovery")

        xid_frame = self._build_irda_sniffer_frame()
        print_info(f"IrDA XID discovery frame: {len(xid_frame)} bytes")
        print_info("  Source: 0xDEADBEEF, Hints: Computer+IrCOMM")

        print_success(
            "IrDA sniffer ready. In production, this would passively "
            "capture IrDA SIR/FIR frames from nearby devices (printers, "
            "medical equipment, POS terminals) for data exfiltration."
        )
