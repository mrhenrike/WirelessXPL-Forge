#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""OOK/ASK protocol encoders for sub-GHz IoT remote control systems.

Supports: EV1527, Princeton/PT2262, HT6P20/HT12X, SMC5326, CAME, NICE, Holtek, Chamberlain.
Output: timing sequences and Flipper Zero .sub file format.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class SubGHzConfig:
    """Sub-GHz radio configuration."""

    frequency: float
    preset: str = "FuriHalSubGhzPresetOok650Async"
    bit_time: int = 0


class OOKEncoder:
    """Generic ASK/OOK encoder base class.

    Subclasses set class-level timing attributes to define the protocol.
    """

    name: str = "Generic"
    bit_time: int = 500
    chirp_0: Tuple[int, int] = (1, 3)
    chirp_1: Tuple[int, int] = (3, 1)
    preamble_periods: int = 1
    sync_low: int = 31
    code_bits: int = 24

    def encode(self, code: int) -> List[Tuple[int, int]]:
        """Encode an integer code to a list of (duration_us, level) pairs.

        Args:
            code: Integer code value to encode.

        Returns:
            List of (duration_microseconds, level) tuples where level is 0 or 1.
        """
        if code < 0 or code >= (1 << self.code_bits):
            raise ValueError(
                f"Code {code} out of range for {self.code_bits}-bit protocol"
            )
        result: List[Tuple[int, int]] = []
        # Preamble
        result.append((self.bit_time, 1))
        result.append((self.bit_time * self.sync_low, 0))
        # Data bits (MSB first)
        for i in range(self.code_bits - 1, -1, -1):
            bit = (code >> i) & 1
            chirp = self.chirp_1 if bit else self.chirp_0
            result.append((self.bit_time * chirp[0], 1))
            result.append((self.bit_time * chirp[1], 0))
        return result

    def to_sub_raw(
        self,
        code: int,
        frequency: float = 433.92,
        repeats: int = 3,
        preset: Optional[str] = None,
    ) -> str:
        """Generate Flipper Zero .sub file content for RAW replay.

        Args:
            code: Integer code value to encode.
            frequency: Carrier frequency in MHz.
            repeats: Number of repeat transmissions.
            preset: Override default preset string.

        Returns:
            String contents of a valid .sub file.
        """
        chosen_preset = preset or SubGHzConfig(frequency=frequency).preset
        lines = [
            "Filetype: Flipper SubGhz RAW File",
            "Version: 1",
            f"Frequency: {int(frequency * 1_000_000)}",
            f"Preset: {chosen_preset}",
            "Protocol: RAW",
        ]
        for _ in range(repeats):
            timing = self.encode(code)
            raw_values = []
            for duration, level in timing:
                raw_values.append(duration if level else -duration)
            lines.append("RAW_Data: " + " ".join(str(v) for v in raw_values))
        return "\n".join(lines)


class EV1527Encoder(OOKEncoder):
    """EV1527 -- most common static code protocol in BR IoT devices.

    Used widely in Brazilian garage doors, alarms, and remote controls.
    24-bit code with 20-bit address and 4-bit command.
    """

    name = "EV1527"
    bit_time = 333
    chirp_0 = (1, 3)
    chirp_1 = (3, 1)
    sync_low = 31
    code_bits = 24


class PrincetonEncoder(OOKEncoder):
    """Princeton PT2262 -- 24-bit static code protocol.

    Compatible with many clones (SC2262, SM5262, etc.).
    """

    name = "Princeton"
    bit_time = 350
    chirp_0 = (1, 3)
    chirp_1 = (3, 1)
    sync_low = 31
    code_bits = 24


class CAMEEncoder(OOKEncoder):
    """CAME 12-bit fixed code protocol for garage doors."""

    name = "CAME"
    bit_time = 320
    chirp_0 = (1, 2)
    chirp_1 = (2, 1)
    sync_low = 36
    code_bits = 12


class NICEEncoder(OOKEncoder):
    """NICE Flo 12-bit fixed code protocol."""

    name = "NICE"
    bit_time = 700
    chirp_0 = (1, 2)
    chirp_1 = (2, 1)
    sync_low = 36
    code_bits = 12


class HoltekEncoder(OOKEncoder):
    """Holtek HT12X 12-bit static code."""

    name = "Holtek"
    bit_time = 433
    chirp_0 = (1, 2)
    chirp_1 = (2, 1)
    sync_low = 30
    code_bits = 12


class ChamberlainEncoder(OOKEncoder):
    """Chamberlain/LiftMaster garage door -- 9-bit."""

    name = "Chamberlain"
    bit_time = 1000
    chirp_0 = (1, 3)
    chirp_1 = (3, 1)
    sync_low = 40
    code_bits = 9


class AnsonicEncoder(OOKEncoder):
    """Ansonic 12-bit fixed code protocol (common in BR/LATAM)."""

    name = "Ansonic"
    bit_time = 400
    chirp_0 = (1, 2)
    chirp_1 = (2, 1)
    sync_low = 30
    code_bits = 12


PROTOCOL_MAP = {
    "EV1527": EV1527Encoder,
    "Princeton": PrincetonEncoder,
    "CAME": CAMEEncoder,
    "NICE": NICEEncoder,
    "Holtek": HoltekEncoder,
    "Chamberlain": ChamberlainEncoder,
    "Ansonic": AnsonicEncoder,
}

__all__ = [
    "SubGHzConfig",
    "OOKEncoder",
    "EV1527Encoder",
    "PrincetonEncoder",
    "CAMEEncoder",
    "NICEEncoder",
    "HoltekEncoder",
    "ChamberlainEncoder",
    "AnsonicEncoder",
    "PROTOCOL_MAP",
]
