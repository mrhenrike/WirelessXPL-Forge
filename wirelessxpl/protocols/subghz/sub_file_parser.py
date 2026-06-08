#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Flipper Zero / Bruce .sub file parser and generator.

Handles reading and writing .sub signal files for sub-GHz replay.
Compatible with Flipper Zero SubGhz application and Bruce ESP32 firmware.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class SubGHzSignal:
    """Parsed sub-GHz signal from a .sub file.

    Attributes:
        frequency: Carrier frequency in Hz.
        preset: Radio preset string.
        protocol: Protocol identifier (RAW or named protocol).
        raw_data: List of RAW_Data sequences, each a list of signed integers.
        extra_fields: Any additional fields from the file.
    """

    frequency: int
    preset: str
    protocol: str
    raw_data: List[List[int]] = field(default_factory=list)
    extra_fields: dict = field(default_factory=dict)

    @property
    def frequency_mhz(self) -> float:
        """Return frequency in MHz."""
        return self.frequency / 1_000_000.0


def parse(filename: str | Path) -> SubGHzSignal:
    """Parse a Flipper Zero .sub file.

    Args:
        filename: Path to the .sub file.

    Returns:
        SubGHzSignal with parsed fields.

    Raises:
        ValueError: If required fields are missing or malformed.
        FileNotFoundError: If file does not exist.
    """
    path = Path(filename)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filename}")

    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    frequency: Optional[int] = None
    preset: Optional[str] = None
    protocol: Optional[str] = None
    raw_data: List[List[int]] = []
    extra: dict = {}

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" not in line:
            continue

        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()

        if key == "Frequency":
            try:
                frequency = int(value)
            except ValueError:
                raise ValueError(f"Invalid Frequency value: {value!r}")
        elif key == "Preset":
            preset = value
        elif key == "Protocol":
            protocol = value
        elif key == "RAW_Data":
            try:
                integers = [int(x) for x in value.split()]
                raw_data.append(integers)
            except ValueError as exc:
                raise ValueError(f"Invalid RAW_Data: {exc}") from exc
        elif key not in ("Filetype", "Version"):
            extra[key] = value

    if frequency is None:
        raise ValueError("Missing required field: Frequency")
    if preset is None:
        raise ValueError("Missing required field: Preset")
    if protocol is None:
        raise ValueError("Missing required field: Protocol")

    return SubGHzSignal(
        frequency=frequency,
        preset=preset,
        protocol=protocol,
        raw_data=raw_data,
        extra_fields=extra,
    )


def generate(signal: SubGHzSignal, filename: str | Path) -> None:
    """Write a SubGHzSignal to a .sub file.

    Args:
        signal: SubGHzSignal instance to serialize.
        filename: Destination path for the .sub file.
    """
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "Filetype: Flipper SubGhz RAW File",
        "Version: 1",
        f"Frequency: {signal.frequency}",
        f"Preset: {signal.preset}",
        f"Protocol: {signal.protocol}",
    ]

    for key, value in signal.extra_fields.items():
        lines.append(f"{key}: {value}")

    for raw_line in signal.raw_data:
        lines.append("RAW_Data: " + " ".join(str(v) for v in raw_line))

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def from_timing(
    timing: list,
    frequency_hz: int,
    preset: str = "FuriHalSubGhzPresetOok650Async",
    repeats: int = 1,
) -> SubGHzSignal:
    """Build a SubGHzSignal from a list of (duration_us, level) tuples.

    Args:
        timing: List of (duration_us, level) pairs.
        frequency_hz: Carrier frequency in Hz.
        preset: Radio preset string.
        repeats: Number of repeat transmissions to include.

    Returns:
        SubGHzSignal ready for writing with generate().
    """
    raw_values = []
    for duration, level in timing:
        raw_values.append(duration if level else -duration)

    raw_data = [raw_values] * repeats

    return SubGHzSignal(
        frequency=frequency_hz,
        preset=preset,
        protocol="RAW",
        raw_data=raw_data,
    )


__all__ = [
    "SubGHzSignal",
    "parse",
    "generate",
    "from_timing",
]
