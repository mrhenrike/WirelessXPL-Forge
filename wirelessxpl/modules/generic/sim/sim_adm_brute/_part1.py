#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""SIM ADM PIN brute-force module.

Attempt to recover the ADM (Administrative) PIN of a SIM card through
systematic testing. The ADM PIN grants full read/write access to all card
files, enabling profile modification, file updates, and OTA key extraction.

SAFETY: The ADM retry counter is typically 10 or fewer attempts. Exhausting
all attempts permanently locks the ADM function with no recovery path.
This module always reads the remaining attempt counter before any verification
and refuses to proceed when 0 attempts remain.

Modes:
  info             - Explain ADM PIN, risk of card lock, and mitigation
  check_remaining  - Read remaining VERIFY attempts before lock
  brute_sequential - Sequential brute from start to end hex value
  brute_wordlist   - Try PINs from a wordlist file
  brute_common     - Try common default ADM PINs (vendor defaults)
  verify_single    - Try a single known ADM PIN

The ADM PIN is typically 8 bytes (16 hex characters). The VERIFY APDU for
ADM1 uses P2=0x0A: 00 20 00 0A 08 [8-byte PIN].

Version: 1.0.0
"""


import logging
import os
import time
from typing import Any, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.sim._disclaimer import (
    require_authorised_lab,
    require_sim_ownership,
)

logger = logging.getLogger(__name__)

HAS_PYSCARD = False
try:
    from smartcard.System import readers as list_readers  # type: ignore[import-untyped]
    HAS_PYSCARD = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# ADM PIN VERIFY constants
# ---------------------------------------------------------------------------
VERIFY_CLA = 0x00
VERIFY_INS = 0x20
VERIFY_P1 = 0x00
VERIFY_P2_ADM1 = 0x0A
ADM_PIN_LEN = 8

SW_OK = (0x90, 0x00)

# ---------------------------------------------------------------------------
# Known vendor default ADM PINs (8 bytes each, hex representation)
# ---------------------------------------------------------------------------
COMMON_ADM_PINS: list[tuple[str, list[int]]] = [
    ("Gemalto default (8888...88FF)", [0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0xFF]),
    ("All zeros", [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    ("All ones (1111...11)", [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]),
    ("All 0xFF", [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
    ("Chinese vendor (4444...44)", [0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44]),
    ("Sequential 1234567812345678", [0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78]),
    ("All 0x22", [0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22]),
    ("All 0x33", [0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33]),
    ("All 0x55", [0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55]),
    ("All 0xAA", [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
    ("ADM ASCII '00000000'", [0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30]),
    ("ADM ASCII '11111111'", [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31]),
    ("ADM ASCII '12345678'", [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]),
    ("ADM ASCII '88888888'", [0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38]),
    ("sysmoUSIM-SJS1 default", [0xAD, 0xAC, 0x8E, 0x16, 0x25, 0x47, 0xCF, 0x56]),
]

MIN_SAFE_ATTEMPTS = 3


def _hex(data: list[int]) -> str:
    """Format byte list as hex string."""
    return "".join(f"{b:02X}" for b in data)


def _hex_spaced(data: list[int]) -> str:
    """Format byte list as hex string with spaces."""
    return " ".join(f"{b:02X}" for b in data)


def _parse_hex_pin(hex_str: str) -> list[int] | None:
    """Parse hex string into 8-byte ADM PIN. Returns None on invalid input."""
    cleaned = hex_str.strip().replace(" ", "").replace("0x", "").replace("0X", "")
    if not cleaned:
        return None
    if len(cleaned) != 16:
        return None
    try:
        return [int(cleaned[i:i + 2], 16) for i in range(0, 16, 2)]
    except ValueError:
        return None


def _int_to_pin_bytes(value: int) -> list[int]:
    """Convert integer (0 to 2^64-1) into 8-byte big-endian PIN."""
    pin_bytes = []
    for shift in range(56, -1, -8):
        pin_bytes.append((value >> shift) & 0xFF)
    return pin_bytes


