#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Interactive APDU command laboratory for SIM cards.

Send arbitrary APDU commands to SIM/USIM cards for security research and
analysis. Supports single command execution, batch scripting, convenience
wrappers for SELECT/READ/UPDATE operations, PIN verification, and
brute-force enumeration of accessible elementary files (EFs) under the
current dedicated file (DF).

Modes:
  info           - Print APDU reference guide and common commands
  send           - Send a single APDU command (hex string)
  script         - Execute a file of APDU commands (one per line)
  select         - SELECT a file by FID or path (convenience wrapper)
  read_binary    - READ BINARY from the currently selected file
  read_record    - READ RECORD from the currently selected file
  update_binary  - UPDATE BINARY (requires ADM/PIN verification)
  verify_pin     - Verify PIN1, PIN2, or ADM
  get_response   - GET RESPONSE for pending data
  status         - GET STATUS of current application
  enumerate_files - Brute-force enumerate accessible EFs under current DF

Version: 1.0.0
"""


import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.sim._disclaimer import (
    require_authorised_lab,
    require_sim_ownership,
)

logger = logging.getLogger(__name__)

HAS_PYSCARD = False
try:
    from smartcard.System import readers as list_readers  # type: ignore[import-untyped]
    from smartcard.util import toHexString  # type: ignore[import-untyped]
    HAS_PYSCARD = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# SW (Status Word) interpretation table
# ---------------------------------------------------------------------------
SW_TABLE: dict[int, str] = {
    0x9000: "OK",
    0x6282: "End of file/record reached before Le bytes",
    0x6981: "Command incompatible with file structure",
    0x6982: "Security status not satisfied",
    0x6983: "Authentication method blocked",
    0x6984: "Referenced data invalidated",
    0x6985: "Conditions of use not satisfied",
    0x6986: "Command not allowed (no current EF)",
    0x6A80: "Incorrect parameters in data field",
    0x6A81: "Function not supported",
    0x6A82: "File or application not found",
    0x6A83: "Record not found",
    0x6A84: "Not enough memory space",
    0x6A86: "Incorrect P1-P2",
    0x6A88: "Referenced data not found",
    0x6B00: "Wrong parameters P1-P2",
    0x6D00: "Instruction code not supported or invalid",
    0x6E00: "Class not supported",
    0x6F00: "No precise diagnosis",
}

_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")
MAX_APDU_LEN = 261


def _hex(data: list[int]) -> str:
    """Format byte list as hex string."""
    return " ".join(f"{b:02X}" for b in data)


def _parse_hex_string(hex_str: str) -> list[int] | None:
    """Parse hex string (with or without spaces) into byte list.

    Returns None if the input is invalid.
    """
    cleaned = hex_str.strip().replace(" ", "").replace("0x", "").replace("0X", "")
    if not cleaned:
        return None
    if not _HEX_PATTERN.match(cleaned):
        return None
    if len(cleaned) % 2 != 0:
        return None
    try:
        return [int(cleaned[i:i + 2], 16) for i in range(0, len(cleaned), 2)]
    except ValueError:
        return None


def _interpret_sw(sw1: int, sw2: int) -> str:
    """Interpret status word pair into human-readable description."""
    sw = (sw1 << 8) | sw2
    if sw in SW_TABLE:
        return SW_TABLE[sw]
    if sw1 == 0x61:
        return f"{sw2} bytes of response available (use GET RESPONSE)"
    if sw1 == 0x6C:
        return f"Wrong Le; correct length is {sw2} (0x{sw2:02X})"
    if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        return f"Verification failed, {sw2 & 0x0F} attempts remaining"
    if sw1 == 0x63:
        return "Warning: state of NV memory changed"
    if sw1 == 0x64:
        return "Execution error: state of NV memory unchanged"
    if sw1 == 0x65:
        return "Execution error: state of NV memory changed"
    if sw1 == 0x67:
        return "Wrong length"
    if sw1 == 0x68:
        return "Functions in CLA not supported"
    if sw1 == 0x69:
        return "Command not allowed"
    if sw1 == 0x6A:
        return "Wrong parameters P1-P2"
    if sw1 == 0x9F:
        return f"{sw2} bytes of response available"
    return f"Unknown SW: {sw1:02X}{sw2:02X}"


