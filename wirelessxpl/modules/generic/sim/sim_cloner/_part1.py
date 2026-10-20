#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""SIM Card Cloning and Provisioning Tool using pySim.

Clone SIM card data to a programmable blank SIM card (sysmocom/Osiris).
Supports reading source SIM EFs, writing to blank target cards, provisioning
test SIMs for private GSM networks, verification, and batch programming.

Requires: pySim (pySim-shell.py / pySim-prog.py), pyscard, PC/SC reader.

Version: 1.0.0
"""


import csv
import json
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.core.hw_validator import HWValidator, Requirement
from wirelessxpl.core.phase_gateway import PhaseGateway
from wirelessxpl.modules.generic.sim._disclaimer import (
    require_authorised_lab,
    require_sim_ownership,
)

logger = logging.getLogger(__name__)

HAS_PYSIM = False
try:
    from pySim.commands import SimCardCommands
    from pySim.transport.pcsc import PcscSimLink
    HAS_PYSIM = True
except ImportError:
    pass

_PYSIM_SHELL = "pySim-shell.py"
_PYSIM_PROG = "pySim-prog.py"

_EF_MAP = {
    "IMSI": "3F00/7FFF/6F07",
    "ICCID": "3F00/2FE2",
    "MSISDN": "3F00/7FFF/6F40",
    "SPN": "3F00/7FFF/6F46",
    "ACC": "3F00/7FFF/6F78",
    "PLMN": "3F00/7FFF/6F30",
    "SMSP": "3F00/7FFF/6F42",
}

_CSV_HEADER = ("ICCID", "IMSI", "KI", "OPC", "ADM")


def _which(binary: str) -> str | None:
    return shutil.which(binary)


def _ensure_tmp(base: str) -> str:
    """Create .tmp directory inside the given base path."""
    tmp = os.path.join(base, ".tmp")
    os.makedirs(tmp, exist_ok=True)
    return tmp


def _validate_hex(value: str, expected_len: int, label: str) -> bool:
    """Validate hex string length and content."""
    cleaned = value.strip().upper()
    if len(cleaned) != expected_len:
        print_error(f"{label} must be {expected_len} hex chars, got {len(cleaned)}")
        return False
    try:
        int(cleaned, 16)
    except ValueError:
        print_error(f"{label} contains invalid hex characters")
        return False
    return True


