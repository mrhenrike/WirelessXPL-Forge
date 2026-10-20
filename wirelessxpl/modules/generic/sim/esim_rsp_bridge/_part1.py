#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""eSIM Remote SIM Provisioning (RSP) research module using pySim.

Interact with eUICC/eSIM cards for security research, profile management,
and vulnerability assessment of the GSMA SGP.22 RSP ecosystem. Supports
EID reading, profile enumeration, TS.48 vulnerability checking, eUICC
capability inspection, certificate chain analysis, and SM-DP+ connectivity.

Requires: pySim (pySim.esim.rsp), pyscard, PC/SC reader with eUICC support.

Version: 1.0.0
"""


import logging
import os
import socket
import ssl
from datetime import datetime, timezone, UTC
from typing import Any, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.sim._disclaimer import (
    require_authorised_lab,
    require_sim_ownership,
)

logger = logging.getLogger(__name__)

HAS_PYSIM_RSP = False
try:
    from pySim.esim import es2p as pysim_es2p
    from pySim.esim import es8p as pysim_es8p
    from pySim.esim import rsp as pysim_rsp
    HAS_PYSIM_RSP = True
except ImportError:
    pass

HAS_PYSCARD = False
try:
    from smartcard.System import readers as sc_readers
    from smartcard.util import toBytes, toHexString
    HAS_PYSCARD = True
except ImportError:
    pass

HAS_CRYPTOGRAPHY = False
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    HAS_CRYPTOGRAPHY = True
except ImportError:
    pass

# ISD-R (Issuer Security Domain - Root) AID for eSIM profile management
ISD_R_AID = "A0000005591010FFFFFFFF8900000100"

# S@T Browser AID prefix (varies by vendor)
SAT_BROWSER_AID_PREFIX = "A0000000090001"

# Common APDU commands
SELECT_CMD = [0x00, 0xA4, 0x04, 0x00]
GET_DATA_EID = [0x80, 0xCA, 0x00, 0x46]
GET_STATUS_ISD_R = [0x80, 0xF2, 0x40, 0x00]


def _hex_to_bytes(hex_str: str) -> list[int]:
    """Convert hex string to byte list for APDU commands."""
    return [int(hex_str[i:i + 2], 16) for i in range(0, len(hex_str), 2)]


def _ensure_tmp(base: str) -> str:
    tmp = os.path.join(base, ".tmp")
    os.makedirs(tmp, exist_ok=True)
    return tmp


