#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Automated handshake snooper — capture + verify WPA handshakes.

Orchestrates the full handshake capture workflow:
  1. Put interface in monitor mode
  2. Scan for target AP
  3. Deauthenticate clients to force re-authentication
  4. Capture EAPOL 4-way handshake via Scapy (native) or airodump-ng (optional)
  5. Verify handshake validity via aircrack-ng
  6. Save for offline cracking

Capture methods:
  - Native (default): Scapy sniff() filtering EAPOL (ether_type=0x888e), detects
    M1/M2/M3/M4 frames per (bssid, client) pair, writes .pcapng via wrpcap()
    compatible with aircrack-ng and hashcat.
  - Airodump (optional): airodump-ng subprocess (use_airodump=True).

Deauth methods:
  - Native (default): Scapy Dot11Deauth frames (native_deauth=True).
  - aireplay: aireplay-ng --deauth (native_deauth=False, aircrack-ng suite).

Verification: aircrack-ng only. Cowpatty and pyrit dependencies removed.

Inspired by Fluxion's Handshake Snooper attack module.

Version: 2.0.0
"""


import logging
import shutil
import subprocess
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

try:
    from wirelessxpl.core.ml.handshake_scorer import HandshakeScorer
    _HAS_ML = True
except ImportError:
    _HAS_ML = False

logger = logging.getLogger(__name__)

# EAPOL-Key Key Information field bitmasks (16-bit big-endian)
_KEY_ACK    = 0x0080  # Bit 7 - Key ACK
_KEY_MIC    = 0x0100  # Bit 8 - Key MIC
_KEY_SECURE = 0x0200  # Bit 9 - Secure


def _classify_eapol_message(eapol_raw: bytes) -> str | None:
    """Classify an EAPOL-Key frame as M1, M2, M3, or M4.

    Parses the Key Information field from raw EAPOL frame bytes and
    returns the 4-way handshake message number based on the ACK, MIC,
    and Secure flag combination.

    EAPOL frame layout:
      Byte 0:   Version
      Byte 1:   Type (3 = EAPOL-Key)
      Bytes 2-3: Body Length
      Byte 4:   Key Descriptor Type
      Bytes 5-6: Key Information (big-endian uint16)

    Args:
        eapol_raw: Raw bytes starting from the EAPOL version byte.

    Returns:
        "M1", "M2", "M3", "M4", or None if not an EAPOL-Key or unclassifiable.
    """
    if len(eapol_raw) < 7:
        return None
    if eapol_raw[1] != 3:  # Not EAPOL-Key
        return None

    key_info = (eapol_raw[5] << 8) | eapol_raw[6]
    ack    = bool(key_info & _KEY_ACK)
    mic    = bool(key_info & _KEY_MIC)
    secure = bool(key_info & _KEY_SECURE)

    if ack and not mic:
        return "M1"
    if not ack and mic and not secure:
        return "M2"
    if ack and mic:
        return "M3"
    if not ack and mic and secure:
        return "M4"
    return None


@requires_os(OSRequirement.LINUX_ONLY)
