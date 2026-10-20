#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Active TKIP attack suite with native Michael MIC, Beck-Tews, and detection.

Provides a native Python implementation of the Michael MIC algorithm as the
primary path for TKIP MIC operations. The Beck-Tews and Vanhoef-Piessens attacks
first attempt native Scapy-based frame capture with michael_mic() verification,
then fall back to tkiptun-ng for full exploitation. Scapy-based detection of
TKIP-only or mixed-mode APs is unchanged.

Native Michael MIC path: michael_mic() + Scapy (primary).
tkiptun-ng path: accepted dependency, used as fallback or full-chain executor.

Requires: Scapy, aircrack-ng suite (tkiptun-ng, accepted dep), monitor-mode interface.

Version: 2.0.0
"""


import logging
import os
import shutil
import struct
import subprocess
from typing import List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

SCAPY_AVAILABLE = False
try:
    from scapy.all import (
        Dot11,
        Dot11Beacon,
        Dot11Deauth,
        Dot11Elt,
        Dot11ProbeResp,
        Dot11QoS,
        rdpcap,
    )
    from scapy.all import (
        sniff as scapy_sniff,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    pass


BECK_TEWS_INFO = """
=== Beck-Tews Attack (2008) ===

Targets WPA-TKIP networks with QoS (WMM) enabled.
Exploits the weak Michael MIC and TKIP per-packet key mixing
to decrypt one ARP-length packet and inject up to 7 forged frames
into QoS channels not used by legitimate traffic.

Requirements:
  - Target AP must support WPA-TKIP (not CCMP-only)
  - QoS / WMM must be enabled on the AP
  - Monitor-mode interface with injection capability
  - tkiptun-ng from the aircrack-ng suite (accepted dep, fallback path)
  - Scapy for native primary path

Time: approximately 12-15 minutes per packet decryption.

References:
  - Martin Beck, Erik Tews: "Practical attacks against WEP and WPA"
    https://dl.aircrack-ng.org/breakingwepandwpa.pdf
  - CVE-2008-5230 (TKIP temporal key recovery)
"""

VANHOEF_PIESSENS_INFO = """
=== Vanhoef-Piessens Extended TKIP Injection (2014) ===

Extends the Beck-Tews attack with improved injection techniques
that relax the QoS channel restrictions. This allows injection of
larger payloads and broadens the attack surface to include DHCP,
DNS and other protocols beyond ARP.

Requirements:
  - Same as Beck-Tews (QoS-enabled WPA-TKIP AP)
  - tkiptun-ng with extended-mode patches or compatible build

References:
  - Mathy Vanhoef, Frank Piessens: "Advanced Wi-Fi Attacks Using
    Commodity Hardware" (ACSAC 2014)
    https://papers.mathyvanhoef.com/acsac2014.pdf
"""

DETECT_INFO = """
=== TKIP Detection Mode ===

Scans live traffic or a PCAP file for access points that advertise
TKIP as pairwise or group cipher (via RSN/WPA information elements).
Reports whether TKIP is the sole cipher (highest risk) or used in
mixed mode alongside CCMP.
"""

TKIPTUN_INFO = """
=== tkiptun-ng Direct Bridge ===

Direct invocation of the tkiptun-ng binary from the aircrack-ng suite.
Passes interface, BSSID, and target MAC for automated TKIP injection.

Docs: https://www.aircrack-ng.org/doku.php?id=tkiptun-ng
"""


def _which(binary: str) -> str | None:
    return shutil.which(binary)


def michael_mic(key: bytes, da: bytes, sa: bytes, priority: int, data: bytes) -> bytes:
    """Compute Michael MIC for TKIP frames.

    The Michael algorithm is a message authentication code designed for
    TKIP (WPA/802.11i). It uses two 32-bit subkeys and a series of rotation
    and XOR operations over a padded input block sequence.

    Reference: IEEE 802.11-2020 clause 12.5.3 (Michael MIC);
    Beck & Tews 2008, breakingwepandwpa.pdf.

    Args:
        key: 8-byte Michael key (TX or RX MIC key derived from PTK).
        da: 6-byte destination address (little-endian byte order as on wire).
        sa: 6-byte source address.
        priority: 1-byte MSDU priority (QoS TID; usually 0 for non-QoS).
        data: MSDU payload bytes (plaintext, before TKIP encryption).

    Returns:
        8-byte Michael MIC value (little-endian packed).

    Raises:
        ValueError: If key is not exactly 8 bytes.
    """
    if len(key) != 8:
        raise ValueError(f"Michael key must be 8 bytes, got {len(key)}")

    def _ror32(v: int, n: int) -> int:
        return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF

    def _michael_block(l_val: int, r_val: int) -> tuple:
        r_val ^= _ror32(l_val, 15)
        l_val = (l_val + r_val) & 0xFFFFFFFF
        r_val ^= ((l_val & 0xFF00FF00) >> 8) | ((l_val & 0x00FF00FF) << 8)
        r_val &= 0xFFFFFFFF
        l_val = (l_val + r_val) & 0xFFFFFFFF
        r_val ^= _ror32(l_val, 2)
        l_val = (l_val + r_val) & 0xFFFFFFFF
        r_val ^= _ror32(l_val, 30)
        l_val = (l_val + r_val) & 0xFFFFFFFF
        return l_val, r_val

    l_state = struct.unpack("<I", key[:4])[0]
    r_state = struct.unpack("<I", key[4:8])[0]

    # Michael header: DA (6) || SA (6) || priority (1) || 3 zero bytes
    header = da + sa + bytes([priority & 0xFF, 0x00, 0x00, 0x00])
    message = header + data

    # Append 0x5a terminator, then zero-pad to a 4-byte boundary
    message += b"\x5a"
    pad_len = (-(len(message))) % 4
    message += b"\x00" * pad_len

    for i in range(0, len(message), 4):
        block = struct.unpack("<I", message[i : i + 4])[0]
        l_state ^= block
        l_state, r_state = _michael_block(l_state, r_state)

    return struct.pack("<II", l_state, r_state)


@requires_os(OSRequirement.LINUX_ONLY)
