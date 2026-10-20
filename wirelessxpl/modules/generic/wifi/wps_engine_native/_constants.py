#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Native WPS attack engine - Pixie Dust, PIN brute-force, and NULL PIN.

Implements the full WPS EAP-WSC protocol (M1-M8 state machine) in native
Python using Scapy, replacing external bridges for reaver, bully, and pixiewps.

Supported attack modes:
  pixie_dust    Offline PIN recovery via weak nonce (CVE-2014-9527 and variants)
  pin_brute     Online PIN brute-force with all generation algorithms
  null_pin      Known-vulnerable NULL/empty PIN (00000000)
  scan          WPS-enabled AP discovery via wash (accepted dependency)

Key algorithms implemented:
  - DH 1536-bit key exchange (RFC 3526 Group 5)
  - HMAC-SHA256 for AuthKey, PSK1, PSK2 derivation
  - WPS PIN Luhn checksum (IEEE 802.11-2020 Annex J)
  - Zhao statistical PIN generation
  - OUI-based manufacturer default PIN database
  - WPS lock detection and adaptive backoff
  - Full EAP-WSC M1-M8 state machine with Scapy frame injection

Association flow (required before EAP exchange):
  The engine sends 802.11 Auth -> AssocReq (with WPS IE) -> EAPOL-Start before
  waiting for EAP-Request/Identity. Without EAPOL-Start, the AP never initiates
  the EAP exchange and the engine times out.

Note: Some APs advertise a channel in their beacon frames but operate at a
slightly different frequency (channel drift/mismatch). If scan reports ch3 but
capture fails, try adjacent channels (ch4, ch2). Use `iw dev <iface> scan`
to confirm the actual operating frequency of the AP.

Dependencies (accepted external):
  - scapy: raw 802.11 frame injection and capture
  - wash: WPS scanner (part of reaver-suite, accepted exception)

OS requirement: Linux only (raw sockets, nl80211, monitor mode).

Version: 1.0.0
"""


import hashlib
import hmac as _hmac
import logging
import secrets
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple
from collections.abc import Iterator

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

try:
    from scapy.all import (
        EAPOL,
        LLC,
        SNAP,
        Dot11,
        Dot11AssoReq,
        Dot11Auth,
        Dot11Elt,
        Ether,
        RadioTap,
        Raw,
        conf,
        sendp,
        sniff,
    )
    from scapy.layers.eap import EAP
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# RFC 3526 Group 5 (1536-bit MODP) DH parameters
# ---------------------------------------------------------------------------

_DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
    16,
)
_DH_GENERATOR = 2
_DH_PRIME_LEN = 192  # bytes (1536 bits)


# ---------------------------------------------------------------------------
# WPS TLV attribute type IDs (IEEE 802.11-2020 Annex J)
# ---------------------------------------------------------------------------

class WpsAttr:
    """WPS TLV attribute type constants."""

    VERSION          = 0x104A
    MSG_TYPE         = 0x1022
    ENROLLEE_NONCE   = 0x101A
    REGISTRAR_NONCE  = 0x1039
    UUID_E           = 0x1047
    UUID_R           = 0x1048
    AUTH_TYPE_FLAGS  = 0x1004
    ENCR_TYPE_FLAGS  = 0x1010
    CONN_TYPE_FLAGS  = 0x100D
    CONFIG_METHODS   = 0x1008
    PRIM_DEV_TYPE    = 0x1054
    RF_BANDS         = 0x103C
    ASSOC_STATE      = 0x1002
    DEV_PASSWD_ID    = 0x1012
    CONFIG_ERROR     = 0x1009
    OS_VERSION       = 0x102D
    MANUFACTURER     = 0x1021
    MODEL_NAME       = 0x1023
    MODEL_NUMBER     = 0x1024
    SERIAL_NUMBER    = 0x1042
    DEVICE_NAME      = 0x1011
    PUBLIC_KEY       = 0x1032
    AUTHENTICATOR    = 0x1005
    ENCR_SETTINGS    = 0x1018
    KEY_WRAP_AUTH    = 0x101E
    CRED             = 0x100E
    NETWORK_KEY      = 0x1027
    SSID             = 0x1045
    AUTH_TYPE        = 0x1003
    ENCR_TYPE        = 0x100F
    MAC_ADDR         = 0x1020
    E_HASH1          = 0x1014
    E_HASH2          = 0x1015
    E_SNONCE1        = 0x1016
    E_SNONCE2        = 0x1017
    R_HASH1          = 0x103D
    R_HASH2          = 0x103E
    R_SNONCE1        = 0x103F
    R_SNONCE2        = 0x1040
    PSK1             = 0x1044
    PSK2             = 0x1045


class WpsMsgType:
    """WPS EAP-WSC message type codes."""

    M1       = 0x04
    M2       = 0x05
    M2D      = 0x06
    M3       = 0x07
    M4       = 0x08
    M5       = 0x09
    M6       = 0x0A
    M7       = 0x0B
    M8       = 0x0C
    WSC_ACK  = 0x0D
    WSC_NACK = 0x0E
    WSC_DONE = 0x0F


class EapWscOpCode:
    """Op-codes for the EAP-WSC (WPS) expanded EAP type (0xFE)."""

    WSC_START = 0x01
    WSC_ACK   = 0x02
    WSC_NACK  = 0x03
    WSC_MSG   = 0x04
    WSC_DONE  = 0x05
    WSC_FRAG  = 0x06


# EAP expanded type vendor identifiers for WPS
_EAP_WSC_VENDOR_ID   = b"\x00\x37\x2A"   # Wi-Fi Alliance OUI
_EAP_WSC_VENDOR_TYPE = b"\x00\x00\x00\x01"


class WpsLockState(Enum):
    """WPS AP lock detection state."""

    UNLOCKED = auto()
    WARNING  = auto()
    LOCKED   = auto()


# ---------------------------------------------------------------------------
# DH Key Exchange (RFC 3526 Group 5, 1536-bit MODP)
# ---------------------------------------------------------------------------

