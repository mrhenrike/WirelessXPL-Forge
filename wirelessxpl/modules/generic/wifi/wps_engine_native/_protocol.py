"""WPS TLV and message builders."""
from __future__ import annotations
import hashlib, hmac, os, struct
from ._constants import WpsAttr, WpsMsgType, EapWscOpCode
from ._crypto import _derive_auth_key, _compute_authenticator, _dh_generate_keypair, _dh_pub_to_bytes

def _tlv_parse(data: bytes) -> dict[int, bytes]:
    """Parse WPS TLV (Type-Length-Value) attributes from raw bytes.

    Attributes that appear multiple times will be overwritten by the
    last occurrence (consistent with the WPS specification behavior
    for duplicate attributes in valid messages).

    Args:
        data: Raw bytes from an EAP-WSC message body.

    Returns:
        Dict mapping attribute type (int) to value (bytes).
    """
    attrs: dict[int, bytes] = {}
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
    uuid_e: bytes | None = None,
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
) -> RadioTap:
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

