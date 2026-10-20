"""WPS DH and crypto helpers."""
from __future__ import annotations
import hashlib, hmac, os, struct
from ._constants import WpsAttr

def _dh_generate_keypair() -> tuple[int, int]:
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

