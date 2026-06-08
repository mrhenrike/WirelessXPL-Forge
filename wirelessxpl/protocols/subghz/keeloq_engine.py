#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""KeeLoq rolling code encryption/decryption engine.

Pure Python implementation of the KeeLoq algorithm.
Reference: Microchip HCS200/HCS301 Application Note AN642.
No external dependencies required.

KeeLoq is a block cipher with 64-bit key and 32-bit block size.
Used in rolling code remote entry systems (cars, garage doors).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# KeeLoq NLFC (Non-Linear Function) lookup table -- 32-bit extraction
# Derived from the hardware circuit described in AN642
_NLF = 0x3A5C742E


def _nlf_bit(a: int, b: int, c: int, d: int, e: int) -> int:
    """Evaluate the KeeLoq non-linear function for one bit."""
    index = (a << 4) | (b << 3) | (c << 2) | (d << 1) | e
    return (_NLF >> index) & 1


def keeloq_encrypt(plaintext: int, key: int) -> int:
    """Encrypt a 32-bit plaintext with a 64-bit key using KeeLoq.

    Args:
        plaintext: 32-bit plaintext value.
        key: 64-bit manufacturer key.

    Returns:
        32-bit ciphertext.
    """
    plaintext &= 0xFFFFFFFF
    key &= 0xFFFFFFFFFFFFFFFF

    x = plaintext
    for i in range(528):
        k_bit = (key >> (63 - (i % 64))) & 1
        b31 = (x >> 31) & 1
        b26 = (x >> 26) & 1
        b20 = (x >> 20) & 1
        b9  = (x >> 9) & 1
        b1  = (x >> 1) & 1
        b0  = x & 1
        nl = _nlf_bit(b31, b26, b20, b9, b1)
        new_bit = b0 ^ nl ^ k_bit
        x = ((x >> 1) | (new_bit << 31)) & 0xFFFFFFFF

    return x


def keeloq_decrypt(ciphertext: int, key: int) -> int:
    """Decrypt a 32-bit ciphertext with a 64-bit key using KeeLoq.

    Args:
        ciphertext: 32-bit ciphertext (HOP portion of frame).
        key: 64-bit manufacturer key.

    Returns:
        32-bit plaintext.
    """
    ciphertext &= 0xFFFFFFFF
    key &= 0xFFFFFFFFFFFFFFFF

    x = ciphertext
    for i in range(527, -1, -1):
        k_bit = (key >> (63 - (i % 64))) & 1
        b31 = (x >> 31) & 1
        b30 = (x >> 30) & 1
        b25 = (x >> 25) & 1
        b19 = (x >> 19) & 1
        b8  = (x >> 8) & 1
        nl = _nlf_bit(b30, b25, b19, b8, b31)
        new_bit = b31 ^ nl ^ k_bit
        x = ((x << 1) & 0xFFFFFFFF) | new_bit

    return x


@dataclass
class KeeLoqFrame:
    """Parsed KeeLoq frame from a captured RF signal.

    Attributes:
        raw_bits: Original 66-bit frame as integer.
        fix: 32-bit fixed portion (serial + button code).
        hop: 32-bit hopping portion (encrypted counter).
        serial: 28-bit device serial number (upper 28 bits of fix).
        button: 4-bit button code (lower 4 bits of fix).
        counter: Decrypted 16-bit counter (if key known), else None.
        vlow: Battery indicator bit.
        rpt: Repeat indicator bit.
    """

    raw_bits: int
    fix: int
    hop: int
    serial: int
    button: int
    counter: Optional[int] = None
    vlow: bool = False
    rpt: bool = False


def decode_frame(raw_bits: int) -> KeeLoqFrame:
    """Decode a 66-bit KeeLoq frame into its components.

    KeeLoq frame format (66 bits, transmitted LSB first):
      bits 0-31:  HOP (encrypted counter + button + status)
      bits 32-63: FIX (serial number + button code)
      bit 64:     VLOW (battery low indicator)
      bit 65:     RPT (repeat transmission indicator)

    Args:
        raw_bits: 66-bit captured frame as integer.

    Returns:
        KeeLoqFrame dataclass instance.
    """
    raw_bits &= 0x3FFFFFFFFFFFFFFFF

    hop = raw_bits & 0xFFFFFFFF
    fix = (raw_bits >> 32) & 0xFFFFFFFF
    vlow = bool((raw_bits >> 64) & 1)
    rpt = bool((raw_bits >> 65) & 1)

    serial = (fix >> 4) & 0x0FFFFFFF
    button = fix & 0x0F

    return KeeLoqFrame(
        raw_bits=raw_bits,
        fix=fix,
        hop=hop,
        serial=serial,
        button=button,
        vlow=vlow,
        rpt=rpt,
    )


def decode_frame_with_key(raw_bits: int, key: int) -> KeeLoqFrame:
    """Decode a KeeLoq frame and decrypt the HOP portion.

    Args:
        raw_bits: 66-bit captured frame as integer.
        key: 64-bit manufacturer key.

    Returns:
        KeeLoqFrame with counter field populated.
    """
    frame = decode_frame(raw_bits)
    plaintext = keeloq_decrypt(frame.hop, key)
    counter = plaintext & 0xFFFF
    frame.counter = counter
    return frame


# Known manufacturer key seeds for learning/research
# These are publicly documented (NOT secret)
_KNOWN_SEEDS: dict[str, int] = {
    "Microchip_demo": 0x0000000000000000,
}


def learn_key_simple(serial: int) -> int:
    """Derive a simple KeeLoq manufacturer key from serial (HCS200 learning).

    Simple learning algorithm: key derived from serial via documented method.
    This is the simplified variant published in academic papers.

    Args:
        serial: 28-bit device serial number.

    Returns:
        64-bit derived key.
    """
    key_msb = (serial << 36) | (serial << 8) | ((serial >> 20) & 0xFF)
    key_lsb = (serial << 36) | (serial << 8) | ((serial >> 20) & 0xFF)
    key = ((key_msb & 0xFFFFFFFF) << 32) | (key_lsb & 0xFFFFFFFF)
    return key & 0xFFFFFFFFFFFFFFFF


__all__ = [
    "keeloq_encrypt",
    "keeloq_decrypt",
    "decode_frame",
    "decode_frame_with_key",
    "learn_key_simple",
    "KeeLoqFrame",
]
