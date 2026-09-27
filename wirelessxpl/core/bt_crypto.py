#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Bluetooth Classic cryptographic primitives (SAFER+ based).

Pure Python 3 implementation of the Bluetooth BR/EDR key derivation and
authentication functions from the BT Core Spec v5.x:

  - H()            SAFER+ hash function (Ar rounds)
  - e1()           Authentication: SRES + ACO from link key, AU_RAND, BTADD
  - e3()           Encryption key Kc from link key, EN_RAND, COF
  - Kc_to_Kc_prime()  Entropy reduction of Kc via GF(2^128) polynomials
  - kdf()          Full Key Derivation: link key -> session key (Kc')

Used by KNOB, BIAS, and BLUFFS attack modules for session key
computation, verification, and entropy analysis.

Reference: BT Core Spec v5.3, Vol 2 Part H (Security Specification).

Version: 1.0.0
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

AR_KEY_LEN = 16
AR_ROUNDS = 8
SRES_LEN = 4
ACO_LEN = 12
COF_LEN = 12
BTADD_LEN = 6

# SAFER+ S-box: EXP_45[i] = (45^i mod 257) mod 256
EXP_45: List[int] = [int(((45 ** i) % 257) % 256) for i in range(256)]

# LOG_45 is the inverse: LOG_45[EXP_45[i]] = i
LOG_45: List[int] = [0] * 256
for _i in range(256):
    LOG_45[EXP_45[_i]] = _i

# GF(2^128) reduction polynomials for entropy reduction (Kc -> Kc')
G1 = [
    0x00,
    0x0000011d,
    0x0001003f,
    0x010000db,
    0x01000000af,
    0x010000000039,
    0x01000000000291,
    0x0100000000000095,
    0x01000000000000001b,
    0x01000000000000000609,
    0x0100000000000000000215,
    0x01000000000000000000013b,
    0x010000000000000000000000dd,
    0x010000000000000000000000049d,
    0x01000000000000000000000000014f,
    0x010000000000000000000000000000e7,
    0x0000000100000000000000000000000000000000,
]

G2 = [
    0x00,
    0xe275a0abd218d4cf928b9bbf6cb08f,
    0x01e3f63d7659b37f18c258cff6efef,
    0x000001bef66c6c3ab1030a5a1919808b,
    0x016ab89969de17467fd3736ad9,
    0x0163063291da50ec55715247,
    0x2c9352aa6cc054468311,
    0xb3f7fffce279f3a073,
    0xa1ab815bc7ec8025,
    0x02c98011d8b04d,
    0x058e24f9a4bb,
    0x0ca76024d7,
    0x1c9c26b9,
    0x26d9e3,
    0x4377,
    0x89,
    0x01,
]

# K_tilda transform constants (EQ 15, BT Spec p.1676)
_KT_ADD = [233, None, 223, None, 179, None, 149, None,
           None, 229, None, 193, None, 167, None, 131]
_KT_XOR = [None, 229, None, 193, None, 167, None, 131,
           233, None, 223, None, 179, None, 149, None]

# Armenian permutation table
_PERM = [8, 11, 12, 15, 2, 1, 6, 5, 10, 9, 14, 13, 0, 7, 4, 3]

# Byte indices that use XOR in add_one (odd subkeys) vs addition
_XOR_INDICES = {0, 3, 4, 7, 8, 11, 12, 15}


def _add_one(left: bytearray, right: bytearray) -> bytearray:
    """SAFER+ add_one: XOR at positions {0,3,4,7,8,11,12,15}, add mod 256 elsewhere."""
    result = bytearray(AR_KEY_LEN)
    for i in range(AR_KEY_LEN):
        if i in _XOR_INDICES:
            result[i] = left[i] ^ right[i]
        else:
            result[i] = (left[i] + right[i]) % 256
    return result


def _add_two(left: bytearray, right: bytearray) -> bytearray:
    """SAFER+ add_two: add mod 256 at positions {0,3,4,7,8,11,12,15}, XOR elsewhere."""
    result = bytearray(AR_KEY_LEN)
    for i in range(AR_KEY_LEN):
        if i in _XOR_INDICES:
            result[i] = (left[i] + right[i]) % 256
        else:
            result[i] = left[i] ^ right[i]
    return result


def _nonlin_subs(inp: bytearray) -> bytearray:
    """SAFER+ nonlinear substitution (exponential/logarithmic S-box)."""
    result = bytearray(AR_KEY_LEN)
    for i in range(AR_KEY_LEN):
        if i in _XOR_INDICES:
            result[i] = EXP_45[inp[i]]
        else:
            result[i] = LOG_45[inp[i]]
    return result


def _pht(x: int, y: int) -> Tuple[int, int]:
    """Pseudo-Hadamard Transform."""
    return (2 * x + y) % 256, (x + y) % 256


def _phts(inp: bytearray) -> bytearray:
    """Apply PHT to consecutive byte pairs."""
    result = bytearray(AR_KEY_LEN)
    for i in range(0, AR_KEY_LEN, 2):
        result[i], result[i + 1] = _pht(inp[i], inp[i + 1])
    return result


def _permute(inp: bytearray) -> bytearray:
    """Armenian permutation."""
    return bytearray(inp[_PERM[i]] for i in range(AR_KEY_LEN))


def _rotate_key(key: bytearray) -> bytearray:
    """Rotate each byte left by 3 bits."""
    result = bytearray(len(key))
    for i in range(len(key)):
        b = key[i]
        result[i] = ((b << 3) | (b >> 5)) & 0xFF
    return result


def _biases() -> List[Optional[bytearray]]:
    """Compute SAFER+ key schedule biases B[2..17]."""
    b_list: List[Optional[bytearray]] = [None, None]
    for n in range(2, 18):
        bias = bytearray(AR_KEY_LEN)
        for i in range(AR_KEY_LEN):
            bias[i] = int(((45 ** (45 ** (17 * n + i + 1) % 257)) % 257) % 256)
        b_list.append(bias)
    return b_list


def _key_schedule(key: bytearray) -> List[Optional[bytearray]]:
    """SAFER+ key schedule: generate 17 subkeys from 128-bit master key."""
    biases = _biases()
    byte_16 = 0
    for i in range(AR_KEY_LEN):
        byte_16 ^= key[i]

    expanded = bytearray(key) + bytearray([byte_16])

    keys: List[Optional[bytearray]] = [None] * 18
    keys[1] = bytearray(expanded[:AR_KEY_LEN])

    prev = bytearray(expanded)
    for n in range(2, 18):
        rotated = _rotate_key(prev)
        offset = (n - 1) % 17
        selected = bytearray(rotated[offset:] + rotated[:offset])[:AR_KEY_LEN]
        keys[n] = bytearray((selected[i] + biases[n][i]) % 256 for i in range(AR_KEY_LEN))
        prev = rotated

    return keys


def _add_bytes_mod256(left: bytearray, right: bytearray) -> bytearray:
    """Bytewise addition mod 256."""
    return bytearray((left[i] + right[i]) % 256 for i in range(AR_KEY_LEN))


def _xor_bytes(left: bytearray, right: bytearray) -> bytearray:
    """Bytewise XOR."""
    return bytearray(left[i] ^ right[i] for i in range(AR_KEY_LEN))


def _ar_rounds(keys: List[Optional[bytearray]], inp: bytearray,
               is_prime: bool) -> List[Optional[bytearray]]:
    """Execute SAFER+ Ar rounds (8 rounds)."""
    ar: List[Optional[bytearray]] = [None] * 11
    ar[1] = bytearray(inp)
    temp = bytearray(inp)

    for r in range(1, 9):
        if is_prime and r == 3:
            temp = _add_one(temp, ar[1])

        rv = _add_one(temp, keys[2 * r - 1])
        rv = _nonlin_subs(rv)
        rv = _add_two(rv, keys[2 * r])
        rv = _phts(rv)
        rv = _permute(rv)
        rv = _phts(rv)
        rv = _permute(rv)
        rv = _phts(rv)
        rv = _permute(rv)
        rv = _phts(rv)

        temp = rv
        ar[r + 1] = rv

    ar[10] = _add_one(ar[9], keys[17])
    return ar


def _expand(inp: bytearray, length: int) -> bytearray:
    """Expand L-byte input to 16 bytes (EQ 14, BT Spec p.1675)."""
    return bytearray(inp[i % length] for i in range(AR_KEY_LEN))


def _k_to_k_tilda(k: bytearray) -> bytearray:
    """Compute K_tilda from K (EQ 15, BT Spec p.1676)."""
    result = bytearray(AR_KEY_LEN)
    for i in range(AR_KEY_LEN):
        if _KT_ADD[i] is not None:
            result[i] = (k[i] + _KT_ADD[i]) % 256
        else:
            result[i] = k[i] ^ _KT_XOR[i]
    return result


def H(k: bytearray, i_one: bytearray, i_two: bytearray,
      length: int) -> Tuple[List, List, List, List, bytearray]:
    """SAFER+ hash function H used in e1 and e3.

    Args:
        k: 16-byte key (link key).
        i_one: 16-byte input 1 (RAND).
        i_two: Variable-length input 2 (BTADD or COF).
        length: Length of i_two (6 for BTADD, 12 for COF).

    Returns:
        Tuple of (Keys, Ar, KeysPrime, ArPrime, Output).
    """
    keys = _key_schedule(k)
    k_tilda = _k_to_k_tilda(k)
    keys_prime = _key_schedule(k_tilda)

    i_two_ext = _expand(i_two, length)

    ar = _ar_rounds(keys, i_one, is_prime=False)

    pre_ar_prime_inp = _xor_bytes(ar[10], i_one)
    ar_prime_inp = _add_bytes_mod256(i_two_ext, pre_ar_prime_inp)
    ar_prime = _ar_rounds(keys_prime, ar_prime_inp, is_prime=True)

    return keys, ar, keys_prime, ar_prime, ar_prime[10]


def e1(k: bytearray, rand: bytearray, btadd_s: bytearray) -> Tuple[bytearray, bytearray]:
    """Compute SRES and ACO for BT authentication (EQ 12, BT Spec p.1675).

    Args:
        k: 16-byte link key (Kl).
        rand: 16-byte AU_RAND.
        btadd_s: 6-byte slave Bluetooth address.

    Returns:
        Tuple of (SRES: 4 bytes, ACO: 12 bytes).
    """
    _, _, _, _, out = H(k, rand, btadd_s, BTADD_LEN)
    sres = out[:SRES_LEN]
    aco = out[SRES_LEN:]
    return sres, aco


def e3(k: bytearray, rand: bytearray, cof: bytearray) -> bytearray:
    """Compute encryption key Kc (EQ 23, BT Spec p.1681).

    Args:
        k: 16-byte link key (Kl).
        rand: 16-byte EN_RAND.
        cof: 12-byte Ciphering Offset (ACO or BTADD_master || BTADD_master).

    Returns:
        Kc: 16-byte encryption key.
    """
    _, _, _, _, kc = H(k, rand, cof, COF_LEN)
    return kc


def _gf128_multiply_mod(a: int, b: int, modulus: int) -> int:
    """GF(2^128) polynomial multiplication modulo a reduction polynomial."""
    result = 0
    a_val = a
    for _ in range(128):
        if b & 1:
            result ^= a_val
        b >>= 1
        carry = a_val & (1 << 127)
        a_val = (a_val << 1) & ((1 << 128) - 1)
        if carry:
            a_val ^= modulus
    return result


def _gf128_multiply(a: int, b: int) -> int:
    """GF(2^128) polynomial multiplication (no reduction, 256-bit result)."""
    result = 0
    for i in range(128):
        if b & (1 << i):
            result ^= (a << i)
    return result


def Kc_to_Kc_prime(kc: bytearray, entropy_bytes: int) -> bytearray:
    """Reduce Kc entropy to L bytes via GF(2^128) polynomials.

    This is the mechanism exploited by KNOB to weaken the session key.

    Args:
        kc: 16-byte encryption key from e3().
        entropy_bytes: Negotiated key size in bytes (1-16).

    Returns:
        Kc': 16-byte reduced encryption key.
    """
    if entropy_bytes == 16:
        return bytearray(kc)

    g1 = G1[entropy_bytes]
    g2 = G2[entropy_bytes]

    kc_int = int.from_bytes(kc, "big")
    kc_mod_g1 = _gf128_multiply_mod(kc_int, 1, g1)

    kc_prime_full = _gf128_multiply(g2, kc_mod_g1)
    kc_prime_int = kc_prime_full & ((1 << 128) - 1)

    return bytearray(kc_prime_int.to_bytes(AR_KEY_LEN, "big"))


def kdf(link_key: bytearray, au_rand: bytearray, en_rand: bytearray,
        btadd_peer: bytearray, entropy: int) -> bytearray:
    """Full BT Classic Key Derivation Function.

    Computes the session key (Kc') from the link key and session parameters.
    Used by KNOB/BIAS/BLUFFS analysis to verify/crack session keys.

    Args:
        link_key: 16-byte paired link key.
        au_rand: 16-byte authentication random challenge.
        en_rand: 16-byte encryption random nonce.
        btadd_peer: 6-byte peer Bluetooth address.
        entropy: Negotiated key size in bytes (1-16).

    Returns:
        Kc': 16-byte session encryption key.
    """
    btadd_rev = bytearray(reversed(btadd_peer))
    _, cof = e1(link_key, au_rand, btadd_rev)

    kc = e3(link_key, en_rand, cof)
    kc_rev = bytearray(reversed(kc))

    kc_prime = Kc_to_Kc_prime(kc_rev, entropy)
    return bytearray(reversed(kc_prime))
