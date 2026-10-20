"""Tests for wirelessxpl.core.bt_crypto — SAFER+ Bluetooth crypto primitives."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wirelessxpl.core.bt_crypto import (
    AR_KEY_LEN,
    EXP_45,
    LOG_45,
    Kc_to_Kc_prime,
    _add_one,
    _add_two,
    _nonlin_subs,
    _permute,
    _pht,
    _phts,
    _rotate_key,
    _xor_bytes,
    e1,
    e3,
    kdf,
)

# ---------------------------------------------------------------------------
# S-box tables
# ---------------------------------------------------------------------------

def test_exp_45_length() -> None:
    assert len(EXP_45) == 256


def test_log_45_length() -> None:
    assert len(LOG_45) == 256


def test_exp_log_inverse_relation() -> None:
    for i in range(1, 256):
        val = EXP_45[i]
        assert LOG_45[val] == i, f"Failed at index {i}"


def test_exp_45_first_value() -> None:
    assert EXP_45[0] == 1


# ---------------------------------------------------------------------------
# Basic operations
# ---------------------------------------------------------------------------

def test_pht_basic() -> None:
    a, b = _pht(10, 20)
    assert a == (2 * 10 + 20) % 256
    assert b == (10 + 20) % 256


def test_pht_overflow() -> None:
    a, b = _pht(200, 200)
    assert a == (400 + 200) % 256
    assert b == 400 % 256


def test_xor_bytes() -> None:
    a = bytearray(b"\xff" * 16)
    b_arr = bytearray(b"\xff" * 16)
    result = _xor_bytes(a, b_arr)
    assert result == bytearray(16)


def test_xor_bytes_identity() -> None:
    a = bytearray(range(16))
    zeros = bytearray(16)
    result = _xor_bytes(a, zeros)
    assert result == a


def test_add_one_returns_16_bytes() -> None:
    a = bytearray(range(16))
    b = bytearray(range(16, 32))
    result = _add_one(a, b)
    assert len(result) == AR_KEY_LEN


def test_add_two_returns_16_bytes() -> None:
    a = bytearray(range(16))
    b = bytearray(range(16, 32))
    result = _add_two(a, b)
    assert len(result) == AR_KEY_LEN


def test_nonlin_subs_returns_16_bytes() -> None:
    inp = bytearray(range(16))
    result = _nonlin_subs(inp)
    assert len(result) == AR_KEY_LEN


def test_phts_returns_16_bytes() -> None:
    inp = bytearray(range(16))
    result = _phts(inp)
    assert len(result) == AR_KEY_LEN


def test_permute_returns_16_bytes() -> None:
    inp = bytearray(range(16))
    result = _permute(inp)
    assert len(result) == AR_KEY_LEN


def test_rotate_key_returns_same_length() -> None:
    key = bytearray(range(16))
    result = _rotate_key(key)
    assert len(result) == 16


def test_rotate_key_zero() -> None:
    key = bytearray(16)
    result = _rotate_key(key)
    assert result == bytearray(16)


# ---------------------------------------------------------------------------
# e1: authentication
# ---------------------------------------------------------------------------

def test_e1_returns_sres_and_aco() -> None:
    k = bytearray(range(16))
    rand = bytearray(range(16, 32))
    btadd = bytearray(b"\xaa\xbb\xcc\xdd\xee\xff")
    sres, aco = e1(k, rand, btadd)
    assert len(sres) == 4
    assert len(aco) == 12


def test_e1_deterministic() -> None:
    k = bytearray(b"\x01" * 16)
    rand = bytearray(b"\x02" * 16)
    btadd = bytearray(b"\x03" * 6)
    sres1, aco1 = e1(k, rand, btadd)
    sres2, aco2 = e1(k, rand, btadd)
    assert sres1 == sres2
    assert aco1 == aco2


def test_e1_different_keys_different_output() -> None:
    k1 = bytearray(b"\x01" * 16)
    k2 = bytearray(b"\x02" * 16)
    rand = bytearray(b"\x03" * 16)
    btadd = bytearray(b"\x04" * 6)
    sres1, _ = e1(k1, rand, btadd)
    sres2, _ = e1(k2, rand, btadd)
    assert sres1 != sres2


# ---------------------------------------------------------------------------
# e3: encryption key
# ---------------------------------------------------------------------------

def test_e3_returns_16_bytes() -> None:
    k = bytearray(range(16))
    rand = bytearray(range(16, 32))
    cof = bytearray(range(12))
    kc = e3(k, rand, cof)
    assert len(kc) == 16


def test_e3_deterministic() -> None:
    k = bytearray(b"\xaa" * 16)
    rand = bytearray(b"\xbb" * 16)
    cof = bytearray(b"\xcc" * 12)
    assert e3(k, rand, cof) == e3(k, rand, cof)


# ---------------------------------------------------------------------------
# Kc_to_Kc_prime: entropy reduction (KNOB)
# ---------------------------------------------------------------------------

def test_kc_to_kc_prime_full_entropy() -> None:
    kc = bytearray(range(16))
    result = Kc_to_Kc_prime(kc, 16)
    assert result == kc


def test_kc_to_kc_prime_reduced() -> None:
    kc = bytearray(b"\xff" * 16)
    result = Kc_to_Kc_prime(kc, 1)
    assert len(result) == 16
    assert result != kc


def test_kc_to_kc_prime_deterministic() -> None:
    kc = bytearray(b"\xab" * 16)
    r1 = Kc_to_Kc_prime(kc, 8)
    r2 = Kc_to_Kc_prime(kc, 8)
    assert r1 == r2


# ---------------------------------------------------------------------------
# kdf: full key derivation
# ---------------------------------------------------------------------------

def test_kdf_returns_16_bytes() -> None:
    lk = bytearray(b"\x01" * 16)
    au_rand = bytearray(b"\x02" * 16)
    en_rand = bytearray(b"\x03" * 16)
    btadd = bytearray(b"\x04" * 6)
    result = kdf(lk, au_rand, en_rand, btadd, entropy=16)
    assert len(result) == 16


def test_kdf_deterministic() -> None:
    lk = bytearray(b"\x10" * 16)
    au = bytearray(b"\x20" * 16)
    en = bytearray(b"\x30" * 16)
    bt = bytearray(b"\x40" * 6)
    r1 = kdf(lk, au, en, bt, entropy=8)
    r2 = kdf(lk, au, en, bt, entropy=8)
    assert r1 == r2


def test_kdf_different_entropy_different_result() -> None:
    lk = bytearray(b"\x10" * 16)
    au = bytearray(b"\x20" * 16)
    en = bytearray(b"\x30" * 16)
    bt = bytearray(b"\x40" * 6)
    r_full = kdf(lk, au, en, bt, entropy=16)
    r_min = kdf(lk, au, en, bt, entropy=1)
    assert r_full != r_min
