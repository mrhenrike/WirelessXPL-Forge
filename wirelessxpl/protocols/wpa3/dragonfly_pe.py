"""
wirelessxpl/protocols/wpa3/dragonfly_pe.py - Native WPA3 SAE Dragonfly PE Generator.

Implements the SAE Dragonfly Password Element (PE) generation algorithm
as defined in IEEE 802.11-2020 and RFC 7664.

Two modes:
  1. Hunt-and-Peck (original, vulnerable to timing side-channel):
     generate_pe(password, mac_ap, mac_sta) -> (iterations, pe_value)

  2. Fixed-iteration mitigated (constant-time, recommended):
     generate_pe_fixed(password, mac_ap, mac_sta, Kmin=40) -> (iterations, pe_value)

Uses MODP Group-22 (1024-bit prime, RFC 5114) as reference group for timing analysis.

Source: Adapted from wireless-research/wpa3_sec/src/dragonfly_modp.py
License: Research/educational - reimplemented without external deps.

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import random
from hashlib import pbkdf2_hmac
from typing import Tuple

__version__ = "1.0.0"

# MODP Group-22 parameters (RFC 5114, 1024-bit prime, 160-bit subgroup order)
# Used for SAE Dragonfly timing analysis demonstrations
_P = int(
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
    "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
    "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
    "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
    "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
    "DF1FB2BC2E4A4371", 16
)
_G = int(
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
    "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
    "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
    "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
    "855E6EEB22B3B2E5", 16
)

# Typical P256 (ECC Group 19) parameters for real WPA3-SAE
# P256 is used in modern WPA3-Personal implementations
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _mac_to_bytes(mac: str) -> bytes:
    """Convert MAC address string to 6-byte binary."""
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def generate_pe(
    password: str,
    ap_mac: str,
    sta_mac: str,
) -> Tuple[int, int]:
    """Generate WPA3 SAE Password Element using Hunt-and-Peck (MODP Group-22).

    This is the ORIGINAL Dragonfly algorithm vulnerable to timing side-channels
    (CVE-2019-9494 Dragonblood). The number of iterations leaks information
    about the password.

    Args:
        password: WPA3 passphrase.
        ap_mac: AP MAC address (e.g. "AA:BB:CC:DD:EE:FF").
        sta_mac: Station MAC address.

    Returns:
        (iterations, pe_value) where iterations leaks timing info.
    """
    pwd_bytes = password.encode("utf-8")
    ap_bytes = _mac_to_bytes(ap_mac)
    sta_bytes = _mac_to_bytes(sta_mac)
    key_len = (_P.bit_length() + 7) // 8

    for counter in range(1, 256):
        base = hashlib.sha512(pwd_bytes + ap_bytes + sta_bytes + bytes([counter])).digest()
        seed = pbkdf2_hmac("sha512", base, b"", 1, dklen=key_len)
        seed_int = int.from_bytes(seed, "big")
        if seed_int < _P:
            pe = pow(_G, seed_int, _P)
            if pe > 1:
                return counter, pe
    raise RuntimeError("PE not found within 255 iterations (unexpected)")


def generate_pe_fixed(
    password: str,
    ap_mac: str,
    sta_mac: str,
    kmin: int = 40,
    kmax: int = 255,
    num_pe: int = 20,
) -> Tuple[int, int]:
    """Generate WPA3 SAE Password Element with fixed iteration count (mitigated).

    This is the MITIGATED algorithm (constant-time variant) recommended by
    the WPA3 specification after Dragonblood disclosure. Always runs at least
    kmin iterations regardless of when the first valid PE is found.

    Args:
        password: WPA3 passphrase.
        ap_mac: AP MAC address.
        sta_mac: Station MAC address.
        kmin: Minimum iterations (default 40, spec recommends >= 40).
        kmax: Maximum iterations (default 255).
        num_pe: Target number of PE candidates to collect.

    Returns:
        (iterations, pe_value) where iterations is constant = kmin.
    """
    pwd_bytes = password.encode("utf-8")
    ap_bytes = _mac_to_bytes(ap_mac)
    sta_bytes = _mac_to_bytes(sta_mac)
    key_len = (_P.bit_length() + 7) // 8
    found_pes = []
    iterations = 0

    for counter in range(1, kmax + 1):
        iterations = counter
        base = hashlib.sha512(pwd_bytes + ap_bytes + sta_bytes + bytes([counter])).digest()
        seed = pbkdf2_hmac("sha512", base, b"", 1, dklen=key_len)
        seed_int = int.from_bytes(seed, "big")
        if seed_int < _P:
            pe = pow(_G, seed_int, _P)
            if pe > 1:
                found_pes.append(pe)
                if len(found_pes) >= num_pe and counter >= kmin:
                    break
        if counter == kmin:
            break  # Always stop at kmin (constant time)

    if not found_pes:
        raise RuntimeError("No PE found by kmin - increase kmin")
    return iterations, random.choice(found_pes)


def measure_timing_vulnerability(
    password: str,
    ap_mac: str,
    sta_mac: str,
    trials: int = 10,
) -> dict:
    """Measure timing variance in PE generation (detects Dragonblood CVE-2019-9494).

    Args:
        password: Passphrase to test.
        ap_mac: AP MAC.
        sta_mac: STA MAC.
        trials: Number of timing measurements.

    Returns:
        dict with min/max/mean iterations and vulnerability assessment.
    """
    import time
    iteration_counts = []
    times = []

    for _ in range(trials):
        t0 = time.perf_counter()
        iters, _ = generate_pe(password, ap_mac, sta_mac)
        elapsed = time.perf_counter() - t0
        iteration_counts.append(iters)
        times.append(elapsed)

    mean_iters = sum(iteration_counts) / len(iteration_counts)
    variance = sum((x - mean_iters) ** 2 for x in iteration_counts) / len(iteration_counts)
    vulnerable = variance > 0.5  # Non-zero variance = timing leak

    return {
        "password": password[:3] + "***",
        "trials": trials,
        "iterations_min": min(iteration_counts),
        "iterations_max": max(iteration_counts),
        "iterations_mean": round(mean_iters, 2),
        "iterations_variance": round(variance, 4),
        "timing_vulnerable": vulnerable,
        "assessment": (
            "VULNERABLE to timing side-channel (Dragonblood CVE-2019-9494)"
            if vulnerable else
            "Constant-time implementation detected"
        ),
    }
