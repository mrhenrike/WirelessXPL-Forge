#!/usr/bin/env python3
"""Apply @requires_os decorators in batch to wifi/ and bluetooth/ modules.

Classification:
  LINUX_ONLY  - monitor mode, raw sockets, HCI direct, Zigbee, hostapd, aircrack
  LINUX_MAC   - BLE via bleak (bleak supports Linux + macOS)
  CROSS_PLATFORM - pcap analysis, offline tools, export, info-only

Run from repo root:
  python3 tools/apply_os_guard.py [--dry-run]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

BASE = Path(__file__).parent.parent
WIFI_DIR = BASE / "wirelessxpl/modules/generic/wifi"
BT_DIR   = BASE / "wirelessxpl/modules/generic/bluetooth"

IMPORT_LINE = "from wirelessxpl.core.os_guard import OSRequirement, requires_os\n"

# wifi/ modules that are cross-platform (offline/analysis/export only)
WIFI_CROSS = {
    "pcap_wpa_handshake_validate.py",
    "pcap_rf_anomaly_ml.py",
    "wordlist_orchestrator.py",
    "hashcat_gpu_orchestrator.py",
    "gps_wardriving_ndjson.py",
    "wigle_export.py",
    "research_ecosystem_status.py",
    "aircrack_crack_engine.py",
    "sigma_rule_detector.py",
    "_disclaimer.py",
    "_i18n_service.py",
    "__init__.py",
}

# bluetooth/ modules using bleak (Linux + macOS)
BT_LINUX_MAC = {
    "btle_scan.py",
    "btle_enumerate.py",
    "btle_write.py",
    "ble_gatt_enum_unauth.py",
    "ble_extra_attacks.py",
    "ble_phishing.py",
    "ble_spoofing_impersonation.py",
    "ble_crackle.py",
    "ble_btlejack.py",
    "ble_bluffs_native.py",
    "ble_sweyntooth_bridge.py",
}

BT_SKIP = {"__init__.py", "_disclaimer.py"}


def already_decorated(text: str) -> bool:
    return "requires_os" in text and "@requires_os" in text


def has_exploit_class(text: str) -> bool:
    return bool(re.search(r"^class Exploit", text, re.MULTILINE))


def add_import(text: str) -> str:
    """Insert os_guard import after the last TOP-LEVEL complete import block.

    Only considers lines starting at column 0 (non-indented imports).
    Handles multi-line imports:
        from foo import (
            Bar,
            Baz,
        )
    by tracking the closing ')'.
    """
    if "from wirelessxpl.core.os_guard" in text:
        return text
    lines = text.splitlines(keepends=True)
    last_import_end = 0
    inside_paren = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Only consider TOP-LEVEL imports (line starts at column 0)
        if not inside_paren and line[:1] in ("i", "f") and stripped.startswith(("import ", "from ")):
            last_import_end = i
            if "(" in stripped and ")" not in stripped:
                inside_paren = True
        elif inside_paren:
            last_import_end = i
            if ")" in line and not line[0].isspace():
                inside_paren = False
            elif ")" in stripped and not line[0].isspace():
                inside_paren = False
            elif stripped == ")":
                inside_paren = False
    lines.insert(last_import_end + 1, IMPORT_LINE)
    return "".join(lines)


def add_decorator(text: str, requirement: str) -> str:
    """Add @requires_os(OSRequirement.<req>) before 'class Exploit'."""
    decorator = f"@requires_os(OSRequirement.{requirement})\n"
    # Only decorate the first class Exploit (main entry point)
    return re.sub(
        r"(^class Exploit\b)",
        decorator + r"\1",
        text,
        count=1,
        flags=re.MULTILINE,
    )


def patch_file(path: Path, requirement: str, dry_run: bool) -> bool:
    text = path.read_text(encoding="utf-8")
    if already_decorated(text):
        return False
    if not has_exploit_class(text):
        return False
    patched = add_import(text)
    patched = add_decorator(patched, requirement)
    if dry_run:
        print(f"  [DRY] would patch {path.name} -> {requirement}")
        return True
    path.write_text(patched, encoding="utf-8")
    print(f"  PATCHED  {path.name} -> {requirement}")
    return True


def main(dry_run: bool = False) -> None:
    changed = 0

    WIFI_SKIP = WIFI_CROSS | {"__init__.py", "_disclaimer.py", "_i18n_service.py"}

    print("=== wifi/ modules ===")
    for p in sorted(WIFI_DIR.glob("*.py")):
        if p.name in WIFI_SKIP:
            continue
        req = "CROSS_PLATFORM" if p.name in WIFI_CROSS else "LINUX_ONLY"
        if patch_file(p, req, dry_run):
            changed += 1

    print("=== bluetooth/ modules ===")
    for p in sorted(BT_DIR.glob("*.py")):
        if p.name in BT_SKIP:
            continue
        if p.name in BT_LINUX_MAC:
            req = "LINUX_MAC"
        else:
            req = "LINUX_ONLY"
        if patch_file(p, req, dry_run):
            changed += 1

    print(f"\nTotal patched: {changed}")


if __name__ == "__main__":
    dry = "--dry-run" in sys.argv
    main(dry_run=dry)
