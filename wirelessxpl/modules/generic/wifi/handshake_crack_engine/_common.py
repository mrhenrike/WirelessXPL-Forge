#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""WPA/WPA2/WPA3 Handshake & PMKID Crack Engine.

Multi-backend offline cracking module. The user selects the backend;
the module builds the optimal command, streams output, parses results,
and reports found passwords.

Supported backends:
  hashcat_gpu    hashcat with GPU acceleration (-D 2) — fastest
  hashcat_cpu    hashcat CPU only (-D 1 --force)      — GPU-less machines
  hashcat_auto   hashcat auto-detect device            — default
  aircrack       aircrack-ng (pcap/pcapng directly)   — no conversion needed
  john           John the Ripper (wpapsk format)       — CPU, rule support
  cowpatty       cowpatty (genpmk pre-computation)     — targeted attacks
  auto           Try backends in order: hashcat_gpu → aircrack → john

Input formats accepted:
  - .pcapng / .pcap   (4-way handshake or PMKID capture)
  - .hash             (hcxpcapngtool WPA*02* or WPA*01* format)
  - .hccapx / .22000  (hashcat native format)
  - .cap              (aircrack native)

The module automatically converts formats as needed (hcxpcapngtool).

Inspired workflow integrations (native, no external bridges):
  - HashCater: attack_flow both, smart ISP masks, GPU thermal/cooldown
  - Cap2Hash: batch PCAP→HC22000 conversion with skip/cleanup

Version: 2.0.0
"""

import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

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
from wirelessxpl.core.os_guard import OSRequirement, requires_os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Backend definitions
# ---------------------------------------------------------------------------

BACKENDS = {
    "hashcat_gpu": {
        "bin":  "hashcat",
        "desc": "hashcat GPU acceleration (-D 2) — CUDA/OpenCL, fastest",
    },
    "hashcat_cpu": {
        "bin":  "hashcat",
        "desc": "hashcat CPU only (-D 1 --force) — no GPU required",
    },
    "hashcat_auto": {
        "bin":  "hashcat",
        "desc": "hashcat auto device detection — picks best available",
    },
    "aircrack": {
        "bin":  "aircrack-ng",
        "desc": "aircrack-ng — reads pcap/pcapng directly, no conversion",
    },
    "john": {
        "bin":  "john",
        "desc": "John the Ripper — wpapsk format, supports rules/mangling",
    },
    "cowpatty": {
        "bin":  "cowpatty",
        "desc": "cowpatty — direct WPA-PSK attack, genpmk pre-computation",
    },
    "auto": {
        "bin":  None,
        "desc": "Auto: try hashcat_gpu → hashcat_cpu → aircrack → john",
    },
}

# Hashcat modes for WPA
_HASH_MODE_WPA_EAPOL  = 22000   # WPA-EAPOL-PBKDF2 (M1+M2 pair)
_HASH_MODE_WPA_PMKID  = 22001   # WPA-PMKID-PBKDF2
_HASH_MODE_HCCAPX     = 2500    # legacy .hccapx

_CAPTURE_GLOBS = ("*.pcap", "*.cap", "*.pcapng")
_HASH_GLOBS = ("*.hc22000", "*.22000", "*.hash")

# ---------------------------------------------------------------------------
# Session logging, GPU thermal, smart masks (HashCater + Cap2Hash native)
# ---------------------------------------------------------------------------

class _SessionLog:
    """Optional session log file (HashCater-style long runs)."""

    def __init__(self, path: str) -> None:
        self._path = Path(path).expanduser() if path else None
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, message: str) -> None:
        if not self._path:
            return
        ts = time.strftime("%H:%M:%S")
        try:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(f"[{ts}] {message}\n")
        except OSError as exc:
            logger.debug("session log write failed: %s", exc)


def _get_gpu_temperature() -> int | None:
    """Read GPU temperature via nvidia-smi or Linux hwmon (°C)."""
    if shutil.which("nvidia-smi"):
        try:
            r = subprocess.run(
                ["nvidia-smi", "--query-gpu=temperature.gpu",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=10,
            )
            if r.stdout.strip():
                return int(r.stdout.strip().splitlines()[0].strip())
        except (ValueError, subprocess.SubprocessError):
            pass

    for hwmon in Path("/sys/class/drm").glob("card*/device/hwmon/hwmon*/temp1_input"):
        try:
            milli = int(hwmon.read_text().strip())
            return milli // 1000
        except (ValueError, OSError):
            continue
    return None


def _wait_gpu_cooldown(retain_c: int, slog: _SessionLog) -> None:
    """Wait until GPU drops below retain_c (HashCater Wait-GpuCooldown)."""
    if retain_c <= 0:
        return
    while True:
        temp = _get_gpu_temperature()
        if temp is None or temp <= retain_c:
            return
        msg = f"[COOLDOWN] GPU at {temp}°C — aguardando ≤{retain_c}°C…"
        print_warning(f"  {msg}")
        slog.write(msg)
        time.sleep(30)


def _hashcat_safety_args(temp_abort: int, workload: int) -> list[str]:
    args: list[str] = []
    if workload > 0:
        args.extend(["-w", str(max(1, min(4, workload)))])
    if temp_abort > 0:
        args.append(f"--hwmon-temp-abort={temp_abort}")
    return args


def _generate_smart_masks(essid: str) -> list[str]:
    """SSID + Brazilian ISP heuristic masks (HashCater + real BR patterns)."""
    masks: list[str] = []
    essid_up = (essid or "").upper()
    base = re.sub(r"[^a-zA-Z0-9]", "", essid or "").lower()

    masks.extend(["?d?d?d?d?d?d?d?d", "?d?d?d?d?d?d?d?d?d?d"])

    if essid_up.startswith("VIVO"):
        masks.extend(["vivo?d?d?d?d", "VIVO?d?d?d?d", "?d?d?d?d?d?d?d?d?d"])
    elif essid_up.startswith("CLARO"):
        masks.extend(["claro?d?d?d?d", "CLARO?d?d?d?d", "?u?l?l?l?l?d?d?d?d"])
    elif "TP-LINK" in essid_up or essid_up.startswith("TP_LINK"):
        masks.extend(["tplink?d?d?d", "admin?d?d?d?d", "?d?d?d?d?d?d?d?d"])
    elif essid_up.startswith("NET_") or essid_up.startswith("NET-"):
        masks.extend(["net?d?d?d?d", "?d?d?d?d?d?d?d?d"])
    elif essid_up.startswith("WIFI") or essid_up.startswith("WI-FI"):
        masks.extend(["wifi?d?d?d?d", "?d?d?d?d?d?d?d?d"])
    elif essid_up.startswith("OI_") or essid_up.startswith("OI "):
        masks.extend(["oi?d?d?d?d", "?d?d?d?d?d?d?d?d"])
    elif essid_up.startswith("TIM_") or "TIM " in essid_up:
        masks.extend(["tim?d?d?d?d", "?d?d?d?d?d?d?d?d"])
    elif essid_up.startswith("GVT") or essid_up.startswith("SKY"):
        masks.extend(["?l?l?l?l?d?d?d?d", "?d?d?d?d?d?d?d?d"])
    elif essid_up.startswith("AZUL") or "AZULLAR" in essid_up:
        masks.extend(["azul?d?d?d?d", "?l?l?l?l?l?l?d?d"])

    if len(base) >= 4:
        masks.extend([f"{base}@?d?d?d", f"{base}@?d?d?d?d"])

    seen: set[str] = set()
    ordered: list[str] = []
    for m in masks:
        if m not in seen:
            seen.add(m)
            ordered.append(m)
    return ordered


