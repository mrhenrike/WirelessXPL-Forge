#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Aircrack-ng Full Suite Bridge - unified orchestration for the entire aircrack-ng toolkit.

Bridges every major binary in the aircrack-ng suite as subprocess calls:

  airmon-ng    - monitor mode management
  airodump-ng  - scanning, capture, channel hop, CSV/PCAP output
  aireplay-ng  - all 7 attack modes (deauth, fake-auth, ARP replay, chop-chop,
                 fragmentation, caffe-latte, interactive/P0841)
  aircrack-ng  - WEP IV crack, WPA dict/PMKID crack
  airdecap-ng  - decrypt captured PCAP files with known key
  airolib-ng   - PMK pre-computation database management
  besside-ng   - automated WPA/WEP cracking
  packetforge-ng - forge encrypted packets for injection
  airbase-ng   - software AP / evil twin backend
  airtun-ng    - virtual tunnel interface for encrypted injection
  airdecloak-ng - remove WEP cloaking from captures
  tkiptun-ng   - TKIP QoS injection (Beck-Tews style)

Prerequisites (host):
  - aircrack-ng suite installed: apt install aircrack-ng
  - Wireless interface with injection/monitor support
  - Root/sudo privileges

Version: 1.0.0
"""


import logging
import os
import shutil
import subprocess
from typing import Dict, List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

_SUITE_BINS = (
    "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
    "airdecap-ng", "airolib-ng", "besside-ng", "packetforge-ng",
    "airbase-ng", "airtun-ng", "airdecloak-ng", "tkiptun-ng",
)

_AIREPLAY_ATTACKS = {
    "deauth":        "-0",
    "fakeauth":      "-1",
    "interactive":   "-2",
    "arp_replay":    "-3",
    "chopchop":      "-4",
    "fragment":      "-5",
    "caffe_latte":   "-6",
    "hirte":         "-7",
    "p0841":         "-2",
}


def _which(binary: str) -> str | None:
    return shutil.which(binary)


def _run(cmd: list[str], *, timeout: int = 0, capture: bool = False,
         dry_run: bool = False) -> subprocess.CompletedProcess | None:
    """Execute subprocess with safe defaults."""
    cmd_str = " ".join(cmd)
    if dry_run:
        print_info(f"[dry-run] {cmd_str}")
        return None

    print_status(f"exec: {cmd_str}")
    try:
        kwargs: dict = {
            "stdout": subprocess.PIPE if capture else None,
            "stderr": subprocess.STDOUT if capture else None,
        }
        if timeout > 0:
            kwargs["timeout"] = timeout
        result = subprocess.run(cmd, **kwargs)
        if capture and result.stdout:
            output = result.stdout.decode("utf-8", errors="replace")
            for line in output.splitlines():
                print_info(line)
        return result
    except subprocess.TimeoutExpired:
        print_status(f"Timeout ({timeout}s) reached for: {cmd[0]}")
        return None
    except FileNotFoundError:
        print_error(f"Binary not found: {cmd[0]}")
        return None


def _run_bg(cmd: list[str], *, dry_run: bool = False,
            log_file: str | None = None) -> subprocess.Popen | None:
    """Start a long-running subprocess in background."""
    cmd_str = " ".join(cmd)
    if dry_run:
        print_info(f"[dry-run bg] {cmd_str}")
        return None

    print_status(f"exec (background): {cmd_str}")
    try:
        out_target = None
        if log_file:
            out_target = open(log_file, "w")
        proc = subprocess.Popen(
            cmd,
            stdout=out_target or subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid if os.name != "nt" else None,
        )
        print_success(f"PID {proc.pid} started: {cmd[0]}")
        return proc
    except FileNotFoundError:
        print_error(f"Binary not found: {cmd[0]}")
        return None


