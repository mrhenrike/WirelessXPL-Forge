#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Airgeddon subprocess bridge.

Provides a non-interactive launcher path for common Airgeddon workflows by
feeding predefined environment variables and arguments.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    __info__ = {
        "name": "Airgeddon Bridge",
        "description": (
            "Subprocess bridge to Airgeddon for handshake/WPS/evil-twin/WPA3 "
            "operations in authorized labs."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Airgeddon contributors (subprocess integration)",
        ),
        "references": ("https://github.com/v1s1t0r1sh3r3/airgeddon",),
        "devices": ("wifi",),
    }

    mode = OptString(
        "handshake",
        "Mode: handshake | wps | evil_twin | pmkid | deauth | wpa3_downgrade | menu",
    )
    interface = OptString("wlan0mon", "Monitor mode interface")
    target_bssid = OptString("", "Target BSSID")
    target_essid = OptString("", "Target ESSID")
    channel = OptString("", "Target channel")
    dry_run = OptBool(False, "Print command/env without executing")

    def _find_airgeddon(self) -> Optional[str]:
        found = shutil.which("airgeddon")
        if found:
            return found
        candidate = (
            Path(__file__).resolve().parents[5]
            / "submodules"
            / "IoT"
            / "airgeddon"
            / "airgeddon.sh"
        )
        if candidate.exists():
            return str(candidate)
        return None

    def _build_env(self) -> Dict[str, str]:
        mode = str(self.mode).strip().lower()
        mapping = {
            "handshake": "handshake",
            "wps": "wps",
            "evil_twin": "et",
            "pmkid": "pmkid",
            "deauth": "dos",
            "wpa3_downgrade": "wpa3",
            "menu": "menu",
        }
        if mode not in mapping:
            raise ValueError("Unsupported mode: {}".format(mode))
        env = {
            "AIRGEDDON_WXF_MODE": mapping[mode],
            "AIRGEDDON_WXF_IFACE": str(self.interface),
            "AIRGEDDON_WXF_BSSID": str(self.target_bssid),
            "AIRGEDDON_WXF_ESSID": str(self.target_essid),
            "AIRGEDDON_WXF_CHANNEL": str(self.channel),
            "AIRGEDDON_WXF_TMUX_MOUSE": "1",
        }
        return env


    def check(self) -> str:
        """Verify external tool dependencies are installed."""
        import shutil
        tools: list[str] = []
        src = getattr(self.__class__, "__doc__", "") or ""
        for t in ("aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng",
                   "hashcat", "hcxdumptool", "hcxtools", "wifite", "bettercap",
                   "kismet", "hostapd", "dnsmasq", "mdk4", "mdk3",
                   "hostapd-wpe", "hostapd-mana", "eaphammer"):
            if t.replace("-ng", "").replace("-", "") in (src + self.__class__.__name__).lower():
                tools.append(t)
        if not tools:
            tools = ["aircrack-ng"]
        missing = [t for t in tools if not shutil.which(t.rstrip("_"))]
        if missing:
            return f"Missing tools: {', '.join(missing)} - install before use"
        return f"Tool dependencies found: {', '.join(tools)} - prerequisites OK"

    def run(self) -> None:
        binary = self._find_airgeddon()
        if not binary:
            print_error("airgeddon not found. Install it or clone submodules/IoT/airgeddon.")
            return

        try:
            env_override = self._build_env()
        except ValueError as err:
            print_error(str(err))
            return

        cmd = ["sudo", binary]
        merged_env = os.environ.copy()
        merged_env.update(env_override)

        if self.dry_run:
            print_status("DRY RUN command: {}".format(" ".join(cmd)))
            for k in sorted(env_override.keys()):
                print_info("  {}={}".format(k, env_override[k]))
            return

        print_status("Launching Airgeddon mode '{}'...".format(self.mode))
        print_info("Command: {}".format(" ".join(cmd)))
        try:
            subprocess.run(cmd, env=merged_env, check=False)
        except KeyboardInterrupt:
            print_info("Airgeddon interrupted by user.")
        except Exception as err:
            logger.exception("Airgeddon execution failed")
            print_error("Airgeddon failed: {}".format(err))
