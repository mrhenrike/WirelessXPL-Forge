#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess for Fluxion (GPL-3.0) — captive portal + handshake snooper.

Fluxion automates the evil twin + captive portal workflow with handshake
verification: scans target, captures handshake, creates rogue AP with
vendor-branded portal, verifies submitted passwords against handshake.

Key advantages over standalone evil twin:
  - 54+ vendor-branded portal templates (TP-Link, NETGEAR, HUAWEI, etc.)
  - OS connectivity response detection (Apple CNA, Google generate_204)
  - Automatic handshake verification of submitted passwords
  - Multi-language support (25+ languages)
  - Headless tmux mode + auto-mode (merged PR #1232)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Fluxion subprocess bridge for handshake-verified captive portal attacks."""

    __info__ = {
        "name": "Fluxion Bridge",
        "description": (
            "Evil twin + captive portal with handshake verification via Fluxion "
            "(GPL-3.0 subprocess). 54+ vendor-branded templates, OS connectivity "
            "detection, auto-mode, and multi-language support."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "FluxionNetwork contributors (GPL-3.0, invoked as subprocess)",
        ),
        "references": (
            "https://github.com/FluxionNetwork/fluxion",
        ),
        "devices": ("wifi",),
    }

    target_bssid = OptMAC("", "Target AP BSSID")
    target_channel = OptString("", "Target AP channel")
    interface = OptString("", "Wi-Fi interface (blank = auto-detect)")
    attack = OptString("captive_portal", "Attack: captive_portal | handshake_snooper")
    template = OptString("", "Portal template name (e.g. TP-LINK_en, NETGEAR_en, HUAWEI_en)")
    headless = OptBool(False, "Run in headless tmux mode (Fluxion PR #1232)")
    auto_mode = OptBool(False, "Enable auto-mode (experimental)")
    language = OptString("en", "Interface language (en, es, fr, de, pt-br, etc.)")
    handshake_path = OptString("", "Path to pre-captured handshake (skip snooper)")
    dry_run = OptBool(False, "Print command without executing")

    KNOWN_TEMPLATES = [
        "TP-LINK_en", "TP-LINK_es", "TP-LINK_it", "TP-LINK_tur",
        "NETGEAR_en", "NETGEAR_es", "NETGEAR_it", "NETGEAR-Login_en",
        "HUAWEI_en", "HUAWEI_it", "HUAWEI_tur", "HUAWEI_zh",
        "FRITZBox_de", "FRITZBox1_en", "FRITZBox2_en",
        "Belkin_en", "Belkin_it",
        "ARRIS_en", "ARRIS_es",
        "Cisco_it", "Cisco-Linksys_it",
        "Dlink_it", "Dlink_ru",
        "Asus_it", "Zyxel_it", "Zyxel_ru", "Zyxel_tur",
        "Verizon_en", "Xfinity-Login_en",
        "Telekom_de", "vodafone_es", "movistar_es",
        "Livebox_fr", "Freebox_fr", "SFR_fr", "Bbox_fr",
        "Alice_it", "Telecom_it",
        "ziggo1_nl", "ziggo2_nl", "kpn_nl",
        "Proximus_fr", "Proximus_nl",
        "Google_de", "GENENIX_de",
    ]

    def _find_fluxion(self) -> Optional[str]:
        """Locate fluxion.sh entry point."""
        submodule = Path(__file__).resolve().parents[5] / "submodules" / "IoT" / "fluxion" / "fluxion.sh"
        if submodule.exists():
            return str(submodule)
        path = shutil.which("fluxion")
        return path

    def _build_command(self) -> List[str]:
        """Build the fluxion command line."""
        fluxion = self._find_fluxion()
        if not fluxion:
            raise FileNotFoundError(
                "fluxion.sh not found. Ensure submodules/IoT/fluxion is cloned."
            )

        cmd = ["sudo", "bash", fluxion]

        if self.auto_mode:
            cmd.append("--auto")

        if self.headless:
            cmd.append("--headless")

        if self.language:
            cmd.extend(["-l", self.language])

        return cmd


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
        """Execute Fluxion as subprocess."""
        try:
            cmd = self._build_command()
        except FileNotFoundError as err:
            print_error(str(err))
            return

        cmd_str = " ".join(cmd)

        if self.dry_run:
            print_info("DRY RUN — would execute:")
            print_status(cmd_str)
            if self.template:
                print_info("Template: {}".format(self.template))
            print_info("Available templates ({}):\n  {}".format(
                len(self.KNOWN_TEMPLATES),
                "\n  ".join(self.KNOWN_TEMPLATES[:20]) + "\n  ... and {} more".format(
                    len(self.KNOWN_TEMPLATES) - 20),
            ))
            return

        print_status("Launching Fluxion ({} attack)...".format(self.attack))
        print_info("Command: {}".format(cmd_str))
        if self.template:
            print_info("Requested template: {}".format(self.template))
        print_info("Fluxion is interactive — follow on-screen prompts.")
        print_info("Press Ctrl+C to abort.")

        try:
            subprocess.run(cmd, check=False)
        except KeyboardInterrupt:
            print_info("\nFluxion interrupted by user.")
        except Exception as err:
            print_error("Fluxion failed: {}".format(err))
