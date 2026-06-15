#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Wirespy — Wi-Fi monitor and attack bridge (Bash).

Wirespy is a Bash-based tool that automates:
  - Monitor mode setup/teardown
  - Channel selection and hopping
  - Hidden SSID discovery
  - Rogue AP (evil twin) creation
  - Automated SSID scanning and reporting

This bridge invokes wirespy.sh as a subprocess with the appropriate arguments.

Incorporated from:
  - submodules/IoT/wirespy (aress31 / M. Chatelain)

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
from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


def _wirespy_root() -> Path:
    return Path(__file__).resolve().parents[5] / "wirespy"


def _find_wirespy_script() -> Optional[str]:
    root = _wirespy_root()
    candidates = [
        root / "wirespy.sh",
        root / "src" / "wirespy.sh",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return shutil.which("wirespy")


class Exploit(Exploit):
    """Wirespy Wi-Fi monitoring and attack automation bridge (Bash subprocess)."""

    __info__ = {
        "name": "Wirespy Wi-Fi Monitor Bridge",
        "description": (
            "Automates Wi-Fi monitor mode, channel hopping, SSID discovery, "
            "and rogue AP creation via the wirespy Bash script (subprocess). "
            "Useful for quick Wi-Fi survey and evil-twin setup automation."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "aress31 (wirespy — invoked as Bash subprocess)",
        ),
        "references": (
            "https://github.com/aress31/wirespy",
        ),
        "devices": ("wifi", "802.11 monitor recon"),
    }

    mode = OptString(
        "monitor",
        "Modo passado ao wirespy: monitor | scan | evil_twin | help",
    )
    interface = OptString("", "Interface sem fio (ex.: wlan0)")
    channel = OptInteger(0, "Canal (0 = hop)")
    target_ssid = OptString("", "SSID alvo para evil_twin")
    extra_args = OptString("", "Argumentos extras para wirespy.sh (ex.: --timeout 30)")
    dry_run = OptBool(False, "Exibir comando sem executar")
    i_know_scope = OptBool(False, "Confirmo que estou em laboratório autorizado")


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
        require_authorised_lab(self.i_know_scope)

        script = _find_wirespy_script()
        if not script:
            print_error(
                "wirespy.sh não encontrado. Inicialize o submodule: "
                "git submodule update --init submodules/IoT/wirespy"
            )
            return

        bash = shutil.which("bash") or "/bin/bash"
        mode = str(self.mode).strip()
        iface = str(self.interface).strip()

        cmd: List[str] = [bash, script]
        if mode:
            cmd.append(mode)
        if iface:
            cmd.extend(["--interface", iface])
        ch = int(self.channel)
        if ch > 0:
            cmd.extend(["--channel", str(ch)])
        ssid = str(self.target_ssid).strip()
        if ssid:
            cmd.extend(["--ssid", ssid])
        extra = str(self.extra_args).strip()
        if extra:
            cmd.extend(extra.split())

        cmd_str = " ".join(cmd)
        if self.dry_run:
            print_info("DRY RUN — {}".format(cmd_str))
            return

        print_status("Wirespy ({}): {}".format(mode, cmd_str))
        try:
            subprocess.run(cmd, cwd=str(_wirespy_root()), check=False)
        except KeyboardInterrupt:
            print_info("\nInterrompido.")
        except PermissionError:
            print_error("Permissão negada. Execute com sudo/root.")
        except Exception as exc:
            print_error("Erro wirespy: {}".format(exc))
