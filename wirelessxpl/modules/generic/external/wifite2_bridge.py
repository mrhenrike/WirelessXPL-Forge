#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess para Wifite2 (GPL-2.0) — orquestração de auditoria Wi‑Fi.

Invoca o Wifite2 como processo externo; nenhum código GPL é importado ou ligado.
O bridge monta a linha de comando para: captura/crack WPA (handshake via
aircrack-ng / hashcat quando indicado), PMKID, WPS (Pixie Dust ou brute force de
PIN), ataques WEP (fragmentação, chop-chop, replay — conforme o próprio Wifite),
filtros de alvo (BSSID, canal, ESSID, tipo de cripto), modo 5 GHz (-5), verbosidade,
encerramento de processos conflitantes (--kill) e wordlist (--dict).

License: GPL-2.0 (somente subprocesso do binário Wifite2).
Version: 1.0.0
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *

_ATTACK_MODES = frozenset({"all", "wpa", "wps", "wep", "pmkid"})


class Exploit(Exploit):
    """Bridge subprocess do Wifite2 para WirelessXPL-Forge."""

    __info__ = {
        "name": "Wifite2 Bridge",
        "description": (
            "Orquestração de auditoria Wi‑Fi via Wifite2 (GPL-2.0 subprocess): WPA "
            "(handshake + crack), PMKID, WPS Pixie / PIN brute, WEP, filtros de alvo, "
            "5 GHz, --kill, verbose e wordlist customizada."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Wifite2 contributors (GPL-2.0, invocado como subprocesso)",
        ),
        "references": (
            "https://github.com/kimocoder/wifite2",
            "https://github.com/derv82/wifite2",
        ),
        "devices": ("wifi",),
    }

    interface = OptString("", "Interface Wi‑Fi (ex.: wlan0mon; vazio = interativo)")
    target_bssid = OptMAC("", "BSSID do AP alvo")
    target_essid = OptString("", "ESSID do AP alvo")
    channel = OptString("", "Canal para escanear/ataque (vazio = padrão Wifite)")
    attack_mode = OptString(
        "all",
        "Filtro de auditoria: all | wpa | wps | wep | pmkid",
    )
    pixie_dust = OptBool(False, "WPS Pixie Dust (--pixie; com --wps-only vira Pixie-only)")
    wps_only = OptBool(False, "Somente ataques WPS (--wps-only); use com pixie_dust ou --no-pixie")
    no_wps = OptBool(False, "Nunca usar WPS PIN/Pixie (--no-wps); favorece WPA/handshake")
    five_ghz = OptBool(False, "Incluir canais 5 GHz (-5)")
    wordlist = OptString("", "Wordlist para crack offline (--dict)")
    kill_procs = OptBool(False, "Encerrar processos que conflitam com airmon/airodump (--kill)")
    verbose = OptBool(False, "Modo verbose (-v)")
    crack_only = OptBool(False, "Somente exibir/comandos de crack (--crack)")
    dry_run = OptBool(False, "Exibir comando sem executar")

    def _find_wifite(self) -> Optional[str]:
        """Localiza o entry point do Wifite2.

        Returns:
            Caminho do launcher `wifite`, `bin/wifite` ou `Wifite.py`, ou None.
        """
        which = shutil.which("wifite")
        if which:
            return which

        iot_root = Path(__file__).resolve().parents[5]
        legacy = (
            iot_root
            / "submodules"
            / "IoT"
            / "wifite2"
            / "bin"
            / "wifite"
        )
        sibling_bin = iot_root / "wifite2" / "bin" / "wifite"
        sibling_py = iot_root / "wifite2" / "Wifite.py"

        for candidate in (sibling_bin, legacy):
            if candidate.exists():
                return str(candidate)

        if sibling_py.exists():
            return str(sibling_py)

        return None

    def _build_command(self) -> List[str]:
        """Monta a linha de comando do Wifite2 a partir das opções."""
        wpath = self._find_wifite()
        if not wpath:
            raise FileNotFoundError(
                "wifite não encontrado. Instale o Wifite2 ou mantenha o submódulo "
                "submodules/IoT/wifite2."
            )

        mode = str(self.attack_mode).strip().lower()
        if mode not in _ATTACK_MODES:
            raise ValueError(
                "attack_mode inválido: {!r} (use: {})".format(
                    self.attack_mode,
                    ", ".join(sorted(_ATTACK_MODES)),
                )
            )

        if wpath.endswith(".py"):
            cmd: List[str] = ["sudo", "python3", wpath]
        else:
            cmd = ["sudo", wpath]

        if self.verbose:
            cmd.append("-v")

        if self.interface:
            cmd.extend(["-i", str(self.interface).strip()])

        if self.channel:
            cmd.extend(["-c", str(self.channel).strip()])

        if self.target_bssid:
            cmd.extend(["-b", str(self.target_bssid).strip()])

        if self.target_essid:
            cmd.extend(["-e", str(self.target_essid).strip()])

        if self.five_ghz:
            cmd.append("-5")

        if self.kill_procs:
            cmd.append("--kill")

        if mode == "wpa":
            cmd.append("--wpa")
        elif mode == "wps":
            cmd.append("--wps")
        elif mode == "wep":
            cmd.append("--wep")
        elif mode == "pmkid":
            cmd.append("--pmkid")

        if self.no_wps:
            cmd.append("--no-wps")

        if self.wps_only:
            cmd.append("--wps-only")
            if self.pixie_dust:
                cmd.append("--pixie")
            else:
                cmd.append("--no-pixie")
        elif self.pixie_dust:
            cmd.append("--pixie")

        wl = str(self.wordlist).strip()
        if wl:
            if not os.path.isfile(wl):
                raise FileNotFoundError("wordlist não é um arquivo válido: {}".format(wl))
            cmd.extend(["--dict", wl])

        if self.crack_only:
            cmd.append("--crack")

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
        """Executa o Wifite2 como subprocesso."""
        try:
            cmd = self._build_command()
        except (FileNotFoundError, ValueError) as err:
            print_error(str(err))
            return

        cmd_str = " ".join(cmd)

        if self.dry_run:
            print_info("DRY RUN — comando que seria executado:")
            print_status(cmd_str)
            return

        print_status("Iniciando Wifite2 (modo: {})...".format(self.attack_mode))
        print_info("Comando: {}".format(cmd_str))
        print_info("Wifite2 é interativo em muitos fluxos — siga os prompts no terminal.")
        print_info("Ctrl+C encerra a execução.")

        try:
            subprocess.run(cmd, check=False)
        except KeyboardInterrupt:
            print_info("\nWifite2 interrompido pelo usuário.")
        except Exception as err:
            print_error("Falha ao executar Wifite2: {}".format(err))
