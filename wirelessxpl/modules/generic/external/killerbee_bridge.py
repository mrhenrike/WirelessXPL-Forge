#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess para riverloopsec/killerbee — IEEE 802.15.4 / Zigbee.

Invoca as ferramentas CLI do pacote (zbstumbler, zbdump, zbreplay, zbassocflood,
etc.) sem importar o framework no runtime do WirelessXPL.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Ponte subprocess para KillerBee (802.15.4 / Zigbee)."""

    __info__ = {
        "name": "KillerBee Bridge",
        "description": (
            "Orquestra zbstumbler, zbdump, zbreplay, zbassocflood e utilitários "
            "relacionados (subprocess) para avaliação de segurança IEEE 802.15.4 / "
            "Zigbee. Requer hardware suportado pelo KillerBee e pacote instalado ou "
            "clone com scripts em tools/."
        ),
        "authors": (
            "André Henrique (@mrhenrique) | União Geek",
            "Joshua Wright, Ryan Speers / KillerBee contributors (upstream)",
        ),
        "references": (
            "https://github.com/riverloopsec/killerbee",
        ),
        "devices": ("ieee802154", "zigbee", "killerbee"),
    }

    channel = OptInteger(11, "Canal IEEE 802.15.4 (Zigbee 2.4 GHz típico: 11–26)")
    target_panid = OptString(
        "",
        "PAN ID hex: filtro zbdump (-P) ou alvo zbassocflood (-p), ex.: BAAD ou 0xBAAD",
    )
    capture_file = OptString(
        "",
        "Arquivo PCAP: saída em sniff (-w) ou entrada em replay/inject (-r)",
    )
    attack = OptString(
        "scan",
        "Modo: sniff | replay | inject | dos | scan",
    )
    interface = OptString(
        "",
        "Dispositivo KillerBee (-i), ex.: /dev/ttyUSB0",
    )
    dry_run = OptBool(False, "Exibe o comando sem executar")

    def _candidate_repo_roots(self) -> List[Path]:
        """Possíveis raízes do clone ``killerbee``."""
        here = Path(__file__).resolve()
        return [
            here.parents[7] / "submodules" / "IoT" / "killerbee",
            here.parents[6] / "submodules" / "IoT" / "killerbee",
            here.parents[5] / "submodules" / "IoT" / "killerbee",
            here.parents[4] / "killerbee",
            here.parents[5] / "killerbee",
        ]

    def _repo_root(self) -> Optional[Path]:
        """Retorna diretório do clone se existir."""
        for p in self._candidate_repo_roots():
            tools = p / "tools"
            if tools.is_dir() and (tools / "zbstumbler").is_file():
                return p.resolve()
        return None

    def _python_runner(self) -> str:
        """Intérprete para executar scripts em ``tools/``."""
        return shutil.which("python3") or sys.executable or "python3"

    def _tool_argv0(self, name: str) -> List[str]:
        """``argv`` inicial: shim no PATH ou ``python3 tools/name``."""
        w = shutil.which(name)
        if w:
            return [w]
        root = self._repo_root()
        if root:
            script = root / "tools" / name
            if script.is_file():
                return [self._python_runner(), str(script)]
        raise FileNotFoundError(
            "Ferramenta '{}' não encontrada (PATH ou killerbee/tools).".format(name),
        )

    def _channel_int(self) -> int:
        """Canal numérico com aviso fora da faixa Zigbee 2.4 GHz."""
        ch = int(self.channel)
        if ch < 11 or ch > 26:
            logger.warning("Canal %s fora do intervalo Zigbee 11–26 (2.4 GHz).", ch)
        return ch

    def _normalize_attack(self) -> str:
        """Normaliza nome do modo."""
        s = str(self.attack).strip().lower()
        if s in ("sniff", "replay", "inject", "dos", "scan"):
            return s
        raise ValueError("attack deve ser sniff | replay | inject | dos | scan")

    def _pan_for_flood(self) -> str:
        """Argumento ``-p`` do zbassocflood (hex, tipicamente 4 dígitos)."""
        raw = str(self.target_panid).strip()
        if not raw:
            raise ValueError("dos exige target_panid (ex.: BAAD).")
        if raw.lower().startswith("0x"):
            return raw[2:]
        return raw

    def _build_command(self) -> List[str]:
        """Monta argv para o utilitário selecionado.

        Returns:
            Lista de argumentos para ``subprocess``.

        Raises:
            FileNotFoundError: Ferramenta ou clone ausente.
            ValueError: Combinação inválida de opções.
        """
        mode = self._normalize_attack()
        ch = self._channel_int()
        dev = str(self.interface).strip()
        cap = str(self.capture_file).strip()

        if mode == "scan":
            cmd = self._tool_argv0("zbstumbler")
            if dev:
                cmd.extend(["-i", dev])
            cmd.extend(["-c", str(ch)])
            if cap:
                cmd.extend(["-w", cap])
            return cmd

        if mode == "sniff":
            if not cap:
                raise ValueError("sniff exige capture_file (arquivo PCAP de saída).")
            cmd = self._tool_argv0("zbdump")
            if dev:
                cmd.extend(["-i", dev])
            cmd.extend(["-c", str(ch), "-w", cap])
            pan = str(self.target_panid).strip()
            if pan:
                phex = pan if pan.lower().startswith("0x") else "0x" + pan
                cmd.extend(["-P", phex])
            return cmd

        if mode in ("replay", "inject"):
            if not cap:
                raise ValueError("replay/inject exige capture_file (PCAP gravado).")
            cmd = self._tool_argv0("zbreplay")
            if dev:
                cmd.extend(["-i", dev])
            cmd.extend(["-c", str(ch), "-r", cap])
            return cmd

        if mode == "dos":
            cmd = self._tool_argv0("zbassocflood")
            if dev:
                cmd.extend(["-i", dev])
            cmd.extend(["-c", str(ch), "-p", self._pan_for_flood()])
            return cmd

        raise ValueError("Modo não tratado.")

    def run(self) -> None:
        """Executa a ferramenta KillerBee selecionada."""
        try:
            cmd = self._build_command()
        except (FileNotFoundError, ValueError) as err:
            logger.error("%s", err)
            return

        cmd_str = " ".join(cmd)
        if self.dry_run:
            logger.info("DRY RUN — comando KillerBee:")
            logger.info("%s", cmd_str)
            return

        logger.info("KillerBee (%s): %s", str(self.attack).strip(), cmd_str)
        logger.warning("Use apenas em redes e dispositivos autorizados.")

        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")

        try:
            subprocess.run(cmd, cwd=os.getcwd(), env=env, check=False)
        except KeyboardInterrupt:
            logger.info("Interrompido pelo usuário.")
        except Exception as exc:
            logger.error("Falha ao executar KillerBee: %s", exc)
            logger.exception("killerbee_bridge")
