#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess para crackle (BSD) — quebra de pairing BLE e descriptografia AES-CCM.

Invoca ``crackle`` como processo externo. Modo *crack*: deriva TK/STK/LTK a partir de
PCAP com handshake (Just Works / PIN de 6 dígitos conforme o tráfego). Modo *decrypt*:
usa LTK conhecida (-l) para gerar PCAP com tráfego descriptografado. Entrada/saída
via -i / -o.

Referência: https://github.com/mikeryan/crackle
"""

from __future__ import annotations

import logging, os, shutil, subprocess
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Ponte subprocess para crackle (crack TK / decrypt com LTK, PCAP in/out)."""

    __info__ = {
        "name": "crackle Bridge",
        "description": (
            "Quebra de criptografia de pairing BLE (TK/STK/LTK) e descriptografia "
            "AES-CCM de tráfego em PCAP via crackle (BSD, subprocess). Não inclui "
            "binários; requer crackle no PATH."
        ),
        "authors": [
            "André Henrique (@mrhenrike) | União Geek",
            "Mike Ryan / crackle contributors (BSD, subprocess)",
        ],
        "references": [
            "https://github.com/mikeryan/crackle",
        ],
        "devices": ("ble-pcap",),
    }

    mode = OptString("crack", "Modo: crack | decrypt")
    input_pcap = OptString("", "PCAP/PCAPNG de entrada (-i)")
    output_pcap = OptString("", "PCAP de saída (-o); recomendado em crack para tráfego decifrado")
    ltk = OptString("", "LTK hex 128 bits (32 hex chars) para mode=decrypt (-l)")
    verbose = OptBool(False, "Log extra no bridge (saída do crackle sempre no terminal)")
    dry_run = OptBool(False, "Exibe o comando sem executar")

    def _find_crackle(self) -> Optional[str]:
        """Localiza o executável ``crackle`` no PATH."""
        return shutil.which("crackle")

    def _normalize_ltk(self, raw: str) -> str:
        """Remove espaços do LTK hex fornecido pelo usuário."""
        return "".join(raw.split())

    def _build_command(self) -> List[str]:
        """Monta a linha de comando do crackle.

        Returns:
            Lista de argumentos começando pelo binário.

        Raises:
            ValueError: Parâmetros ausentes ou modo inválido.
        """
        exe = self._find_crackle()
        if not exe:
            raise FileNotFoundError("crackle não encontrado no PATH.")

        inp = str(self.input_pcap).strip()
        if not inp or not os.path.isfile(inp):
            raise ValueError("Defina input_pcap com um ficheiro existente.")

        mode = str(self.mode).strip().lower()
        cmd: List[str] = [exe, "-i", inp]

        if mode == "crack":
            out = str(self.output_pcap).strip()
            if out:
                cmd.extend(["-o", out])
            return cmd

        if mode == "decrypt":
            out = str(self.output_pcap).strip()
            if not out:
                raise ValueError("decrypt exige output_pcap (-o).")
            ltk_hex = self._normalize_ltk(str(self.ltk))
            if len(ltk_hex) != 32 or any(c not in "0123456789abcdefABCDEF" for c in ltk_hex):
                raise ValueError("decrypt exige ltk com 32 caracteres hexadecimais (128 bits).")
            cmd.extend(["-o", out, "-l", ltk_hex.lower()])
            return cmd

        raise ValueError("mode deve ser crack ou decrypt.")

    def run(self) -> None:
        """Executa crackle ou dry-run; imprime stdout/stderr do processo."""
        try:
            cmd = self._build_command()
        except FileNotFoundError as err:
            print_error(str(err))
            return
        except ValueError as err:
            print_error(str(err))
            return

        cmd_str = " ".join(cmd)
        if self.verbose:
            logger.debug("crackle cmd: %s", cmd_str)

        if self.dry_run:
            print_info("DRY RUN — comando:")
            print_status(cmd_str)
            return

        print_status("Executando crackle...")
        print_info(cmd_str)

        try:
            proc = subprocess.run(
                cmd,
                cwd=os.getcwd(),
                capture_output=True,
                text=True,
                timeout=3600,
                check=False,
            )
        except Exception as exc:
            print_error(str(exc))
            logger.exception("crackle subprocess")
            return

        if proc.stdout:
            print_info(proc.stdout.rstrip())
        if proc.stderr:
            print_status(proc.stderr.rstrip())

        if proc.returncode == 0:
            print_success("crackle finalizou com código 0.")
        else:
            print_error("crackle saiu com código {}".format(proc.returncode))

        out = str(self.output_pcap).strip()
        if out and Path(out).is_file():
            print_info("Saída PCAP: {}".format(Path(out).resolve()))
