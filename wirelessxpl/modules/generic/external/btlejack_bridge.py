#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess para Btlejack (MIT) — sniff/jam/hijack BLE via hardware compatível.

Invoca ``btlejack`` como processo externo; nenhum código MIT é importado no runtime
do WirelessXPL. Suporta enumeração de access addresses (-s), captura de conexões
novas (-c) ou existentes (-f), jam (-j), hijack (-t), exportação PCAP (-o/-x),
múltiplos sniffers (-d repetido) e modo verboso (-v).

Referência: https://github.com/virtualabs/btlejack
"""

from __future__ import annotations

import logging, os, shutil, subprocess
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


def _is_bd_addr(value: str) -> bool:
    """True se ``value`` parece um endereço Bluetooth AA:BB:CC:DD:EE:FF."""
    parts = value.strip().split(":")
    if len(parts) != 6:
        return False
    for octet in parts:
        if len(octet) != 2:
            return False
        try:
            int(octet, 16)
        except ValueError:
            return False
    return True


class Exploit(Exploit):
    """Ponte subprocess para Btlejack (sniff, scan de AA, jam, hijack, PCAP)."""

    __info__ = {
        "name": "Btlejack Bridge",
        "description": (
            "Sniff BLE (conexões novas ou existentes), descoberta de access address, "
            "jam, hijack e export PCAP via Btlejack (MIT, subprocess). Requer "
            "btlejack no PATH e hardware suportado (ex.: Micro:Bit com firmware)."
        ),
        "authors": [
            "André Henrique (@mrhenrike) | União Geek",
            "virtualabs / Btlejack contributors (MIT, subprocess)",
        ],
        "references": [
            "https://github.com/virtualabs/btlejack",
        ],
        "devices": ("ble", "bbc-microbit", "nrf51822-sniffer"),
    }

    mode = OptString(
        "sniff",
        "Modo: sniff | jam | hijack | scan",
    )
    access_address = OptString(
        "",
        "Access address 32-bit (hex, ex. 0xdda4845e) para -f; ou BD_ADDR para -c em sniff sem follow",
    )
    channel = OptString(
        "",
        "Channel map hexadecimal para -m (ex. 0x1fffffffff), opcional em follow/hijack",
    )
    follow = OptBool(
        True,
        "Sniff: True = conexão existente (-f + access_address); False = nova conexão (-c any ou BD_ADDR)",
    )
    output_pcap = OptString("", "Arquivo de saída PCAP (-o); vazio = sem gravação PCAP")
    device_index = OptString(
        "",
        "Multi-sniffer: caminhos serial separados por vírgula (ex. /dev/ttyACM0,/dev/ttyACM1) → -d cada",
    )
    verbose = OptBool(False, "Repasse -v ao btlejack")
    dry_run = OptBool(False, "Exibe o comando sem executar")

    def _find_btlejack(self) -> Optional[str]:
        """Localiza o executável ``btlejack`` no PATH."""
        return shutil.which("btlejack")

    def _normalize_follow_aa(self, raw: str) -> str:
        """Normaliza access address para o argumento de ``-f`` (aceita com ou sem 0x)."""
        s = raw.strip()
        if not s:
            return s
        if s.lower().startswith("0x"):
            return s
        return "0x" + s

    def _build_command(self) -> List[str]:
        """Monta a linha de comando do btlejack a partir das opções atuais.

        Returns:
            Lista de argumentos, começando pelo binário.

        Raises:
            ValueError: Combinação inválida de modo e parâmetros.
        """
        exe = self._find_btlejack()
        if not exe:
            raise FileNotFoundError("btlejack não encontrado no PATH.")

        mode = str(self.mode).strip().lower()
        cmd: List[str] = [exe]

        for dev in [p.strip() for p in str(self.device_index).split(",") if p.strip()]:
            cmd.extend(["-d", dev])

        if self.verbose:
            cmd.append("-v")

        outp = str(self.output_pcap).strip()
        if outp:
            cmd.extend(["-o", outp])

        chm = str(self.channel).strip()
        if chm and not chm.lower().startswith("0x"):
            chm = "0x" + chm

        if mode == "scan":
            cmd.append("-s")
            return cmd

        if mode == "sniff":
            if self.follow:
                aa = str(self.access_address).strip()
                if not aa:
                    raise ValueError("sniff + follow exige access_address (hex 32-bit).")
                cmd.extend(["-f", self._normalize_follow_aa(aa)])
                if chm:
                    cmd.extend(["-m", chm])
                return cmd

            target = str(self.access_address).strip()
            if target and _is_bd_addr(target):
                cmd.extend(["-c", target])
            else:
                cmd.extend(["-c", "any"])
            return cmd

        if mode == "jam":
            aa = str(self.access_address).strip()
            if not aa:
                raise ValueError("jam exige access_address.")
            cmd.extend(["-f", self._normalize_follow_aa(aa), "-j"])
            if chm:
                cmd.extend(["-m", chm])
            return cmd

        if mode == "hijack":
            aa = str(self.access_address).strip()
            if not aa:
                raise ValueError("hijack exige access_address.")
            cmd.extend(["-f", self._normalize_follow_aa(aa), "-t"])
            if chm:
                cmd.extend(["-m", chm])
            return cmd

        raise ValueError("mode deve ser sniff, jam, hijack ou scan.")

    def run(self) -> None:
        """Executa btlejack ou imprime dry-run / erros de validação."""
        try:
            cmd = self._build_command()
        except FileNotFoundError as err:
            print_error(str(err))
            return
        except ValueError as err:
            print_error(str(err))
            return

        cmd_str = " ".join(cmd)
        if self.dry_run:
            print_info("DRY RUN — comando:")
            print_status(cmd_str)
            return

        print_status("Executando btlejack...")
        print_info(cmd_str)

        try:
            proc = subprocess.run(cmd, cwd=os.getcwd(), timeout=None, check=False)
        except KeyboardInterrupt:
            print_info("Interrompido pelo usuário.")
            return
        except Exception as exc:
            print_error(str(exc))
            logger.exception("btlejack subprocess")
            return

        if proc.returncode == 0:
            print_success("btlejack finalizou com código 0.")
        else:
            print_error("btlejack saiu com código {}".format(proc.returncode))
        if str(self.output_pcap).strip():
            p = Path(self.output_pcap)
            if p.is_file():
                print_info("PCAP: {}".format(p.resolve()))
