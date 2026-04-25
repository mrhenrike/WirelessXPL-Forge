#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Hashcatch — passive WPA/WPA2 handshake harvester bridge (C binary).

Hashcatch passively monitors Wi-Fi channels and saves WPA EAPOL handshakes
to files whenever a 4-way handshake is detected. Unlike active tools (hcxdumptool),
it does not transmit any frames — purely passive.

Captured files are compatible with aircrack-ng and hashcat (mode 2500/22000).

Incorporated from:
  - submodules/IoT/hashcatch (delta-rs, MIT, invoked as subprocess)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


def _hashcatch_bin() -> Optional[str]:
    """Find hashcatch binary: PATH or compiled in submodule."""
    found = shutil.which("hashcatch")
    if found:
        return found
    repo = Path(__file__).resolve().parents[5] / "hashcatch"
    candidates = [
        repo / "hashcatch",
        repo / "hashcatch" / "hashcatch",
        repo / "bin" / "hashcatch",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


class Exploit(Exploit):
    """Hashcatch passive WPA handshake harvester (C binary, subprocess)."""

    __info__ = {
        "name": "Hashcatch Passive WPA Handshake Bridge",
        "description": (
            "Purely passive WPA/WPA2 handshake capture using hashcatch (C binary). "
            "Hops channels and saves EAPOL handshakes to files without transmitting. "
            "Output compatible with aircrack-ng and hashcat (mode 2500/22000)."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "delta-rs (hashcatch MIT, invoked as subprocess)",
        ),
        "references": (
            "https://github.com/s0wr0b1ndef/hashcatch",
        ),
        "devices": ("wifi", "802.11 WPA/WPA2 EAPOL"),
    }

    interface = OptString("", "Interface Wi-Fi para monitoramento (hashcatch gere monitor)")
    output_dir = OptString("", "Diretório de saída para handshakes capturados")
    timeout = OptInteger(120, "Tempo de captura em segundos (0 = ilimitado)")
    verbose = OptBool(True, "Saída detalhada")
    dry_run = OptBool(False, "Exibir comando sem executar")
    i_know_scope = OptBool(False, "Confirmo que estou em laboratório autorizado")

    def run(self) -> None:
        require_authorised_lab(self.i_know_scope)

        bin_path = _hashcatch_bin()
        if not bin_path:
            print_error(
                "hashcatch não encontrado. Compile de https://github.com/s0wr0b1ndef/hashcatch "
                "e coloque o binário no PATH ou no submodule hashcatch/."
            )
            return

        iface = str(self.interface).strip()
        if not iface:
            print_error("Defina interface.")
            return

        cmd: List[str] = [bin_path, "-i", iface]

        out_dir = str(self.output_dir).strip()
        if not out_dir:
            out_dir = str(Path(__file__).resolve().parents[5] / ".tmp" / "hashcatch_captures")
        os.makedirs(out_dir, exist_ok=True)
        cmd.extend(["-d", out_dir])

        if self.verbose:
            cmd.append("-v")

        cmd_str = " ".join(cmd)
        if self.dry_run:
            print_info("DRY RUN — {}".format(cmd_str))
            return

        print_status("Hashcatch: captura passiva em {} (saída: {})".format(iface, out_dir))
        print_info("Comando: {}".format(cmd_str))

        timeout = int(self.timeout) if int(self.timeout) > 0 else None
        try:
            subprocess.run(cmd, timeout=timeout, check=False)
        except KeyboardInterrupt:
            print_info("\nCaptura interrompida.")
        except subprocess.TimeoutExpired:
            print_info("Timeout ({:d}s) atingido.".format(int(self.timeout)))
        except PermissionError:
            print_error("Permissão negada. Execute com sudo/root.")
        except Exception as exc:
            print_error("Erro hashcatch: {}".format(exc))

        # Report captures
        caps = list(Path(out_dir).glob("*.cap")) + list(Path(out_dir).glob("*.pcap"))
        if caps:
            print_success("{} handshake(s) capturado(s) em {}.".format(len(caps), out_dir))
            print_info("Crack: aircrack-ng -w wordlist.txt {}/*.cap".format(out_dir))
        else:
            print_info("Nenhum handshake detectado no período.")
