#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Bridge subprocess para Pyrit (GPU-accelerated WPA/WPA2 cracking).

Invoca ``pyrit`` como processo externo para computacao PBKDF2-SHA1 acelerada
por GPU (CUDA/OpenCL). Nenhum codigo nativo do Pyrit e importado; todas as
operacoes sao realizadas via subprocess.

Modos expostos:
  - **info** - capacidades e guia de uso do Pyrit.
  - **benchmark** - medir desempenho da GPU.
  - **list_cores** - listar dispositivos de computacao disponiveis.
  - **analyze** - verificar handshakes em captura.
  - **attack_passthrough** - ataque com wordlist sem pre-computacao.
  - **attack_batch** - ataque com banco de PMKs pre-computadas.
  - **attack_db** - ataque a ESSID especifico com banco local.
  - **import_passwords** - importar wordlist para banco interno.
  - **create_essid** - registrar ESSID no banco interno.
  - **batch_build** - pre-computar PMKs no banco.
  - **strip_capture** - reduzir captura a handshakes relevantes.
  - **export_hashdb** - exportar banco de hashes.

Licenca (apenas subprocess): Pyrit GPL-3.0.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)

_VALID_MODES = frozenset({
    "info",
    "benchmark",
    "list_cores",
    "analyze",
    "attack_passthrough",
    "attack_batch",
    "attack_db",
    "import_passwords",
    "create_essid",
    "batch_build",
    "strip_capture",
    "export_hashdb",
})

_PYRIT_INFO_TEXT = """
Pyrit GPU Bridge - WirelessXPL-Forge
=====================================
Pyrit usa CUDA/OpenCL para computacao massivamente paralela de PBKDF2-SHA1,
acelerando cracking de WPA/WPA2 em ordens de magnitude sobre CPU.

Modos disponiveis:
  benchmark          Medir taxa de PMKs/s na GPU
  list_cores         Listar dispositivos (GPU, CPU) disponiveis
  analyze            Verificar handshakes validos em captura .pcap/.cap
  attack_passthrough Ataque direto: wordlist + captura (sem pre-computacao)
  attack_batch       Ataque com banco de PMKs pre-computadas
  attack_db          Ataque a ESSID especifico usando banco local
  import_passwords   Importar wordlist para banco interno do Pyrit
  create_essid       Registrar ESSID alvo no banco interno
  batch_build        Pre-computar PMKs para ESSIDs registrados
  strip_capture      Reduzir captura a pacotes de handshake relevantes
  export_hashdb      Exportar banco de hashes para arquivo

Fluxo tipico de pre-computacao:
  1. create_essid   (registrar rede alvo)
  2. import_passwords (carregar wordlist)
  3. batch_build    (pre-computar PMKs, GPU-intensivo)
  4. attack_batch   (cracking rapido contra captura)

Prerequisitos: pyrit instalado e acessivel no PATH.
Documentacao: https://github.com/JPaulMora/Pyrit
""".strip()


def _resolve_pyrit(custom_path: str) -> Optional[str]:
    """Resolve o caminho do binario pyrit.

    Args:
        custom_path: Caminho customizado fornecido pelo operador.

    Returns:
        Caminho absoluto do binario ou None se nao encontrado.
    """
    if custom_path:
        expanded = os.path.expanduser(custom_path)
        if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
            return expanded
        return None
    return shutil.which("pyrit")


class Exploit(Exploit):
    """Subprocess bridge para Pyrit GPU-accelerated WPA/WPA2 cracking."""

    __info__ = {
        "name": "Pyrit GPU Bridge (WPA/WPA2)",
        "description": (
            "Bridge para computacao PBKDF2-SHA1 acelerada por GPU via Pyrit. "
            "Suporta benchmark, analise de capturas, ataques passthrough/batch/db, "
            "importacao de wordlists e pre-computacao de PMKs. Somente subprocess."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            "Pyrit contributors (GPL-3.0, invoked as subprocess)",
        ),
        "references": (
            "https://github.com/JPaulMora/Pyrit",
            "https://pyrit.wordpress.com/",
        ),
        "devices": ("wifi", "802.11 WPA/WPA2"),
    }

    mode = OptString(
        "info",
        "Modo de operacao: info, benchmark, list_cores, analyze, "
        "attack_passthrough, attack_batch, attack_db, import_passwords, "
        "create_essid, batch_build, strip_capture, export_hashdb",
    )
    capture_file = OptString("", "Caminho do arquivo de captura (.cap/.pcap)")
    wordlist = OptString("", "Caminho da wordlist para import/attack")
    essid = OptString("", "ESSID da rede alvo")
    output_file = OptString("", "Caminho do arquivo de saida (strip/export)")
    pyrit_path = OptString("", "Caminho customizado para o binario pyrit")
    dry_run = OptBool(True, "Exibir comando sem executar")

    def _require_capture(self) -> Optional[str]:
        """Valida e retorna o caminho do arquivo de captura."""
        path = str(self.capture_file).strip()
        if not path:
            print_error("Defina capture_file para este modo.")
            return None
        if not os.path.isfile(path):
            print_error("Arquivo de captura nao encontrado: {}".format(path))
            return None
        return path

    def _require_wordlist(self) -> Optional[str]:
        """Valida e retorna o caminho da wordlist."""
        path = str(self.wordlist).strip()
        if not path:
            print_error("Defina wordlist para este modo.")
            return None
        if not os.path.isfile(path):
            print_error("Wordlist nao encontrada: {}".format(path))
            return None
        return path

    def _require_essid(self) -> Optional[str]:
        """Valida e retorna o ESSID."""
        value = str(self.essid).strip()
        if not value:
            print_error("Defina essid para este modo.")
            return None
        return value

    def _require_output(self) -> Optional[str]:
        """Valida e retorna o caminho de saida."""
        path = str(self.output_file).strip()
        if not path:
            print_error("Defina output_file para este modo.")
            return None
        return path

    def _build_benchmark(self, pyrit: str) -> Optional[List[str]]:
        """Monta comando: pyrit benchmark."""
        return [pyrit, "benchmark"]

    def _build_list_cores(self, pyrit: str) -> Optional[List[str]]:
        """Monta comando: pyrit list_cores."""
        return [pyrit, "list_cores"]

    def _build_analyze(self, pyrit: str) -> Optional[List[str]]:
        """Monta comando: pyrit -r <capture> analyze."""
        cap = self._require_capture()
        if not cap:
            return None
        return [pyrit, "-r", cap, "analyze"]

    def _build_attack_passthrough(self, pyrit: str) -> Optional[List[str]]:
        """Monta comando: pyrit -r <capture> -i <wordlist> attack_passthrough."""
        cap = self._require_capture()
        if not cap:
            return None
        wl = self._require_wordlist()
        if not wl:
            return None
        return [pyrit, "-r", cap, "-i", wl, "attack_passthrough"]

    def _build_attack_batch(self, pyrit: str) -> Optional[List[str]]:
        """Monta comando: pyrit -r <capture> attack_batch."""
        cap = self._require_capture()
        if not cap:
            return None
        return [pyrit, "-r", cap, "attack_batch"]

    def _build_attack_db(self, pyrit: str) -> Optional[List[str]]:
        """Monta comando: pyrit -r <capture> -e <essid> attack_db."""
        cap = self._require_capture()
        if not cap:
            return None
        essid = self._require_essid()
        if not essid:
            return None
        return [pyrit, "-r", cap, "-e", essid, "attack_db"]

    def _build_import_passwords(self, pyrit: str) -> Optional[List[str]]:
        """Monta comando: pyrit -i <wordlist> import_passwords."""
        wl = self._require_wordlist()
        if not wl:
            return None
        return [pyrit, "-i", wl, "import_passwords"]

    def _build_create_essid(self, pyrit: str) -> Optional[List[str]]:
        """Monta comando: pyrit -e <essid> create_essid."""
        essid = self._require_essid()
        if not essid:
            return None
        return [pyrit, "-e", essid, "create_essid"]

    def _build_batch_build(self, pyrit: str) -> Optional[List[str]]:
        """Monta comando: pyrit batch."""
        return [pyrit, "batch"]

    def _build_strip_capture(self, pyrit: str) -> Optional[List[str]]:
        """Monta comando: pyrit -r <input> -o <output> strip."""
        cap = self._require_capture()
        if not cap:
            return None
        out = self._require_output()
        if not out:
            return None
        return [pyrit, "-r", cap, "-o", out, "strip"]

    def _build_export_hashdb(self, pyrit: str) -> Optional[List[str]]:
        """Monta comando: pyrit -o <output> export_hashdb."""
        out = self._require_output()
        if not out:
            return None
        return [pyrit, "-o", out, "export_hashdb"]

    def _execute(self, cmd: List[str], mode_label: str) -> None:
        """Executa o comando subprocess ou exibe em dry_run.

        Args:
            cmd: Lista de argumentos do comando.
            mode_label: Nome do modo para mensagens.
        """
        cmd_str = " ".join(cmd)

        if bool(self.dry_run):
            print_info("DRY RUN - comando:")
            print_status(cmd_str)
            return

        print_status("Executando: {}".format(mode_label))
        print_info(cmd_str)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,
                cwd=os.getcwd(),
                check=False,
            )
            if proc.stdout:
                for line in proc.stdout.strip().splitlines():
                    print_info(line)
            if proc.stderr:
                for line in proc.stderr.strip().splitlines():
                    print_status(line)
            if proc.returncode == 0:
                print_success("pyrit {} concluiu (codigo 0).".format(mode_label))
            else:
                print_error("pyrit {} saiu com codigo {}".format(
                    mode_label, proc.returncode,
                ))
        except subprocess.TimeoutExpired:
            print_error("pyrit {} excedeu o tempo maximo (3600s).".format(mode_label))
        except KeyboardInterrupt:
            print_info("Interrompido pelo usuario.")
        except OSError as exc:
            print_error("Falha ao executar pyrit: {}".format(exc))


    def check(self) -> str:
        """Verify wireless interface is in monitor mode and ready."""
        import shutil
        import subprocess
        iface = getattr(self, "iface", None) or getattr(self, "interface", None) or "wlan0"
        if shutil.which("iwconfig"):
            try:
                out = subprocess.check_output(
                    ["iwconfig", str(iface)], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if "Monitor" in out:
                    return f"Interface {iface} is in Monitor mode - prerequisites OK"
                if "no wireless extensions" not in out.lower():
                    return f"Interface {iface} found but NOT in Monitor mode - run airmon-ng start {iface}"
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if shutil.which("iw"):
            try:
                out = subprocess.check_output(
                    ["iw", "dev"], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if str(iface) in out:
                    return f"Interface {iface} detected via iw - verify monitor mode"
            except Exception:
                pass
        return f"Interface {iface} not found - connect wireless adapter and enable monitor mode"

    def run(self) -> None:
        """Ponto de entrada principal; despacha para o modo selecionado."""
        mode = str(self.mode).strip().lower()

        if mode not in _VALID_MODES:
            print_error(
                "Modo invalido: '{}'. Valores aceitos: {}".format(
                    mode, ", ".join(sorted(_VALID_MODES)),
                )
            )
            return

        if mode == "info":
            for line in _PYRIT_INFO_TEXT.splitlines():
                print_info(line)
            return

        pyrit = _resolve_pyrit(str(self.pyrit_path).strip())
        if not pyrit:
            print_error(
                "pyrit nao encontrado no PATH. "
                "Instale via pip (pyrit) ou defina pyrit_path."
            )
            return

        print_status("Binario pyrit: {}".format(pyrit))

        builder_map = {
            "benchmark": self._build_benchmark,
            "list_cores": self._build_list_cores,
            "analyze": self._build_analyze,
            "attack_passthrough": self._build_attack_passthrough,
            "attack_batch": self._build_attack_batch,
            "attack_db": self._build_attack_db,
            "import_passwords": self._build_import_passwords,
            "create_essid": self._build_create_essid,
            "batch_build": self._build_batch_build,
            "strip_capture": self._build_strip_capture,
            "export_hashdb": self._build_export_hashdb,
        }

        builder = builder_map.get(mode)
        if not builder:
            print_error("Builder nao implementado para modo: {}".format(mode))
            return

        cmd = builder(pyrit)
        if cmd is None:
            return

        self._execute(cmd, mode)
