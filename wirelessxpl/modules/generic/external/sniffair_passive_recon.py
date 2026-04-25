#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""SniffAir — passive Wi-Fi recon and Auto-EAP credential capture.

SniffAir is a Python framework for passive Wi-Fi reconnaissance and EAP credential
capture. Unlike active scanners, it only listens. Capabilities:
  - Sniffer: capture probe requests, beacons, EAP frames
  - Auto_EAP: automated PEAP/MSCHAPv2 credential harvest via rogue RADIUS
  - Auto_PSK: capture WPA handshakes passively and crack with hashcat
  - Handshaker: trigger 4-way handshake via deauth
  - Captive_Portal: HTTP credential phishing

This module bridges SniffAir in two ways:
  1. **Subprocess**: runs SniffAir CLI directly.
  2. **Native import**: imports SniffAir's Sniffer and parses frames inline.

Incorporated from:
  - submodules/IoT/SniffAir (Beau Bullock / Black Hills Information Security)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


def _sniffair_root() -> Path:
    return Path(__file__).resolve().parents[5] / "SniffAir"


def _add_sniffair_path() -> bool:
    """Add SniffAir to sys.path for native import."""
    root = _sniffair_root()
    if not root.exists():
        return False
    path_str = str(root)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
    return True


class Exploit(Exploit):
    """SniffAir passive Wi-Fi recon and EAP capture (subprocess + optional native)."""

    __info__ = {
        "name": "SniffAir Passive Wi-Fi Recon Bridge",
        "description": (
            "Passive Wi-Fi reconnaissance using SniffAir: captures probe requests, "
            "beacons, and EAP authentication frames. Modules: Auto_EAP (rogue RADIUS "
            "for PEAP/MSCHAPv2 capture), Auto_PSK (WPA handshake), Handshaker (deauth), "
            "Captive_Portal (HTTP phishing). Subprocess or native Scapy mode."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Beau Bullock / Black Hills Information Security "
            "(SniffAir — invoked as subprocess/native)",
        ),
        "references": (
            "https://github.com/Tylous/SniffAir",
        ),
        "devices": ("wifi", "802.11 passive recon EAP WPA"),
    }

    mode = OptString(
        "sniff",
        "Modo: sniff (passive sniffer) | auto_eap | auto_psk | handshaker | info",
    )
    interface = OptString("", "Interface em modo monitor (ex.: wlan0mon)")
    target_ssid = OptString("", "SSID alvo (opcional; vazio = todas as redes)")
    channel = OptInteger(0, "Canal fixo (0 = todos os canais)")
    output_dir = OptString("", "Diretório de saída para capturas e logs")
    timeout = OptInteger(60, "Timeout em segundos (0 = ilimitado)")
    use_native = OptBool(
        False,
        "Usar importação nativa SniffAir em vez de subprocess (requer submodule inicializado)",
    )
    dry_run = OptBool(False, "Exibir comando sem executar")
    i_know_scope = OptBool(False, "Confirmo que estou em laboratório autorizado")

    _VALID_MODES = frozenset({"sniff", "auto_eap", "auto_psk", "handshaker", "info"})

    def _info_mode(self) -> None:
        root = _sniffair_root()
        print_status("SniffAir — passive Wi-Fi recon framework")
        print_info("Submodule path: {}".format(root))
        print_info("Disponível: {}".format("SIM" if root.exists() else "NÃO (inicialize o submodule)"))
        print_info("\nModos:")
        print_info("  sniff        — Captura passiva de frames (beacons, probe req, EAP)")
        print_info("  auto_eap     — PEAP/MSCHAPv2 via rogue RADIUS (Auto_EAP)")
        print_info("  auto_psk     — Captura handshake WPA (Auto_PSK)")
        print_info("  handshaker   — Trigger deauth para forçar handshake")
        print_info("\nPré-requisitos: interface em monitor, hostapd, python-scapy")

    def _run_subprocess(self, script: Path, extra_args: List[str]) -> None:
        """Run a SniffAir Python script as subprocess."""
        python_bin = shutil.which("python3") or "python3"
        cmd: List[str] = [python_bin, str(script)] + extra_args
        cmd_str = " ".join(cmd)

        if self.dry_run:
            print_info("DRY RUN — {}".format(cmd_str))
            return

        print_info("Executando: {}".format(cmd_str))
        timeout = int(self.timeout) if int(self.timeout) > 0 else None
        try:
            subprocess.run(cmd, cwd=str(_sniffair_root()), timeout=timeout, check=False)
        except KeyboardInterrupt:
            print_info("\nInterrompido.")
        except subprocess.TimeoutExpired:
            print_info("Timeout ({:d}s) atingido.".format(int(self.timeout)))
        except Exception as exc:
            print_error("Erro ao executar {}: {}".format(script.name, exc))

    def _run_native_sniff(self) -> None:
        """Native sniff using SniffAir's Sniffer lib imported directly."""
        if not _add_sniffair_path():
            print_error("SniffAir submodule não encontrado. Execute: git submodule update --init")
            return
        iface = str(self.interface).strip()
        if not iface:
            print_error("Defina interface.")
            return
        try:
            from lib.Sniffer import Sniffer  # type: ignore
            print_status("SniffAir Sniffer (nativo): interface={}, canal={}".format(
                iface, int(self.channel) or "todos"
            ))
            sniffer = Sniffer(iface)
            sniffer.run()
        except ImportError as exc:
            print_error("Importação SniffAir falhou: {}. Usando subprocess.".format(exc))
            self._run_subprocess_sniff()
        except KeyboardInterrupt:
            print_info("\nSniffer encerrado.")
        except Exception as exc:
            print_error("Erro no sniffer nativo: {}".format(exc))

    def _run_subprocess_sniff(self) -> None:
        root = _sniffair_root()
        candidates = [
            root / "SniffAir.py",
            root / "sniffair.py",
        ]
        script = next((c for c in candidates if c.exists()), None)
        if not script:
            print_error("SniffAir.py não encontrado em {}.".format(root))
            return
        iface = str(self.interface).strip()
        args: List[str] = []
        if iface:
            args.extend(["-i", iface])
        self._run_subprocess(script, args)

    def run(self) -> None:
        """Execute SniffAir in the selected mode."""
        require_authorised_lab(self.i_know_scope)

        mode = str(self.mode).strip().lower()
        if mode not in self._VALID_MODES:
            print_error("mode deve ser: {}".format(", ".join(sorted(self._VALID_MODES))))
            return

        if mode == "info":
            self._info_mode()
            return

        root = _sniffair_root()
        if mode == "sniff":
            if self.use_native:
                self._run_native_sniff()
            else:
                self._run_subprocess_sniff()
            return

        module_map = {
            "auto_eap": root / "module" / "Auto_EAP" / "Auto_EAP.py",
            "auto_psk": root / "module" / "Auto_EAP" / "Auto_PSK.py",
            "handshaker": root / "module" / "Handshaker" / "Handshaker.py",
        }

        script = module_map.get(mode)
        if not script or not script.exists():
            print_error("Script para modo '{}' não encontrado: {}".format(mode, script))
            print_info("Verifique se o submodule SniffAir está inicializado.")
            return

        iface = str(self.interface).strip()
        ssid = str(self.target_ssid).strip()
        args: List[str] = []
        if iface:
            args.extend(["-i", iface])
        if ssid:
            args.extend(["-s", ssid])

        print_status("SniffAir {}: iface={}, ssid={}".format(
            mode.upper(), iface or "não definida", ssid or "todos"
        ))
        self._run_subprocess(script, args)
