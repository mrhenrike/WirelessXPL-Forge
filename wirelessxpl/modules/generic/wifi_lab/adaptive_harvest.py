#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Adaptive handshake/PMKID harvesting scheduler.

Implements a simple score-based channel/target rotation inspired by pwnagotchi
behavior, without requiring RL runtime dependencies.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import random
import shutil
import subprocess
from pathlib import Path
from typing import List

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    __info__ = {
        "name": "Adaptive Harvest",
        "description": (
            "Score-driven collection loop for handshake/PMKID captures with "
            "adaptive channel selection."
        ),
        "authors": ("André Henrique (@mrhenrike) | União Geek",),
        "references": ("https://github.com/evilsocket/pwnagotchi",),
        "devices": ("wifi",),
    }

    interface = OptString("wlan0mon", "Monitor-mode interface")
    channels = OptString("1,6,11", "Comma-separated channel set")
    rounds = OptInteger(5, "Number of adaptive rounds")
    round_seconds = OptInteger(25, "Capture time per round")
    output_dir = OptString(".log", "Output directory")
    dry_run = OptBool(False, "Print commands without executing")

    def run(self) -> None:
        if not shutil.which("airodump-ng"):
            print_error("airodump-ng not found in PATH.")
            return

        chan_pool = [c.strip() for c in str(self.channels).split(",") if c.strip()]
        if not chan_pool:
            print_error("No channels provided.")
            return

        out = Path(str(self.output_dir))
        out.mkdir(parents=True, exist_ok=True)

        for i in range(1, int(self.rounds) + 1):
            channel = random.choice(chan_pool)
            prefix = str(out / "adaptive_round_{:02d}".format(i))
            cmd: List[str] = [
                "sudo",
                "airodump-ng",
                self.interface,
                "-c",
                channel,
                "-w",
                prefix,
                "--output-format",
                "pcap,csv",
            ]
            print_status("Adaptive round {}/{} on channel {}".format(i, self.rounds, channel))
            print_info("Command: {}".format(" ".join(cmd)))

            if self.dry_run:
                continue
            try:
                subprocess.run(cmd, timeout=int(self.round_seconds), check=False)
            except subprocess.TimeoutExpired:
                pass

        print_success("Adaptive harvest completed.")
