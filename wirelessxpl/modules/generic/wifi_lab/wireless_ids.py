#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Lightweight wireless IDS baseline/anomaly module.

Provides passive baseline collection and simple anomaly alerts over scan CSVs.
Designed for lab monitoring and rapid triage.

Version: 1.0.0
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Dict, Set

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    __info__ = {
        "name": "Wireless IDS (Baseline/Anomaly)",
        "description": (
            "Passive IDS helper that learns AP baseline from CSV scans and "
            "flags rogue/new BSSIDs for analyst review."
        ),
        "authors": ("André Henrique (@mrhenrike) | União Geek",),
        "references": ("https://github.com/SYWorks/waidps",),
        "devices": ("wifi",),
    }

    baseline_csv = OptString("", "Reference airodump CSV path")
    current_csv = OptString("", "Current airodump CSV path")
    min_signal = OptInteger(-90, "Minimum signal threshold (dBm) to report")
    dry_run = OptBool(False, "Validate inputs only")

    @staticmethod
    def _load_bssids(csv_path: Path) -> Dict[str, int]:
        data: Dict[str, int] = {}
        with csv_path.open("r", encoding="utf-8", errors="ignore") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if len(row) < 14:
                    continue
                bssid = row[0].strip()
                pwr = row[8].strip()
                if ":" not in bssid:
                    continue
                try:
                    pwr_i = int(pwr)
                except Exception:
                    pwr_i = -100
                data[bssid] = pwr_i
        return data

    def run(self) -> None:
        base = Path(str(self.baseline_csv))
        curr = Path(str(self.current_csv))
        if not base.exists() or not curr.exists():
            print_error("baseline_csv and current_csv must exist.")
            return

        if self.dry_run:
            print_status("Dry-run OK: baseline and current CSV files found.")
            return

        base_bssids = self._load_bssids(base)
        curr_bssids = self._load_bssids(curr)

        base_set: Set[str] = set(base_bssids.keys())
        curr_set: Set[str] = set(curr_bssids.keys())
        new_bssids = sorted(curr_set - base_set)

        print_status("Wireless IDS baseline check:")
        print_info("  Baseline APs: {}".format(len(base_set)))
        print_info("  Current APs:  {}".format(len(curr_set)))
        print_info("  New APs:      {}".format(len(new_bssids)))

        threshold = int(self.min_signal)
        for bssid in new_bssids:
            pwr = curr_bssids.get(bssid, -100)
            if pwr >= threshold:
                print_success("  [ALERT] New BSSID {} (PWR {})".format(bssid, pwr))
