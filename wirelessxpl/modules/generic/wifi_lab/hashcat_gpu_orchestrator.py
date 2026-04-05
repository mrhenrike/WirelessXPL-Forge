"""Invoke hashcat with WPA/PBKDF2 modes using GPU-friendly defaults.

Uses ``hashcat -I`` for device discovery; passes ``-d`` / ``-w`` / ``-O`` when requested.
Does not ship hashcat — host prerequisite.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger("wirelessxpl.wifi_lab.hashcat")


def _hashcat_list_devices(binary: str) -> str:
    """Capture ``hashcat -I`` stdout for operator visibility."""

    proc = subprocess.run(
        [binary, "-I"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return (proc.stdout or "") + (proc.stderr or "")


def _pick_first_gpu_device_id(listing: str) -> Optional[str]:
    """Heuristically pick first ``Backend Device ID #N`` that looks like a GPU."""

    # Example: "Backend Device ID #1" ... Type: GPU
    for m in re.finditer(r"Backend Device ID #(\d+).*?Type:\s+(\S+)", listing, re.DOTALL):
        dev_id, kind = m.group(1), m.group(2).upper()
        if "GPU" in kind or "CUDA" in kind or "HIP" in kind or "Metal" in kind:
            return dev_id
    m2 = re.search(r"Backend Device ID #(\d+)", listing)
    return m2.group(1) if m2 else None


class Exploit(Exploit):
    """Run hashcat against hc22000 lines with optional GPU device pinning."""

    __info__ = {
        "name": "Hashcat GPU/CPU orchestrator (WPA modes)",
        "description": "Builds a hashcat argv for mode 22000/2500-class WPA material; "
                       "prints devices (-I) and runs or dry-runs attack.",
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://hashcat.net/hashcat/",
            "https://hashcat.net/wiki/doku.php?id=example_hashes",
        ),
        "devices": ("Cracking workstation",),
    }

    hash_file = OptString("", "File with hashcat lines (e.g. from hcxpcapngtool)")
    wordlist = OptString("", "Wordlist path")
    hash_mode = OptInteger(22000, "Hashcat mode (22000 typical for WPA-PBKDF2 PMKID/EAPOL hc22000)")
    workload = OptInteger(3, "Workload profile -w 1..4")
    force_opencl = OptBool(False, "Pass --force (lab only; ignore warnings)")
    device_id = OptString(
        "",
        "hashcat -d: empty = auto-pick first GPU from -I; 'cpu' = skip -d (backend default)",
    )
    dry_run = OptBool(True, "Only print hashcat -I and final argv")
    extra_args = OptString(
        "",
        "Extra args split by space (e.g. --session wxf1 -r rules/best64.rule)",
        advanced=True,
    )

    def run(self) -> None:
        if not self.hash_file or not self.wordlist:
            print_error("Set hash_file and wordlist.")
            return
        hc = shutil.which("hashcat")
        if not hc:
            print_error("hashcat not on PATH.")
            return
        listing = _hashcat_list_devices(hc)
        print_status("=== hashcat -I (trimmed) ===")
        for line in listing.splitlines()[:40]:
            print_info(line)
        if len(listing.splitlines()) > 40:
            print_status("... (truncated)")

        dev = str(self.device_id).strip().lower()
        chosen: Optional[str] = None
        if dev == "cpu":
            chosen = None
        elif dev:
            chosen = dev
        else:
            chosen = _pick_first_gpu_device_id(listing)
            if chosen:
                print_success("Auto-selected device id: {}".format(chosen))
            else:
                print_status("No GPU id heuristically matched; hashcat default backends apply.")

        argv: List[str] = [hc]
        if chosen:
            argv.extend(["-d", chosen])
        argv.extend(
            [
                "-m",
                str(int(self.hash_mode)),
                "-a",
                "0",
                str(self.hash_file),
                str(self.wordlist),
                "-w",
                str(int(self.workload)),
            ]
        )
        if bool(self.force_opencl):
            argv.append("--force")
        if str(self.extra_args).strip():
            argv.extend(str(self.extra_args).split())
        print_status("Command: {}".format(" ".join(argv)))
        if bool(self.dry_run):
            print_status("dry_run=true — not executing.")
            return
        try:
            subprocess.run(argv, check=False)
        except OSError as exc:
            print_error("hashcat failed to start: {}".format(exc))
