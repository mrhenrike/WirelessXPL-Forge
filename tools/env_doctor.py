#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Environment diagnostics for WirelessXPL-Forge runtime dependencies."""

from __future__ import annotations

import importlib
import platform
import shutil
import subprocess
import sys
from typing import List, Tuple


REQUIRED_IMPORTS: Tuple[str, ...] = (
    "requests",
    "Crypto",
    "scapy",
    "setuptools",
)

OPTIONAL_BINARIES: Tuple[Tuple[str, str], ...] = (
    ("aircrack-ng", "WPA cracking / aircrack-ng suite"),
    ("airodump-ng", "Wi-Fi RF discovery (monitor mode)"),
    ("aireplay-ng", "Deauthentication / frame injection"),
    ("airmon-ng", "Monitor mode management"),
    ("hashcat", "GPU/CPU password cracking"),
    ("hcxpcapngtool", "PCAP → hashcat conversion (hcxtools)"),
    ("hcxdumptool", "PCAP capture / PMKID extraction (hcxtools)"),
    ("wifite", "Automated wireless audit"),
    ("reaver", "WPS PIN brute-force"),
    ("bully", "WPS PIN brute-force (alternative)"),
    ("pixiewps", "WPS pixie-dust offline attack"),
    ("wash", "WPS-enabled AP scanner"),
    ("hostapd", "Rogue AP / evil twin"),
    ("hostapd-mana", "KARMA/MANA rogue AP + EAP credential capture"),
    ("dnsmasq", "DHCP/DNS for captive portals"),
    ("bettercap", "MITM / ARP spoof / SSL strip / DNS spoof"),
    ("ettercap", "MITM (alternative backend)"),
    ("macchanger", "MAC address spoofing"),
    ("mdk3", "Beacon flood / deauth (legacy)"),
    ("mdk4", "Beacon flood / deauth / auth flood"),
    ("wifiphisher", "Evil twin + captive portal phishing (GPL-3.0 subprocess)"),
    ("btlejuice", "BLE MITM bridge"),
    ("hcitool", "BLE advertisement / HCI commands (BlueZ)"),
    ("hciconfig", "BLE adapter configuration (BlueZ)"),
    ("evilginx", "Real-time MFA phishing proxy"),
    ("msfconsole", "Metasploit framework integration"),
)


def _check_import(name: str) -> Tuple[str, bool, str]:
    """Check if a Python package is importable and return version info."""
    try:
        module = importlib.import_module(name)
    except Exception as err:
        return name, False, str(err)
    version = getattr(module, "__version__", "n/a")
    return name, True, str(version)


def _check_binary(name: str) -> Tuple[str, bool, str]:
    """Check if a system binary is available on PATH."""
    path = shutil.which(name)
    if path:
        try:
            result = subprocess.run(
                [name, "--version"],
                capture_output=True, text=True, timeout=5,
                encoding="utf-8", errors="replace",
            )
            version = result.stdout.strip().split("\n")[0][:80] if result.stdout else "found"
        except Exception:
            version = "found at {}".format(path)
        return name, True, version
    return name, False, "not found"


def main() -> int:
    """Run WirelessXPL-Forge environment diagnostics."""
    print("WirelessXPL-Forge Environment Doctor")
    print("python_version={}".format(platform.python_version()))
    print("platform={}".format(platform.platform()))
    print("executable={}".format(sys.executable))

    results: List[Tuple[str, bool, str]] = [_check_import(name) for name in REQUIRED_IMPORTS]
    print("\nPython dependency checks:")
    for name, ok, info in results:
        state = "OK" if ok else "FAIL"
        print("  - {}: {} ({})".format(name, state, info))

    failures = [item for item in results if not item[1]]
    if failures:
        print("\nMissing/broken Python dependencies detected.")
        print("Fix: python -m pip install -r requirements.txt")

    bin_results: List[Tuple[str, bool, str]] = [_check_binary(name) for name, _ in OPTIONAL_BINARIES]
    print("\nOptional tool checks:")
    for (name, desc), (_, ok, info) in zip(OPTIONAL_BINARIES, bin_results):
        state = "OK" if ok else "MISSING"
        print("  - {} ({}): {} ({})".format(name, desc, state, info))

    missing_bins = [name for name, ok, _ in bin_results if not ok]
    if missing_bins:
        print("\n{} optional tool(s) not found: {}".format(len(missing_bins), ", ".join(missing_bins)))
        print("Install them for full WXF functionality (see README).")

    if failures:
        return 1

    print("\nEnvironment looks ready for WirelessXPL-Forge.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
