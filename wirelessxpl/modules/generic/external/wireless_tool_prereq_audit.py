"""Report availability of common wireless cracking / capture tools on PATH.

Does not install packages — orchestration only for lab prep.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import shutil

from wirelessxpl.core.exploit import *


class Exploit(Exploit):
    """Check prereq CLIs for 802.11 / WPA workflows."""

    __info__ = {
        "name": "Wireless tool prerequisite audit",
        "description": "Checks PATH for aircrack-ng suite, hcxtools, hashcat, bettercap, tshark. "
                       "Use before wardriving / lab capture pipelines.",
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://www.aircrack-ng.org/",
            "https://github.com/ZerBea/hcxtools",
            "https://hashcat.net/hashcat/",
            "https://www.bettercap.org/",
        ),
        "devices": ("Workstation / Kali / WSL lab host",),
    }

    def run(self) -> None:
        tools = (
            ("aircrack-ng", "WEP/WPA PSK cracking, PCAP parsing"),
            ("airodump-ng", "802.11 frame capture"),
            ("aireplay-ng", "Injection / deauth for handshake harvest"),
            ("hcxpcapngtool", "hcxtools — PCAP → 22000 hash lines"),
            ("hcxdumptool", "Active PMKID / handshake capture (Linux + suitable NIC)"),
            ("hashcat", "GPU/CPU WPA hash cracking"),
            ("bettercap", "Modular MITM / 802.11 tooling (optional)"),
            ("tshark", "CLI Wireshark — BLE/802.11 dissection"),
        )
        found = 0
        for name, note in tools:
            path = shutil.which(name)
            if path:
                found += 1
                print_success("{} → {} ({})".format(name, path, note))
            else:
                print_error("{} — missing ({})".format(name, note))
        print_status("Found {}/{} tools on PATH.".format(found, len(tools)))
