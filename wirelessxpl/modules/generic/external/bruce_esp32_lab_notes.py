"""Bruce ESP32 multi-tool firmware — lab integration notes (no flashing).

Bruce (AGPL-3.0) runs on ESP32-class hardware for Wi‑Fi attacks, wardriving-style
recon, and companion BLE features. This module prints authoritative links and a
safe workflow; it does **not** bundle or flash firmware.

Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

from wirelessxpl.core.exploit import *


class Exploit(Exploit):
    """Documentation bridge for Bruce firmware."""

    __info__ = {
        "name": "Bruce ESP32 firmware (lab notes)",
        "description": "Pointers to BruceDevices firmware: wardriving, raw sniffer hooks, "
                       "deauth/evil-portal patterns on dedicated hardware. Export PCAP to this "
                       "framework's ``generic/pcap/*`` modules for offline WPA3 / EAPOL analysis.",
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://github.com/BruceDevices/firmware",
            "https://github.com/pr3y/Bruce",
            "https://bruce.computer/",
        ),
        "devices": ("ESP32 / Cardputer / M5Stack (user hardware)",),
    }

    def run(self) -> None:
        print_status(
            "Bruce is third-party AGPL firmware — comply with license and local radio laws."
        )
        print_info("Upstream: https://github.com/BruceDevices/firmware")
        print_info("Web flasher / docs: https://bruce.computer/")
        print_info("Suggested lab loop: capture on hardware → export PCAP/PCAPNG → "
                   "`use generic/pcap/pcap_handshake_extractor` / `pcap_eapol_survey` / "
                   "`pcap_dragonblood` → hashcat or aircrack-ng on workstation.")
