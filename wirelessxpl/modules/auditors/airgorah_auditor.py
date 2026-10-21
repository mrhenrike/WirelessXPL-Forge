"""Wrapper stub for Airgorah WiFi security auditor (Rust + GTK4).

Source: https://github.com/martin-olivier/airgorah (4502 stars)
Crate: https://crates.io/crates/airgorah
License: MIT
SRC-ID: SRC-1005, SRC-1006
Category: WiFi audit, deauth, handshake/PMKID capture, WPA cracking

Airgorah is a WiFi security auditing tool written in Rust with GTK4 GUI.
Features: deauthentication, handshake and PMKID capture, WPA cracking.
Requires a wireless adapter with monitor mode support.
"""

from dataclasses import dataclass


@dataclass
class AirgorahConfig:
    interface: str = "wlan0"
    target_bssid: str | None = None
    capture_pmkid: bool = True
    deauth: bool = False
    wordlist: str | None = None


def check_dependencies() -> dict[str, bool]:
    """Verify airgorah binary and required system tools."""
    import shutil

    tools = ["airgorah", "airmon-ng", "hashcat"]
    return {tool: shutil.which(tool) is not None for tool in tools}
