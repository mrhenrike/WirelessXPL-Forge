"""Wrapper stub for wifisting GTK4 wireless toolkit.

Source: https://github.com/yslxotwod/wifisting
License: verify
SRC-ID: SRC-679
Category: WiFi/Bluetooth/RF/MITM, 58 modules, GTK4 GUI, Linux

wifisting provides 58 modules covering Wi-Fi, Bluetooth, RF, and MITM
attacks in a GTK4 interface. Requires Linux with monitor-mode capable
adapter.
"""

from dataclasses import dataclass


@dataclass
class WifistingConfig:
    interface: str = "wlan0"
    module: str | None = None
    headless: bool = False
