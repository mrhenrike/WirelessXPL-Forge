"""Wrapper stub for wifit3 USB-only cross-platform wireless auditor.

Source: https://github.com/derv82/wifit3 (2509 stars)
License: GPL-2.0
SRC-ID: SRC-149
Category: WiFi audit, USB adapter, cross-platform

wifit3 is a USB-only cross-platform wireless auditor. Successor to wifite2
with improved USB adapter support and cross-platform compatibility.
"""

from dataclasses import dataclass


@dataclass
class Wifit3Config:
    interface: str = "wlan0"
    target_bssid: str | None = None
    usb_adapter: str | None = None
    monitor_mode: bool = True
