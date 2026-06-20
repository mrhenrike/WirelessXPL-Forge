"""BLE scanner backed by bleak (replaces bluepy Scanner)."""
from __future__ import annotations

import asyncio
from typing import List, Optional

from .btle_device import Device


class BTLEScanner:
    """Discover nearby BLE devices using bleak BleakScanner."""

    def __init__(self, mac: Optional[str] = None, iface: int = 0) -> None:
        self.mac = mac.upper() if mac else None
        self.iface = iface

    def scan(self, timeout: float = 10.0) -> List[Device]:
        """Synchronous scan; returns list of Device objects."""
        return asyncio.run(self._async_scan(timeout))

    async def _async_scan(self, timeout: float) -> List[Device]:
        try:
            from bleak import BleakScanner  # type: ignore[import-untyped]
        except ImportError:
            return []

        results = await BleakScanner.discover(timeout=timeout, return_adv=True)
        devices: List[Device] = []
        for ble_dev, adv in results.values():
            if self.mac and ble_dev.address.upper() != self.mac:
                continue
            devices.append(Device(ble_dev, adv))

        return devices


class ScanDelegate:
    """Compatibility shim — no-op in the bleak-based implementation."""

    def __init__(self, options=None) -> None:
        self.options = options

    def handleDiscovery(self, dev: Device, is_new: bool, is_new_data: bool) -> None:
        if not is_new:
            return
        if self.options and self.options.buffering:
            dev.print_info()
