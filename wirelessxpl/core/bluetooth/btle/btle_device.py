"""BLE device wrapper around bleak BLEDevice + AdvertisementData."""
from __future__ import annotations

from typing import Optional

from wirelessxpl.core.exploit.printer import (
    color_blue,
    color_green,
    color_red,
    print_error,
    print_status,
    print_table,
)
from wirelessxpl.core.exploit.utils import lookup_vendor


class Device:
    """Single discovered BLE device (bleak-backed, replaces bluepy ScanEntry)."""

    def __init__(self, ble_device, adv_data=None) -> None:
        self._dev = ble_device
        self._adv = adv_data
        self.addr: str = ble_device.address
        self.name: Optional[str] = ble_device.name or (adv_data.local_name if adv_data else None)
        self.rssi: int = adv_data.rssi if adv_data else -100
        self.connectable: bool = bool(adv_data and adv_data.tx_power is not None) or True
        self.vendor: str = (
            "None (Random MAC address)"
            if len(self.addr) == 17 and self.addr[1] in "26AEae"
            else lookup_vendor(self.addr)
        )
        self._services: list = []

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def print_info(self) -> None:
        headers = (color_blue("{} ({} dBm)").format(self.addr, self.rssi), "")
        conn_str = color_green(str(self.connectable)) if self.connectable else color_red(str(self.connectable))
        rows: list = [
            ("Name", self.name or "<unknown>"),
            ("Vendor", self.vendor or "<unknown>"),
            ("Allow Connections", conn_str),
        ]
        if self._adv:
            if self._adv.service_uuids:
                rows.append(("Service UUIDs", ", ".join(str(u) for u in self._adv.service_uuids[:4])))
            if self._adv.manufacturer_data:
                mfr = ", ".join(f"0x{k:04X}" for k in self._adv.manufacturer_data)
                rows.append(("Manufacturer", mfr))
        print_table(headers, *rows, max_column_length=70, extra_fill=3)

    def print_services(self) -> None:
        import asyncio
        services = asyncio.run(self._async_enumerate_services())
        if services:
            headers = ("Handle", "Service / Characteristic", "Properties", "Value")
            print_table(headers, *services, max_column_length=70, extra_fill=3)

    # ------------------------------------------------------------------
    # GATT enumeration (async, called via asyncio.run)
    # ------------------------------------------------------------------

    async def _async_enumerate_services(self) -> list:
        try:
            from bleak import BleakClient, BleakError  # type: ignore[import-untyped]
        except ImportError:
            print_error("bleak not installed: pip install bleak")
            return []

        print_status(f"Enumerating {self.addr} ({self.rssi} dBm) ...")
        rows = []
        try:
            async with BleakClient(self.addr) as client:
                for svc in client.services:
                    rows.append([str(svc.handle), color_green(svc.description or str(svc.uuid)), "", ""])
                    for char in svc.characteristics:
                        props = ", ".join(char.properties)
                        val = ""
                        if "read" in char.properties:
                            try:
                                data = await client.read_gatt_char(char)
                                try:
                                    val = color_blue(repr(data.decode("utf-8")))
                                except Exception:
                                    val = repr(data)
                            except Exception:
                                pass
                        rows.append([f"  {char.handle:04x}", char.description or str(char.uuid), props, val])
        except Exception as exc:
            print_error(f"Enumerate failed: {exc}")
        return rows
