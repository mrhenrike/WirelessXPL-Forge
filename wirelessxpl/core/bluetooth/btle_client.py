from wirelessxpl.core.bluetooth.btle import BTLEScanner, ScanDelegate
from wirelessxpl.core.bluetooth.btle.btle_device import Device
from wirelessxpl.core.exploit.exploit import Exploit
from wirelessxpl.core.exploit.option import OptInteger
from wirelessxpl.core.exploit.printer import (
    print_error,
    print_status,
)


class BTLEClient(Exploit):
    """Bluetooth Low Energy Client (bleak-backed scanner)."""

    scan_time = OptInteger(10, "Number of seconds to scan for")
    buffering = False
    enum_services = False

    def btle_scan(self, mac: str | None = None) -> list[Device]:
        """Scan for BLE devices and return a list of Device objects."""
        scanner = BTLEScanner(mac)
        delegate = ScanDelegate()
        delegate.options = type("_Opt", (), {"buffering": self.buffering, "mac": mac})()

        if mac:
            print_status(f"Scanning for BTLE device {mac}...")
        else:
            print_status(f"Scanning for BTLE devices ({self.scan_time} s)...")

        devices = []
        try:
            devices = scanner.scan(float(self.scan_time))
            for dev in devices:
                delegate.handleDiscovery(dev, True, True)
        except Exception as err:
            print_error(f"Error: {err}")
            print_error("Check if your Bluetooth adapter is connected and powered on.")

        return devices
