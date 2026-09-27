from wirelessxpl.core.exploit.exploit import Exploit
from wirelessxpl.core.exploit.option import OptInteger
from wirelessxpl.core.exploit.printer import (
    print_error,
    print_status,
)
from wirelessxpl.core.bluetooth.btle import BTLEScanner, ScanDelegate


class BTLEClient(Exploit):
    """Bluetooth Low Energy Client (bleak-backed scanner)."""

    scan_time = OptInteger(10, "Number of seconds to scan for")
    buffering = False
    enum_services = False

    def btle_scan(self, mac=None):
        """Scan for BLE devices and return a list of Device objects."""
        scanner = BTLEScanner(mac)
        delegate = ScanDelegate()
        delegate.options = type("_Opt", (), {"buffering": self.buffering, "mac": mac})()

        if mac:
            print_status("Scanning for BTLE device {}...".format(mac))
        else:
            print_status("Scanning for BTLE devices ({} s)...".format(self.scan_time))

        devices = []
        try:
            devices = scanner.scan(float(self.scan_time))
            for dev in devices:
                delegate.handleDiscovery(dev, True, True)
        except Exception as err:
            print_error("Error: {}".format(err))
            print_error("Check if your Bluetooth adapter is connected and powered on.")

        return devices
