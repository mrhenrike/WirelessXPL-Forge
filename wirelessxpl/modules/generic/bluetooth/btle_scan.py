from wirelessxpl.core.bluetooth.btle_client import BTLEClient
from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os


@requires_os(OSRequirement.LINUX_MAC)
class Exploit(BTLEClient):
    __info__ = {
        "name": "Bluetooth LE Scan",
        "description": "Scans for Bluetooth Low Energy devices.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # wirelessxpl module
        ),
        "references": (
            "https://www.evilsocket.net/2017/09/23/This-is-not-a-post-about-BLE-introducing-BLEAH/",
        ),
    }

    enum = OptBool(False, "Automatically enumerate services: true/false")
    buffering = OptBool(False, "Buffering enabled: true/false. Results in real time.")


    def check(self) -> str:
        """Verify Bluetooth HCI adapter is present and accessible."""
        import shutil
        import subprocess
        hci = getattr(self, "hci_iface", None) or getattr(self, "attacker_hci", None) or "hci0"
        if shutil.which("hciconfig"):
            try:
                out = subprocess.check_output(
                    ["hciconfig", str(hci)], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if "BD Address" in out:
                    return f"HCI adapter {hci} found - prerequisites OK"
                return f"hciconfig {hci} responded but no BD Address - check adapter"
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if shutil.which("bluetoothctl"):
            return "bluetoothctl available - verify adapter manually"
        return "hciconfig not found in PATH - install bluez package"

    def run(self):
        devices = self.btle_scan()

        for device in devices:
            if not self.buffering:
                device.print_info()

            if self.enum:
                device.print_services()
        self._exploit()

    def _exploit(self) -> None:
        """E2E exploit: active BLE scan via raw HCI commands."""
        import socket
        import struct as _struct

        try:
            sock = socket.socket(31, socket.SOCK_RAW, 1)
            sock.settimeout(5.0)
            sock.bind((0,))
        except OSError as exc:
            print_error(f"Falha ao abrir HCI socket: {exc}")
            return

        le_set_scan_params = _struct.pack("<BHBBHBB", 0x01, 0x200B, 7, 0x01, 0x0010, 0x0010, 0x00, 0x00)
        sock.send(le_set_scan_params)

        le_set_scan_enable = _struct.pack("<BHBBB", 0x01, 0x200C, 2, 0x01, 0x00)
        sock.send(le_set_scan_enable)

        print_status("BLE scan ativo via HCI por 10s...")
        deadline = time.time() + 10
        devices_found = set()
        while time.time() < deadline:
            try:
                data = sock.recv(256)
                if len(data) > 12 and data[0] == 0x04 and data[1] == 0x3E:
                    addr = data[7:13]
                    mac = ":".join(f"{b:02X}" for b in reversed(addr))
                    if mac not in devices_found:
                        devices_found.add(mac)
                        rssi = _struct.unpack("b", data[-1:])[0]
                        print_info(f"  BLE device: {mac} (RSSI: {rssi} dBm)")
            except OSError:
                break

        le_scan_disable = _struct.pack("<BHBBB", 0x01, 0x200C, 2, 0x00, 0x00)
        sock.send(le_scan_disable)
        sock.close()
        print_success(f"Scan completo: {len(devices_found)} dispositivos BLE encontrados")
