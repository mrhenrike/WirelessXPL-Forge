from wirelessxpl.core.bluetooth.btle_client import BTLEClient
from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os


@requires_os(OSRequirement.LINUX_MAC)
class Exploit(BTLEClient):
    __info__ = {
        "name": "Bluetooth LE Enumerate",
        "description": "Enumerating services and characteristics of a given "
                       "Bluetooth Low Energy devices.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # wirelessxpl module
        ),
        "references": (
            "https://www.evilsocket.net/2017/09/23/This-is-not-a-post-about-BLE-introducing-BLEAH/",
        ),
    }

    target = OptMAC("", "Target MAC address")


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
        res = self.btle_scan(self.target)
        if res:
            device = res[0]

            device.print_info()
            device.print_services()
        self._exploit()

    def _exploit(self) -> None:
        """E2E exploit: enumerate BLE services via raw L2CAP ATT requests."""
        import socket
        import struct as _struct

        target_mac = str(self.target).strip()
        if not target_mac:
            print_warning("Sem MAC alvo: skip enumeração raw")
            return

        try:
            sock = socket.socket(31, socket.SOCK_SEQPACKET, 0)
            sock.settimeout(5.0)
            addr_bytes = bytes(int(b, 16) for b in target_mac.split(":"))
            sock.connect((addr_bytes, 0, 4))
        except OSError as exc:
            print_error(f"Falha na conexão L2CAP ATT: {exc}")
            return

        att_read_by_group = _struct.pack("<BHH", 0x10, 0x0001, 0xFFFF) + b"\x00\x28"
        try:
            sock.send(att_read_by_group)
            resp = sock.recv(512)
            if resp:
                print_success(f"ATT Read By Group Type response: {len(resp)} bytes")
                print_info(f"Raw: {resp.hex()}")
        except OSError:
            print_warning("Timeout na resposta ATT")
        finally:
            sock.close()
