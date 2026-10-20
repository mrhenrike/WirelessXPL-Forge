from wirelessxpl.core.bluetooth.btle_client import BTLEClient
from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os


@requires_os(OSRequirement.LINUX_MAC)
class Exploit(BTLEClient):
    __info__ = {
        "name": "Bluetooth LE Write",
        "description": "Writes data to target Bluetooth Low Energy device to given "
                       "characteristic.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # wirelessxpl module
        ),
        "references": (
            "https://www.evilsocket.net/2017/09/23/This-is-not-a-post-about-BLE-introducing-BLEAH/",
        ),
    }

    target = OptMAC("", "Target MAC address")
    char = OptString("", "Characteristic")
    data = OptString("41424344", "Data (in hex format)")
    buffering = OptBool(True, "Buffering enabled: true/false. Results in real time.")


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
        try:
            data = bytes.fromhex(self.data)
        except ValueError:
            print_error("Data is not in valid format")
            return

        res = self.btle_scan(self.target)
        if res:
            device = res[0]
            device.write(self.char, data)
        self._exploit()

    def _exploit(self) -> None:
        """E2E exploit: write to BLE characteristic via raw L2CAP ATT."""
        import socket
        import struct as _struct

        target_mac = str(self.target).strip()
        char_handle = str(self.char).strip()
        if not target_mac or not char_handle:
            print_warning("Sem MAC ou handle: skip write raw")
            return

        try:
            data = bytes.fromhex(str(self.data))
        except ValueError:
            return

        try:
            handle = int(char_handle, 16) if char_handle.startswith("0x") else int(char_handle)
        except ValueError:
            return

        try:
            sock = socket.socket(31, socket.SOCK_SEQPACKET, 0)
            sock.settimeout(5.0)
            addr_bytes = bytes(int(b, 16) for b in target_mac.split(":"))
            sock.connect((addr_bytes, 0, 4))
        except OSError as exc:
            print_error(f"Conexão L2CAP falhou: {exc}")
            return

        att_write = _struct.pack("<BH", 0x12, handle) + data
        try:
            sock.send(att_write)
            resp = sock.recv(256)
            if resp and resp[0] == 0x13:
                print_success(f"Write confirmado no handle 0x{handle:04X}")
            else:
                print_warning(f"Resposta inesperada: {resp.hex() if resp else 'vazia'}")
        except OSError:
            print_warning("Timeout na resposta ATT Write")
        finally:
            sock.close()
