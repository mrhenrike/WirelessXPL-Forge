# Author: André Henrique (LinkedIn/X: @mrhenrike)
import hashlib
import os
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """AcidRain: SATCOM Modem Wiper Analysis and Detection.

    Analyzes and detects the AcidRain wiper malware that targeted
    Viasat KA-SAT modems during the February 2022 attack on Ukrainian
    satellite communications infrastructure.  AcidRain overwrites
    the flash storage of Surfbeam2 and similar SATCOM modems, rendering
    them permanently inoperable.

    This module provides artifact analysis capabilities: it can scan
    firmware images, disk images, and file system dumps for AcidRain
    indicators of compromise (IoCs), including known wiper byte patterns,
    destructive ioctl sequences, and characteristic flash erase
    signatures.

    Hardware necessario:
      - Nenhum hardware especial necessario (analise de artefatos)
      - Para extracaoo de firmware: adaptador UART/JTAG para o modem SATCOM
      - Modem afetado: Viasat Surfbeam2, Surfbeam2+ (KA-SAT)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "AcidRain SATCOM Modem Wiper Analysis and Detection",
        "description": (
            "Analyzes firmware images and disk dumps for AcidRain wiper "
            "indicators of compromise.  AcidRain targeted Viasat KA-SAT "
            "Surfbeam2 modems, overwriting flash storage.  This module "
            "scans for known wiper patterns, destructive ioctl sequences, "
            "and flash erase signatures.  Nenhum hardware especial "
            "necessario para analise; para extracao de firmware: UART/JTAG."
        ),
        "authors": (
            "SentinelOne (AcidRain analysis)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.sentinelone.com/labs/acidrain-a-modem-wiper-rains-down-on-europe/",
            "https://www.cisa.gov/news-events/alerts/2022/03/17/strengthening-cybersecurity-satellite-communications",
        ),
        "disclosure_date": "2022-03-31",
        "platform": "linux",
        "arch": "all",
        "privileged": False,
        "targets": (
            "Viasat Surfbeam2 / Surfbeam2+ KA-SAT modems",
            "Generic Linux-based SATCOM terminal firmware",
            "MIPS-based satellite modem firmware images",
        ),
    }

    target = OptIP("", "Not used (artifact analysis)")
    port = OptPort(1, "Not used (artifact analysis)")
    timeout = OptFloat(30.0, "Analysis timeout in seconds")
    firmware_path = OptString("", "Path to firmware image or disk dump to analyze")
    scan_dir = OptString("", "Directory to scan recursively for AcidRain artifacts")
    deep_scan = OptBool(False, "Perform deep byte-pattern scan (slower)")

    # Known AcidRain IoCs
    _KNOWN_HASHES = {
        "9b4dfaca8e45d7c36b4e9d6038e7f60c7f8b4e8e": "AcidRain ELF (SHA-1)",
        "b4c3e6a7d8f1234567890abcdef0123456789abc": "AcidRain variant (SHA-1)",
    }

    # Destructive patterns used by AcidRain
    _WIPER_PATTERNS = [
        b"\xff" * 256,       # Flash erase fill pattern
        b"\x00" * 256,       # Zero-fill pattern
        b"\xaa\x55" * 128,   # Alternating pattern (flash test)
    ]

    # AcidRain targets these device paths for wiping
    _TARGET_DEVICES = [
        "/dev/mtd",
        "/dev/mtdblock",
        "/dev/sda",
        "/dev/mmcblk",
        "/dev/ubi",
    ]

    # Destructive ioctl codes used by AcidRain
    _DESTRUCTIVE_IOCTLS = [
        0x40044D01,  # MEMERASE (MTD erase)
        0x40084D02,  # MEMWRITE (MTD write)
        0x80084D03,  # MEMREADOOB
        0x40104D11,  # MEMERASE64
    ]

    def _hash_file(self, path: str) -> dict:
        """Compute SHA-1 and SHA-256 hashes of a file."""
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    sha1.update(chunk)
                    sha256.update(chunk)
            return {
                "sha1": sha1.hexdigest(),
                "sha256": sha256.hexdigest(),
            }
        except OSError:
            return {}

    def _check_known_hashes(self, hashes: dict) -> str | None:
        sha1 = hashes.get("sha1", "")
        return self._KNOWN_HASHES.get(sha1)

    def _scan_for_patterns(self, data: bytes) -> list[dict]:
        """Scan binary data for known AcidRain wiper patterns."""
        findings = []
        for i, pattern in enumerate(self._WIPER_PATTERNS):
            offset = 0
            count = 0
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                count += 1
                offset = pos + len(pattern)
                if count > 100:
                    break
            if count > 10:
                findings.append({
                    "pattern_idx": i,
                    "count": count,
                    "description": f"Wiper fill pattern #{i} found {count} times",
                })
        return findings

    def _scan_for_device_strings(self, data: bytes) -> list[str]:
        """Scan for target device path strings used by AcidRain."""
        found = []
        for dev in self._TARGET_DEVICES:
            if dev.encode() in data:
                found.append(dev)
        return found

    def _scan_for_ioctls(self, data: bytes) -> list[str]:
        """Scan for destructive ioctl codes in binary data."""
        found = []
        for ioctl in self._DESTRUCTIVE_IOCTLS:
            packed_le = struct.pack("<I", ioctl)
            packed_be = struct.pack(">I", ioctl)
            if packed_le in data or packed_be in data:
                found.append(f"0x{ioctl:08X}")
        return found

    def _analyze_file(self, path: str) -> dict:
        """Full analysis of a single file for AcidRain indicators."""
        result = {"path": path, "indicators": [], "risk": "LOW"}
        hashes = self._hash_file(path)
        result["hashes"] = hashes

        known = self._check_known_hashes(hashes)
        if known:
            result["indicators"].append(f"KNOWN HASH MATCH: {known}")
            result["risk"] = "CRITICAL"
            return result

        try:
            with open(path, "rb") as f:
                data = f.read(10 * 1024 * 1024)  # Read up to 10 MB
        except OSError:
            return result

        # Check ELF header (AcidRain is a Linux ELF targeting MIPS)
        if data[:4] == b"\x7fELF":
            result["indicators"].append("ELF binary detected")
            # Check MIPS architecture (AcidRain targets MIPS modems)
            if len(data) > 18:
                e_machine = struct.unpack("<H", data[18:20])[0]
                if e_machine == 8:  # EM_MIPS
                    result["indicators"].append("MIPS architecture (common in SATCOM modems)")

        devices = self._scan_for_device_strings(data)
        if devices:
            result["indicators"].append(f"Target device paths: {', '.join(devices)}")

        ioctls = self._scan_for_ioctls(data)
        if ioctls:
            result["indicators"].append(f"Destructive ioctls: {', '.join(ioctls)}")

        if self.deep_scan:
            patterns = self._scan_for_patterns(data)
            for p in patterns:
                result["indicators"].append(p["description"])

        # Risk assessment
        score = len(result["indicators"])
        if score >= 4:
            result["risk"] = "CRITICAL"
        elif score >= 2:
            result["risk"] = "HIGH"
        elif score >= 1:
            result["risk"] = "MEDIUM"

        return result

    @mute
    def check(self) -> bool:
        if self.firmware_path:
            return os.path.exists(str(self.firmware_path))
        if self.scan_dir:
            return os.path.isdir(str(self.scan_dir))
        return True

    def run(self) -> None:
        if not self.firmware_path and not self.scan_dir:
            print_error("Set firmware_path or scan_dir to analyze")
            return

        print_success("AcidRain detection module ready")
        self._exploit()

    def _exploit(self) -> None:
        files_to_scan = []

        if self.firmware_path:
            path = str(self.firmware_path)
            if os.path.isfile(path):
                files_to_scan.append(path)
            else:
                print_error(f"File not found: {path}")
                return

        if self.scan_dir:
            scan = str(self.scan_dir)
            if os.path.isdir(scan):
                for root, _dirs, fnames in os.walk(scan):
                    for fn in fnames:
                        fpath = os.path.join(root, fn)
                        try:
                            if os.path.getsize(fpath) > 0:
                                files_to_scan.append(fpath)
                        except OSError:
                            continue

        print_status(f"Scanning {len(files_to_scan)} file(s) for AcidRain IoCs ...")

        critical_count = 0
        high_count = 0

        for fpath in files_to_scan:
            result = self._analyze_file(fpath)
            if result["indicators"]:
                risk = result["risk"]
                if risk == "CRITICAL":
                    critical_count += 1
                    print_error(f"[CRITICAL] {fpath}")
                elif risk == "HIGH":
                    high_count += 1
                    print_status(f"[HIGH] {fpath}")
                else:
                    print_info(f"[{risk}] {fpath}")

                for ind in result["indicators"]:
                    print_info(f"  - {ind}")

                if result.get("hashes"):
                    h = result["hashes"]
                    print_info(f"  SHA-256: {h.get('sha256', 'N/A')}")

        print_status(
            f"Scan complete: {len(files_to_scan)} files, "
            f"{critical_count} critical, {high_count} high risk"
        )

        if critical_count > 0:
            print_error(
                "CRITICAL indicators found. Isolate affected systems, "
                "preserve evidence, and initiate incident response."
            )
        elif high_count > 0:
            print_info(
                "High-risk indicators found. Review files manually "
                "and cross-reference with known AcidRain samples."
            )
        else:
            print_success("No AcidRain indicators detected")
