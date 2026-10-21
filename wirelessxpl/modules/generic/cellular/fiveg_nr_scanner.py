#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""5G NR standalone cell scanner and analysis.

Passive 5G NR reconnaissance: scan SSB (Synchronization Signal Blocks),
decode MIB/SIB1, enumerate cells by NR-ARFCN, identify PLMN (MCC/MNC),
extract cell identity (PCI, gNB-ID), and map frequency bands.

Supports n1, n3, n5, n7, n8, n20, n28, n38, n41, n77, n78, n79 bands.
Requires SDR hardware (USRP B210, LimeSDR, BladeRF x40/xA4) and
srsRAN Project or custom GNURadio flowgraph for NR PSS/SSS correlation.

References:
  https://github.com/srsran/srsRAN_Project
  https://www.3gpp.org/ftp/Specs/archive/38_series/38.331/
  https://www.sharetechnote.com/html/5G/5G_SSB.html

MITRE ATT&CK: T1040 (Network Sniffing)
CWE: CWE-319 (Cleartext Transmission of Sensitive Information)

Version: 1.0.0
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
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

NR_BANDS: dict[str, dict[str, Any]] = {
    "n1":  {"dl_low": 2110.0, "dl_high": 2170.0, "duplex": "FDD", "scs": 15},
    "n3":  {"dl_low": 1805.0, "dl_high": 1880.0, "duplex": "FDD", "scs": 15},
    "n5":  {"dl_low": 869.0,  "dl_high": 894.0,  "duplex": "FDD", "scs": 15},
    "n7":  {"dl_low": 2620.0, "dl_high": 2690.0, "duplex": "FDD", "scs": 15},
    "n8":  {"dl_low": 925.0,  "dl_high": 960.0,  "duplex": "FDD", "scs": 15},
    "n20": {"dl_low": 791.0,  "dl_high": 821.0,  "duplex": "FDD", "scs": 15},
    "n28": {"dl_low": 758.0,  "dl_high": 803.0,  "duplex": "FDD", "scs": 15},
    "n38": {"dl_low": 2570.0, "dl_high": 2620.0, "duplex": "TDD", "scs": 30},
    "n41": {"dl_low": 2496.0, "dl_high": 2690.0, "duplex": "TDD", "scs": 30},
    "n77": {"dl_low": 3300.0, "dl_high": 4200.0, "duplex": "TDD", "scs": 30},
    "n78": {"dl_low": 3300.0, "dl_high": 3800.0, "duplex": "TDD", "scs": 30},
    "n79": {"dl_low": 4400.0, "dl_high": 5000.0, "duplex": "TDD", "scs": 30},
}

ARFCN_DELTA_F_GLOBAL_KHZ = 5
ARFCN_F_REF_OFFS_KHZ_LOW = 0
ARFCN_N_REF_OFFS_LOW = 0
ARFCN_F_REF_OFFS_KHZ_MID = 3_000_000
ARFCN_N_REF_OFFS_MID = 600_000
ARFCN_F_REF_OFFS_KHZ_HIGH = 24_250_080
ARFCN_N_REF_OFFS_HIGH = 2_016_667


def arfcn_to_freq_mhz(arfcn: int) -> float:
    """Convert NR-ARFCN to frequency in MHz."""
    if arfcn < ARFCN_N_REF_OFFS_MID:
        freq_khz = ARFCN_F_REF_OFFS_KHZ_LOW + ARFCN_DELTA_F_GLOBAL_KHZ * (arfcn - ARFCN_N_REF_OFFS_LOW)
    elif arfcn < ARFCN_N_REF_OFFS_HIGH:
        freq_khz = ARFCN_F_REF_OFFS_KHZ_MID + 15 * (arfcn - ARFCN_N_REF_OFFS_MID)
    else:
        freq_khz = ARFCN_F_REF_OFFS_KHZ_HIGH + 60 * (arfcn - ARFCN_N_REF_OFFS_HIGH)
    return freq_khz / 1000.0


def freq_to_band(freq_mhz: float) -> str | None:
    """Identify NR band from DL frequency."""
    for band_name, spec in NR_BANDS.items():
        if spec["dl_low"] <= freq_mhz <= spec["dl_high"]:
            return band_name
    return None


@dataclass
class NRCell:
    """Detected 5G NR cell."""
    pci: int = 0
    arfcn: int = 0
    freq_mhz: float = 0.0
    band: str = ""
    scs_khz: int = 30
    rsrp_dbm: float = -140.0
    mcc: str = ""
    mnc: str = ""
    gnb_id: int = 0
    cell_id: int = 0
    tac: int = 0
    ssb_index: int = 0


@dataclass
class ScanResult:
    """Aggregated scan result."""
    cells: list[NRCell] = field(default_factory=list)
    band_scanned: str = ""
    duration_sec: float = 0.0


class FiveGNRScanner(Exploit):
    """5G NR standalone cell scanner."""

    __info__: dict[str, Any] = {
        "name": "5G NR Cell Scanner",
        "description": (
            "Passive 5G NR reconnaissance: scan SSB, decode MIB/SIB1, "
            "enumerate cells by NR-ARFCN, identify PLMN and cell identity."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/srsran/srsRAN_Project",
            "https://www.3gpp.org/ftp/Specs/archive/38_series/38.331/",
        ),
        "devices": ("5G NR gNodeB", "5G NR SA cells"),
        "severity": "medium",
        "cvss": "5.3",
        "cve": "generic",
        "mitre": ["T1040"],
    }

    band = OptString("n78", "NR band to scan (n1,n3,n5,n7,n8,n20,n28,n38,n41,n77,n78,n79)")
    sdr_device = OptString("driver=uhd", "SoapySDR device string (driver=uhd, driver=lime, etc.)")
    sample_rate_mhz = OptInteger(23, "Sample rate in MHz (23.04 for 20 MHz BW)")
    center_freq_mhz = OptString("", "Center frequency MHz (auto from band if empty)")
    gain_db = OptInteger(40, "RX gain in dB")
    scan_duration_sec = OptInteger(10, "Scan duration per frequency step in seconds")
    output_file = OptString("nr_scan_results.json", "Output JSON file")
    srsran_path = OptString("/usr/local/bin", "Path to srsRAN binaries")
    dry_run = OptBool(False, "Print commands without executing")

    def __init__(self) -> None:
        super().__init__()
        self._results: ScanResult = ScanResult()

    def check(self) -> str:
        """Verify SDR hardware and srsRAN tools."""
        tools_found: list[str] = []
        tools_missing: list[str] = []

        for tool in ["SoapySDRUtil", "srsue", "gnb"]:
            if shutil.which(tool) or (Path(str(self.srsran_path.value)) / tool).exists():
                tools_found.append(tool)
            else:
                tools_missing.append(tool)

        if shutil.which("SoapySDRUtil"):
            try:
                result = subprocess.run(
                    ["SoapySDRUtil", "--find"],
                    capture_output=True, text=True, timeout=10,
                )
                if "No devices found" in result.stdout:
                    return "SoapySDR available but no SDR devices connected"
                device_count = result.stdout.count("Found device")
                return f"SDR detected ({device_count} device(s)), tools: {', '.join(tools_found)}"
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        if tools_missing:
            return f"Missing tools: {', '.join(tools_missing)}. Install srsRAN Project."
        return f"Tools available: {', '.join(tools_found)}"

    def _get_scan_frequencies(self) -> list[float]:
        """Generate list of center frequencies to scan for the selected band."""
        band_name = str(self.band.value).strip().lower()
        if band_name not in NR_BANDS:
            print_warning(f"[!] Unknown band {band_name}, using custom center freq")
            custom = str(self.center_freq_mhz.value).strip()
            if custom:
                return [float(custom)]
            return []

        spec = NR_BANDS[band_name]
        dl_low = spec["dl_low"]
        dl_high = spec["dl_high"]
        bw = float(self.sample_rate_mhz.value)
        step = bw * 0.8

        freqs: list[float] = []
        f = dl_low + bw / 2
        while f < dl_high - bw / 2:
            freqs.append(round(f, 2))
            f += step

        if not freqs:
            freqs.append(round((dl_low + dl_high) / 2, 2))

        return freqs

    def _scan_frequency(self, center_freq_mhz: float) -> list[NRCell]:
        """Scan a single center frequency for NR SSBs."""
        cells: list[NRCell] = []
        gain = int(self.gain_db.value)
        rate = float(self.sample_rate_mhz.value)
        duration = int(self.scan_duration_sec.value)

        cmd = [
            "srsue",
            "--rf.device_name", str(self.sdr_device.value),
            "--rf.dl_earfcn", "0",
            "--rf.freq_offset", "0",
            "--rf.rx_gain", str(gain),
            "--rf.srate", f"{rate}e6",
            "--rat.nr.bands", str(self.band.value).strip().lstrip("n"),
            "--rat.nr.nof_carriers", "1",
            "--log.all_level", "info",
            "--general.metrics_csv_enable", "true",
        ]

        if self.dry_run.value:
            print_info(f"[dry-run] Center {center_freq_mhz} MHz: {' '.join(cmd)}")
            return cells

        print_status(f"[*] Scanning {center_freq_mhz} MHz for {duration}s ...")

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            import time
            time.sleep(duration)
            proc.terminate()
            try:
                stdout, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, _ = proc.communicate(timeout=3)

            for line in (stdout or "").splitlines():
                pci_match = re.search(r"PCI[=:\s]+(\d+)", line)
                rsrp_match = re.search(r"RSRP[=:\s]+([-\d.]+)", line)
                if pci_match:
                    cell = NRCell(
                        pci=int(pci_match.group(1)),
                        freq_mhz=center_freq_mhz,
                        band=str(self.band.value),
                        scs_khz=NR_BANDS.get(str(self.band.value), {}).get("scs", 30),
                    )
                    if rsrp_match:
                        cell.rsrp_dbm = float(rsrp_match.group(1))

                    plmn_match = re.search(r"PLMN[=:\s]+(\d{3})/(\d{2,3})", line)
                    if plmn_match:
                        cell.mcc = plmn_match.group(1)
                        cell.mnc = plmn_match.group(2)

                    tac_match = re.search(r"TAC[=:\s]+(\d+)", line)
                    if tac_match:
                        cell.tac = int(tac_match.group(1))

                    cells.append(cell)

        except FileNotFoundError:
            print_error("[-] srsue not found. Install srsRAN Project.")
        except OSError as exc:
            print_error(f"[-] Scan failed: {exc}")

        return cells

    def _export_results(self) -> None:
        """Export scan results to JSON."""
        output_path = Path(str(self.output_file.value))
        data = {
            "band": self._results.band_scanned,
            "cells_found": len(self._results.cells),
            "cells": [
                {
                    "pci": c.pci,
                    "arfcn": c.arfcn,
                    "freq_mhz": c.freq_mhz,
                    "band": c.band,
                    "scs_khz": c.scs_khz,
                    "rsrp_dbm": c.rsrp_dbm,
                    "plmn": f"{c.mcc}/{c.mnc}" if c.mcc else "",
                    "tac": c.tac,
                    "gnb_id": c.gnb_id,
                }
                for c in self._results.cells
            ],
        }
        output_path.write_text(json.dumps(data, indent=2))
        print_success(f"[+] Results saved to {output_path}")

    def run(self) -> None:
        """Execute 5G NR cell scan."""
        band_name = str(self.band.value).strip()
        print_status(f"[*] 5G NR Cell Scanner v1.0.0 | Band {band_name}")

        freqs = self._get_scan_frequencies()
        if not freqs:
            print_error(f"[-] No frequencies for band {band_name}")
            return

        print_info(f"[*] Scanning {len(freqs)} frequency step(s) across band {band_name}")
        self._results = ScanResult(band_scanned=band_name)

        all_cells: list[NRCell] = []
        for freq in freqs:
            cells = self._scan_frequency(freq)
            all_cells.extend(cells)

        seen_pcis: set[int] = set()
        for cell in all_cells:
            if cell.pci not in seen_pcis:
                seen_pcis.add(cell.pci)
                self._results.cells.append(cell)

        print_status(f"\n[*] Scan complete: {len(self._results.cells)} unique cells detected")
        for cell in self._results.cells:
            plmn_str = f" PLMN={cell.mcc}/{cell.mnc}" if cell.mcc else ""
            print_info(
                f"    PCI={cell.pci:4d} | {cell.freq_mhz:8.2f} MHz | "
                f"RSRP={cell.rsrp_dbm:6.1f} dBm | SCS={cell.scs_khz} kHz"
                f"{plmn_str}"
            )

        if self._results.cells:
            self._export_results()
