#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""GNURadio GSM signal analysis bridge.

Integrates gr-gsm (GNURadio GSM receiver blocks) for passive GSM
signal capture and decoding. Tunes SDR to GSM ARFCN frequencies,
captures bursts, decodes BCCH/CCCH system information, extracts
cell parameters (MCC, MNC, LAC, CID), and optionally feeds decoded
frames to Wireshark via UDP for protocol-level analysis.

Supports GSM-900, DCS-1800, PCS-1900, GSM-850 bands.
Requires GNURadio 3.10+, gr-gsm, and SDR hardware.

References:
  https://github.com/ptrkrysik/gr-gsm
  https://osmocom.org/projects/gr-gsm/wiki
  https://www.etsi.org/deliver/etsi_ts/144000_144099/144018/

MITRE ATT&CK: T1040 (Network Sniffing), T1592.002 (Gather Victim Network Information: DNS)
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

GSM_BANDS: dict[str, dict[str, Any]] = {
    "GSM-900": {
        "arfcn_range": (1, 124),
        "freq_offset": 890.0,
        "channel_bw": 0.2,
        "uplink_start": 890.0,
        "downlink_start": 935.0,
    },
    "DCS-1800": {
        "arfcn_range": (512, 885),
        "freq_offset": 1710.0,
        "channel_bw": 0.2,
        "uplink_start": 1710.2,
        "downlink_start": 1805.2,
    },
    "PCS-1900": {
        "arfcn_range": (512, 810),
        "freq_offset": 1850.0,
        "channel_bw": 0.2,
        "uplink_start": 1850.2,
        "downlink_start": 1930.2,
    },
    "GSM-850": {
        "arfcn_range": (128, 251),
        "freq_offset": 824.0,
        "channel_bw": 0.2,
        "uplink_start": 824.2,
        "downlink_start": 869.2,
    },
}


def arfcn_to_freq(arfcn: int, band: str = "GSM-900") -> float:
    """Convert GSM ARFCN to downlink frequency in MHz."""
    if band == "GSM-900":
        if 1 <= arfcn <= 124:
            return 935.0 + arfcn * 0.2
        if arfcn == 0:
            return 935.0
    elif band == "DCS-1800":
        if 512 <= arfcn <= 885:
            return 1805.2 + (arfcn - 512) * 0.2
    elif band == "PCS-1900":
        if 512 <= arfcn <= 810:
            return 1930.2 + (arfcn - 512) * 0.2
    elif band == "GSM-850":
        if 128 <= arfcn <= 251:
            return 869.2 + (arfcn - 128) * 0.2
    return 0.0


@dataclass
class GSMCell:
    """Detected GSM cell."""
    arfcn: int = 0
    freq_mhz: float = 0.0
    band: str = ""
    mcc: str = ""
    mnc: str = ""
    lac: int = 0
    cell_id: int = 0
    bsic: str = ""
    power_dbm: float = -120.0
    neighbors: list[int] = field(default_factory=list)


@dataclass
class CaptureResult:
    """GSM capture session result."""
    cells: list[GSMCell] = field(default_factory=list)
    band_scanned: str = ""
    bursts_captured: int = 0
    frames_decoded: int = 0


class GnuradioGSMBridge(Exploit):
    """GNURadio GSM signal analysis bridge."""

    __info__: dict[str, Any] = {
        "name": "GNURadio GSM Bridge",
        "description": (
            "Passive GSM signal capture and decoding via gr-gsm. "
            "Tunes SDR to GSM ARFCN, captures bursts, decodes BCCH/CCCH, "
            "extracts cell parameters and feeds to Wireshark."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/ptrkrysik/gr-gsm",
            "https://osmocom.org/projects/gr-gsm/wiki",
        ),
        "devices": ("GSM BTS", "GSM-900", "DCS-1800", "PCS-1900", "GSM-850"),
        "severity": "medium",
        "cvss": "5.3",
        "cve": "generic",
        "mitre": ["T1040"],
    }

    band = OptString("GSM-900", "GSM band: GSM-900, DCS-1800, PCS-1900, GSM-850")
    arfcn = OptInteger(0, "Specific ARFCN to tune (0 = scan all)")
    sdr_device = OptString("rtl=0", "SDR device argument (rtl=0, uhd, hackrf, etc.)")
    gain_db = OptInteger(30, "RX gain in dB")
    ppm = OptInteger(0, "Frequency correction in PPM")
    scan_duration_sec = OptInteger(15, "Scan duration per ARFCN in seconds")
    wireshark_udp = OptBool(True, "Forward decoded frames to Wireshark via UDP")
    wireshark_port = OptInteger(4729, "UDP port for GSMTAP (Wireshark)")
    output_file = OptString("gsm_scan_results.json", "Output JSON file")
    cfile_path = OptString("", "Path to captured .cfile for offline analysis")
    dry_run = OptBool(False, "Print commands without executing")

    def __init__(self) -> None:
        super().__init__()
        self._results: CaptureResult = CaptureResult()

    def check(self) -> str:
        """Verify gr-gsm and SDR tools."""
        tools: dict[str, bool] = {}
        for tool in ["grgsm_scanner", "grgsm_livemon", "grgsm_decode", "SoapySDRUtil"]:
            tools[tool] = shutil.which(tool) is not None

        gr_gsm_tools = [t for t, found in tools.items() if found and t.startswith("grgsm")]
        if not gr_gsm_tools:
            return "gr-gsm not found. Install: apt install gr-gsm or build from github.com/ptrkrysik/gr-gsm"

        if tools.get("SoapySDRUtil"):
            try:
                result = subprocess.run(
                    ["SoapySDRUtil", "--find"],
                    capture_output=True, text=True, timeout=10,
                )
                if "No devices found" in result.stdout:
                    return f"gr-gsm available ({', '.join(gr_gsm_tools)}) but no SDR hardware"
                return f"gr-gsm and SDR ready: {', '.join(gr_gsm_tools)}"
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return f"gr-gsm tools: {', '.join(gr_gsm_tools)}"

    def _scan_band(self) -> list[GSMCell]:
        """Scan entire band for active GSM cells using grgsm_scanner."""
        band_name = str(self.band.value).strip()
        print_status(f"[*] Scanning {band_name} for active cells...")

        cmd = [
            "grgsm_scanner",
            "--band", band_name,
            "--args", str(self.sdr_device.value),
            "--gain", str(self.gain_db.value),
            "--ppm", str(self.ppm.value),
        ]

        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return []

        cells: list[GSMCell] = []
        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=120,
            )
            for line in result.stdout.splitlines():
                arfcn_match = re.search(r"ARFCN:\s*(\d+)", line)
                freq_match = re.search(r"Freq:\s*([\d.]+)", line)
                power_match = re.search(r"([-\d.]+)\s*dBm", line)

                if arfcn_match:
                    cell = GSMCell(
                        arfcn=int(arfcn_match.group(1)),
                        band=band_name,
                    )
                    if freq_match:
                        cell.freq_mhz = float(freq_match.group(1))
                    else:
                        cell.freq_mhz = arfcn_to_freq(cell.arfcn, band_name)
                    if power_match:
                        cell.power_dbm = float(power_match.group(1))

                    mcc_match = re.search(r"MCC:\s*(\d+)", line)
                    mnc_match = re.search(r"MNC:\s*(\d+)", line)
                    lac_match = re.search(r"LAC:\s*(\d+)", line)
                    cid_match = re.search(r"CID:\s*(\d+)", line)

                    if mcc_match:
                        cell.mcc = mcc_match.group(1)
                    if mnc_match:
                        cell.mnc = mnc_match.group(1)
                    if lac_match:
                        cell.lac = int(lac_match.group(1))
                    if cid_match:
                        cell.cell_id = int(cid_match.group(1))

                    cells.append(cell)

            print_success(f"[+] Found {len(cells)} active cells")

        except subprocess.TimeoutExpired:
            print_warning("[!] Scanner timed out (120s)")
        except FileNotFoundError:
            print_error("[-] grgsm_scanner not found")

        return cells

    def _capture_arfcn(self, arfcn: int) -> GSMCell | None:
        """Capture and decode traffic on a specific ARFCN."""
        band_name = str(self.band.value).strip()
        freq = arfcn_to_freq(arfcn, band_name)
        if freq == 0.0:
            print_error(f"[-] Invalid ARFCN {arfcn} for band {band_name}")
            return None

        duration = int(self.scan_duration_sec.value)
        print_status(f"[*] Capturing ARFCN {arfcn} ({freq:.1f} MHz) for {duration}s...")

        cmd = [
            "grgsm_livemon",
            "--args", str(self.sdr_device.value),
            "-f", f"{freq}M",
            "--gain", str(self.gain_db.value),
            "--ppm", str(self.ppm.value),
        ]

        if self.wireshark_udp.value:
            cmd.extend(["--serverport", str(self.wireshark_port.value)])

        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return GSMCell(arfcn=arfcn, freq_mhz=freq, band=band_name)

        cell = GSMCell(arfcn=arfcn, freq_mhz=freq, band=band_name)

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

            if stdout:
                self._results.bursts_captured += stdout.count("burst")

                for line in stdout.splitlines():
                    if "MCC" in line:
                        m = re.search(r"MCC:\s*(\d+)", line)
                        if m:
                            cell.mcc = m.group(1)
                    if "MNC" in line:
                        m = re.search(r"MNC:\s*(\d+)", line)
                        if m:
                            cell.mnc = m.group(1)
                    if "LAC" in line:
                        m = re.search(r"LAC:\s*(\d+)", line)
                        if m:
                            cell.lac = int(m.group(1))
                    if "Cell ID" in line or "CID" in line:
                        m = re.search(r"(?:Cell ID|CID):\s*(\d+)", line)
                        if m:
                            cell.cell_id = int(m.group(1))

        except FileNotFoundError:
            print_error("[-] grgsm_livemon not found")
            return None
        except OSError as exc:
            print_error(f"[-] Capture failed: {exc}")
            return None

        return cell

    def _decode_cfile(self) -> list[GSMCell]:
        """Decode a previously captured .cfile for offline analysis."""
        cfile = Path(str(self.cfile_path.value).strip())
        if not cfile.exists():
            print_error(f"[-] Capture file not found: {cfile}")
            return []

        print_status(f"[*] Decoding offline capture: {cfile}")
        arfcn_val = int(self.arfcn.value) if int(self.arfcn.value) > 0 else 100
        band_name = str(self.band.value).strip()
        freq = arfcn_to_freq(arfcn_val, band_name)

        cmd = [
            "grgsm_decode",
            "-c", str(cfile),
            "-f", f"{freq}M",
            "-a", str(arfcn_val),
        ]

        if self.wireshark_udp.value:
            cmd.extend(["-p", str(self.wireshark_port.value)])

        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return []

        cells: list[GSMCell] = []
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
            )
            cell = GSMCell(arfcn=arfcn_val, freq_mhz=freq, band=band_name)
            for line in result.stdout.splitlines():
                m_mcc = re.search(r"MCC:\s*(\d+)", line)
                m_mnc = re.search(r"MNC:\s*(\d+)", line)
                if m_mcc:
                    cell.mcc = m_mcc.group(1)
                if m_mnc:
                    cell.mnc = m_mnc.group(1)

            if cell.mcc or cell.mnc:
                cells.append(cell)
                print_success(f"[+] Decoded cell: MCC={cell.mcc} MNC={cell.mnc}")

        except subprocess.TimeoutExpired:
            print_warning("[!] Decode timed out")
        except FileNotFoundError:
            print_error("[-] grgsm_decode not found")

        return cells

    def _export_results(self) -> None:
        """Export scan results to JSON."""
        output_path = Path(str(self.output_file.value))
        data = {
            "band": self._results.band_scanned,
            "cells_found": len(self._results.cells),
            "bursts_captured": self._results.bursts_captured,
            "cells": [
                {
                    "arfcn": c.arfcn,
                    "freq_mhz": c.freq_mhz,
                    "band": c.band,
                    "power_dbm": c.power_dbm,
                    "plmn": f"{c.mcc}/{c.mnc}" if c.mcc else "",
                    "lac": c.lac,
                    "cell_id": c.cell_id,
                    "bsic": c.bsic,
                }
                for c in self._results.cells
            ],
        }
        output_path.write_text(json.dumps(data, indent=2))
        print_success(f"[+] Results saved to {output_path}")

    def run(self) -> None:
        """Execute GSM signal analysis."""
        band_name = str(self.band.value).strip()
        print_status(f"[*] GNURadio GSM Bridge v1.0.0 | Band {band_name}")

        if self.wireshark_udp.value:
            print_info(f"[*] GSMTAP forwarding to UDP port {self.wireshark_port.value}")
            print_info("[*] Open Wireshark with: wireshark -k -f 'udp port 4729'")

        self._results = CaptureResult(band_scanned=band_name)

        cfile_str = str(self.cfile_path.value).strip()
        if cfile_str:
            cells = self._decode_cfile()
            self._results.cells.extend(cells)
        elif int(self.arfcn.value) > 0:
            cell = self._capture_arfcn(int(self.arfcn.value))
            if cell:
                self._results.cells.append(cell)
        else:
            cells = self._scan_band()
            self._results.cells.extend(cells)

            top_cells = sorted(cells, key=lambda c: c.power_dbm, reverse=True)[:3]
            for cell in top_cells:
                detailed = self._capture_arfcn(cell.arfcn)
                if detailed:
                    if detailed.mcc:
                        cell.mcc = detailed.mcc
                    if detailed.mnc:
                        cell.mnc = detailed.mnc
                    if detailed.lac:
                        cell.lac = detailed.lac
                    if detailed.cell_id:
                        cell.cell_id = detailed.cell_id

        print_status(f"\n[*] Scan complete: {len(self._results.cells)} cells")
        for cell in self._results.cells:
            plmn = f" PLMN={cell.mcc}/{cell.mnc}" if cell.mcc else ""
            lac_cid = f" LAC={cell.lac} CID={cell.cell_id}" if cell.lac else ""
            print_info(
                f"    ARFCN={cell.arfcn:4d} | {cell.freq_mhz:8.1f} MHz | "
                f"{cell.power_dbm:6.1f} dBm{plmn}{lac_cid}"
            )

        if self._results.cells:
            self._export_results()
