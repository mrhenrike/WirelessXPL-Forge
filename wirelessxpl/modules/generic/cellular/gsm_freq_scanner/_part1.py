#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""GSM frequency scanner using Kalibrate-rtl and gr-gsm.

Scans for active GSM base stations across standard frequency bands, identifies
ARFCN, frequency, signal strength, MCC, MNC, LAC, and Cell ID. Supports both
kalibrate-rtl (kal) and grgsm_scanner backends.

Supported bands: GSM900, GSM1800, GSM850, PCS1900.
Supported hardware: RTL-SDR, HackRF, BladeRF, USRP.

Requires: kalibrate-rtl (kal) and/or gr-gsm (grgsm_scanner).

Version: 1.0.0
"""


import csv
import json
import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.sim._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

# GSM band definitions: (name, downlink_start_MHz, downlink_end_MHz, arfcn_start, arfcn_end)
_GSM_BANDS: dict[str, dict[str, Any]] = {
    "GSM900": {
        "dl_start": 935.0,
        "dl_end": 960.0,
        "ul_start": 890.0,
        "ul_end": 915.0,
        "arfcn_start": 1,
        "arfcn_end": 124,
        "offset": 45.0,
        "description": "GSM900 (P-GSM): 890-915 UL, 935-960 DL",
    },
    "GSM1800": {
        "dl_start": 1805.0,
        "dl_end": 1880.0,
        "ul_start": 1710.0,
        "ul_end": 1785.0,
        "arfcn_start": 512,
        "arfcn_end": 885,
        "offset": 95.0,
        "description": "DCS1800: 1710-1785 UL, 1805-1880 DL",
    },
    "GSM850": {
        "dl_start": 869.0,
        "dl_end": 894.0,
        "ul_start": 824.0,
        "ul_end": 849.0,
        "arfcn_start": 128,
        "arfcn_end": 251,
        "offset": 45.0,
        "description": "GSM850: 824-849 UL, 869-894 DL",
    },
    "PCS1900": {
        "dl_start": 1930.0,
        "dl_end": 1990.0,
        "ul_start": 1850.0,
        "ul_end": 1910.0,
        "arfcn_start": 512,
        "arfcn_end": 810,
        "offset": 80.0,
        "description": "PCS1900: 1850-1910 UL, 1930-1990 DL",
    },
}


def _which(binary: str) -> str | None:
    return shutil.which(binary)


def _arfcn_to_freq_dl(arfcn: int, band: str) -> float:
    """Convert ARFCN to downlink frequency (MHz).

    Args:
        arfcn: Absolute Radio Frequency Channel Number.
        band: Band name (GSM900, GSM1800, GSM850, PCS1900).

    Returns:
        Downlink frequency in MHz, or 0.0 if invalid.
    """
    if band == "GSM900":
        if 1 <= arfcn <= 124:
            return 935.0 + 0.2 * (arfcn - 1)
        if arfcn == 0:
            return 935.0
    elif band == "GSM1800":
        if 512 <= arfcn <= 885:
            return 1805.2 + 0.2 * (arfcn - 512)
    elif band == "GSM850":
        if 128 <= arfcn <= 251:
            return 869.2 + 0.2 * (arfcn - 128)
    elif band == "PCS1900":
        if 512 <= arfcn <= 810:
            return 1930.2 + 0.2 * (arfcn - 512)
    return 0.0


def _freq_to_arfcn(freq_mhz: float, band: str) -> int:
    """Convert downlink frequency (MHz) to ARFCN.

    Args:
        freq_mhz: Downlink frequency in MHz.
        band: Band name.

    Returns:
        ARFCN number, or -1 if out of range.
    """
    if band == "GSM900":
        if 935.0 <= freq_mhz <= 960.0:
            return round((freq_mhz - 935.0) / 0.2) + 1
    elif band == "GSM1800":
        if 1805.0 <= freq_mhz <= 1880.0:
            return round((freq_mhz - 1805.2) / 0.2) + 512
    elif band == "GSM850":
        if 869.0 <= freq_mhz <= 894.0:
            return round((freq_mhz - 869.2) / 0.2) + 128
    elif band == "PCS1900":
        if 1930.0 <= freq_mhz <= 1990.0:
            return round((freq_mhz - 1930.2) / 0.2) + 512
    return -1


def _parse_kal_output(raw: str) -> list[dict[str, Any]]:
    """Parse kalibrate-rtl (kal) scan output.

    Typical kal output line:
        chan: 14 (940.8MHz + 12.517kHz)  power: 338862.72
    """
    results: list[dict[str, Any]] = []
    for line in raw.strip().splitlines():
        match = re.match(
            r"\s*chan:\s*(\d+)\s*\(([\d.]+)MHz\s*[+\-]\s*([\d.]+)kHz\)\s*power:\s*([\d.]+)",
            line,
        )
        if match:
            results.append({
                "arfcn": int(match.group(1)),
                "frequency": float(match.group(2)),
                "offset_khz": float(match.group(3)),
                "power": float(match.group(4)),
                "source": "kalibrate-rtl",
            })
    results.sort(key=lambda r: r.get("power", 0), reverse=True)
    return results


def _parse_grgsm_output(raw: str) -> list[dict[str, Any]]:
    """Parse grgsm_scanner output."""
    results: list[dict[str, Any]] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        record: dict[str, Any] = {"source": "grgsm_scanner"}
        arfcn_match = re.search(r"ARFCN:\s*(\d+)", line)
        freq_match = re.search(r"Freq:\s*([\d.]+)M", line, re.IGNORECASE)
        pwr_match = re.search(r"Pwr:\s*([-\d.]+)", line)
        cid_match = re.search(r"CID:\s*(\d+)", line)
        lac_match = re.search(r"LAC:\s*(\d+)", line)
        mcc_match = re.search(r"MCC:\s*(\d+)", line)
        mnc_match = re.search(r"MNC:\s*(\d+)", line)

        if freq_match:
            record["arfcn"] = int(arfcn_match.group(1)) if arfcn_match else 0
            record["frequency"] = float(freq_match.group(1))
            record["power"] = float(pwr_match.group(1)) if pwr_match else 0.0
            record["cid"] = int(cid_match.group(1)) if cid_match else 0
            record["lac"] = int(lac_match.group(1)) if lac_match else 0
            record["mcc"] = int(mcc_match.group(1)) if mcc_match else 0
            record["mnc"] = int(mnc_match.group(1)) if mnc_match else 0
            results.append(record)

    results.sort(key=lambda r: r.get("power", 0), reverse=True)
    return results


