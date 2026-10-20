#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Passive GSM IMSI catcher using gr-gsm and RTL-SDR.

Passively captures IMSI/TMSI/IMEI from GSM broadcast channels (BCCH) using
Software Defined Radio hardware. Combines grgsm_livemon, grgsm_scanner,
and Oros42 simple_IMSI-catcher.py in an integrated pipeline.

Supported hardware: RTL-SDR, HackRF, BladeRF, USRP.

Requires: gr-gsm, GNU Radio, simple_IMSI-catcher.py (Oros42).

Version: 1.0.0
"""


import csv
import json
import logging
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import time
from typing import Any, Dict, List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.sim._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


def _which(binary: str) -> str | None:
    return shutil.which(binary)


def _check_sdr_hardware() -> bool:
    """Verify RTL-SDR hardware is accessible via rtl_test."""
    rtl = _which("rtl_test")
    if not rtl:
        return False
    try:
        result = subprocess.run(
            [rtl, "-t"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
        )
        output = result.stdout.decode("utf-8", errors="replace")
        return "Found" in output or result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _parse_scanner_output(raw: str) -> list[dict[str, Any]]:
    """Parse grgsm_scanner output into a list of frequency records.

    Each line from grgsm_scanner typically looks like:
        ARFCN:   14, Freq:  940.8M, CID:  6015, LAC:  1234, MCC: 724, MNC:  10, Pwr: -45.3
    """
    results: list[dict[str, Any]] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        record: dict[str, Any] = {}
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


def _parse_imsi_captures(capture_dir: str) -> list[dict[str, str]]:
    """Parse IMSI captures from SQLite or plain-text output files."""
    records: list[dict[str, str]] = []

    for fname in os.listdir(capture_dir):
        fpath = os.path.join(capture_dir, fname)

        if fname.endswith(".db") or fname.endswith(".sqlite"):
            try:
                conn = sqlite3.connect(fpath)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='imsi'"
                )
                if cursor.fetchone():
                    cursor.execute("SELECT * FROM imsi")
                    cols = [desc[0] for desc in cursor.description]
                    for row in cursor.fetchall():
                        records.append(dict(zip(cols, [str(v) for v in row], strict=False)))
                conn.close()
            except (sqlite3.Error, OSError) as exc:
                logger.warning("Failed to read %s: %s", fpath, exc)

        elif fname.endswith(".txt") or fname.endswith(".log"):
            try:
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        imsi_match = re.search(r"\b(\d{15})\b", line)
                        if imsi_match:
                            entry: dict[str, str] = {"imsi": imsi_match.group(1)}
                            tmsi_match = re.search(
                                r"TMSI[:\s]*(0x[0-9a-fA-F]+|\d+)", line
                            )
                            if tmsi_match:
                                entry["tmsi"] = tmsi_match.group(1)
                            records.append(entry)
            except OSError as exc:
                logger.warning("Failed to read %s: %s", fpath, exc)

    return records


