#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""WiGLE CSV and KML export from WXF wardrive captures.

Converts wardrive data (airodump-ng CSV, kismetdb SQLite, PCAP) into
WiGLE upload format (WigleWifi-1.4) and KML for Google Earth visualization.

Supported input formats:
  - Airodump-ng CSV (.csv)
  - Kismetdb SQLite (.kismet)
  - PCAP with Beacon frames (basic extraction)

Supported output formats:
  - WiGLE CSV (WigleWifi-1.4 header format)
  - KML (Keyhole Markup Language for Google Earth)

Optional GPS enrichment from NMEA or GPX files.

Requires: Python 3.7+, sqlite3 (stdlib), csv (stdlib).

Version: 1.0.0
"""


import csv
import json
import logging
import os
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)

_WIGLE_HEADER = (
    "WigleWifi-1.4,"
    "appRelease=WirelessXPL-Forge,"
    "model=WXF,"
    "release=1.0.0,"
    "device=WXF,"
    "display=WXF,"
    "board=WXF,"
    "brand=UniaGeek"
)
_WIGLE_COLUMNS = [
    "MAC", "SSID", "AuthMode", "FirstSeen", "Channel",
    "RSSI", "CurrentLatitude", "CurrentLongitude",
    "AltitudeMeters", "AccuracyMeters", "Type",
]


def _sanitize_ssid(ssid: str) -> str:
    """Remove control characters and limit SSID length."""
    clean = re.sub(r"[\x00-\x1f\x7f]", "", ssid)
    return clean[:32]


def _parse_airodump_csv(filepath: str) -> list[dict[str, Any]]:
    """Parse airodump-ng CSV and extract AP records.

    Args:
        filepath: Path to airodump-ng CSV file.

    Returns:
        List of dicts with keys: bssid, ssid, channel, signal, encryption.
    """
    results: list[dict[str, Any]] = []
    in_ap_section = False

    with open(filepath, encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("BSSID") and "channel" in stripped.lower():
                in_ap_section = True
                continue
            if stripped.startswith("Station MAC"):
                in_ap_section = False
                continue
            if not in_ap_section:
                continue

            parts = [p.strip() for p in stripped.split(",")]
            if len(parts) < 14:
                continue

            bssid = parts[0].strip()
            if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                continue

            results.append({
                "bssid": bssid.upper(),
                "ssid": _sanitize_ssid(parts[13].strip() if len(parts) > 13 else ""),
                "channel": parts[3].strip(),
                "signal": parts[8].strip(),
                "encryption": parts[5].strip(),
                "first_seen": parts[1].strip(),
                "lat": "",
                "lon": "",
            })

    return results


def _parse_kismetdb(filepath: str) -> list[dict[str, Any]]:
    """Parse kismetdb (SQLite) and extract device records.

    Args:
        filepath: Path to .kismet database file.

    Returns:
        List of dicts with AP information.
    """
    results: list[dict[str, Any]] = []

    if not os.path.isfile(filepath):
        return results

    conn = None
    try:
        conn = sqlite3.connect(f"file:{filepath}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='devices'"
        )
        if not cursor.fetchone():
            return results

        cursor.execute(
            "SELECT devmac, type, device FROM devices WHERE type LIKE '%AP%' OR type LIKE '%Wi-Fi%'"
        )
        for row in cursor.fetchall():
            devmac = row["devmac"] if row["devmac"] else ""
            device_json_raw = row["device"] if row["device"] else "{}"
            try:
                dev = json.loads(device_json_raw)
            except (json.JSONDecodeError, TypeError):
                dev = {}

            ssid = ""
            channel = ""
            signal = ""
            encryption = ""
            lat = ""
            lon = ""

            if "kismet.device.base.name" in dev:
                ssid = _sanitize_ssid(str(dev["kismet.device.base.name"]))
            if "kismet.device.base.channel" in dev:
                channel = str(dev["kismet.device.base.channel"])
            if "kismet.device.base.signal" in dev:
                sig_data = dev["kismet.device.base.signal"]
                if isinstance(sig_data, dict):
                    signal = str(sig_data.get("kismet.common.signal.last_signal", ""))
                else:
                    signal = str(sig_data)

            loc = dev.get("kismet.device.base.location", {})
            if isinstance(loc, dict):
                avg = loc.get("kismet.common.location.avg_loc", {})
                if isinstance(avg, dict):
                    lat = str(avg.get("kismet.common.location.geopoint", [0, 0])[1])
                    lon = str(avg.get("kismet.common.location.geopoint", [0, 0])[0])

            crypt = dev.get("kismet.device.base.crypt", "")
            if isinstance(crypt, str):
                encryption = crypt

            results.append({
                "bssid": devmac.upper(),
                "ssid": ssid,
                "channel": channel,
                "signal": signal,
                "encryption": encryption,
                "first_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
                "lat": lat,
                "lon": lon,
            })
    except sqlite3.Error as exc:
        logger.error("kismetdb parse error: %s", exc)
    finally:
        if conn:
            conn.close()

    return results


def _parse_gps_file(filepath: str) -> list[dict[str, str]]:
    """Parse GPX or NMEA file to extract trackpoints.

    Args:
        filepath: Path to .gpx or .nmea file.

    Returns:
        List of dicts with lat/lon/time keys.
    """
    points: list[dict[str, str]] = []
    if not filepath or not os.path.isfile(filepath):
        return points

    if filepath.lower().endswith(".gpx"):
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            ns = {"gpx": "http://www.topografix.com/GPX/1/1"}
            for trkpt in root.iter("{http://www.topografix.com/GPX/1/1}trkpt"):
                lat = trkpt.get("lat", "")
                lon = trkpt.get("lon", "")
                if lat and lon:
                    points.append({"lat": lat, "lon": lon})
            if not points:
                for trkpt in root.iter("trkpt"):
                    lat = trkpt.get("lat", "")
                    lon = trkpt.get("lon", "")
                    if lat and lon:
                        points.append({"lat": lat, "lon": lon})
        except ET.ParseError as exc:
            logger.debug("GPX parse error: %s", exc)

    elif filepath.lower().endswith(".nmea") or filepath.lower().endswith(".txt"):
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("$GPGGA") or line.startswith("$GPRMC"):
                    parts = line.split(",")
                    if len(parts) >= 6 and parts[2] and parts[4]:
                        try:
                            lat_raw = float(parts[2])
                            lat_deg = int(lat_raw / 100) + (lat_raw % 100) / 60.0
                            if parts[3] == "S":
                                lat_deg = -lat_deg
                            lon_raw = float(parts[4])
                            lon_deg = int(lon_raw / 100) + (lon_raw % 100) / 60.0
                            if parts[5] == "W":
                                lon_deg = -lon_deg
                            points.append({
                                "lat": f"{lat_deg:.6f}",
                                "lon": f"{lon_deg:.6f}",
                            })
                        except (ValueError, IndexError):
                            continue

    return points


