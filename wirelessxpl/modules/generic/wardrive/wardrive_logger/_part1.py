"""Wardrive Logger - GPS-tagged WiFi network discovery logger.

Records discovered WiFi networks with optional GPS coordinates and exports
to CSV, JSON, and KML formats for map visualization.

GPS source priority:
  1. gpsd daemon (via gpsd-py3 or gps3 library)
  2. NMEA file/serial port
  3. Graceful fallback to lat=None, lon=None

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""


import csv
import json
import logging
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import datetime, timezone, UTC
from pathlib import Path
from typing import Optional
from collections.abc import Callable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# GPS Backends
# ---------------------------------------------------------------------------

class _GpsPosition:
    """Current GPS fix container."""

    __slots__ = ("alt", "fix", "lat", "lon", "speed", "track", "ts")

    def __init__(self) -> None:
        self.lat: float | None = None
        self.lon: float | None = None
        self.alt: float | None = None
        self.speed: float | None = None
        self.track: float | None = None
        self.ts: str | None = None
        self.fix: bool = False

    def copy(self) -> _GpsPosition:
        p = _GpsPosition()
        p.lat = self.lat
        p.lon = self.lon
        p.alt = self.alt
        p.speed = self.speed
        p.track = self.track
        p.ts = self.ts
        p.fix = self.fix
        return p


class _GpsdBackend:
    """Non-blocking gpsd reader thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 2947) -> None:
        self._host = host
        self._port = port
        self._pos = _GpsPosition()
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        """Attempt to start the gpsd reader thread.

        Returns:
            True if the library is available and the thread started.
        """
        try:
            import gpsd  # type: ignore
            gpsd.connect(host=self._host, port=self._port)
            self._running = True
            self._thread = threading.Thread(target=self._poll, args=(gpsd,), daemon=True)
            self._thread.start()
            logger.info("[Wardrive] gpsd backend started (%s:%d)", self._host, self._port)
            return True
        except ImportError:
            logger.debug("[Wardrive] gpsd-py3 not installed, gpsd backend unavailable")
        except Exception as exc:
            logger.debug("[Wardrive] gpsd connection failed: %s", exc)
        return False

    def _poll(self, gpsd: object) -> None:
        while self._running:
            try:
                packet = gpsd.get_current()  # type: ignore[attr-defined]
                if hasattr(packet, "lat") and packet.lat is not None:
                    with self._lock:
                        self._pos.lat = packet.lat
                        self._pos.lon = packet.lon
                        self._pos.alt = getattr(packet, "alt", None)
                        self._pos.speed = getattr(packet, "hspeed", None)
                        self._pos.track = getattr(packet, "track", None)
                        self._pos.ts = datetime.now(UTC).isoformat()
                        self._pos.fix = True
            except Exception:
                pass
            time.sleep(1)

    def position(self) -> _GpsPosition:
        with self._lock:
            return self._pos.copy()

    def stop(self) -> None:
        self._running = False


class _NmeaBackend:
    """NMEA sentence file/serial reader."""

    def __init__(self, source: str) -> None:
        self._source = source
        self._pos = _GpsPosition()
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        src = Path(self._source)
        if not src.exists():
            # Try as serial port path on Linux
            try:
                import serial  # type: ignore
                self._serial = serial.Serial(self._source, 9600, timeout=1)
                self._running = True
                self._thread = threading.Thread(target=self._read_serial, daemon=True)
                self._thread.start()
                logger.info("[Wardrive] NMEA serial backend started (%s)", self._source)
                return True
            except Exception as exc:
                logger.debug("[Wardrive] NMEA serial failed: %s", exc)
                return False

        self._running = True
        self._thread = threading.Thread(target=self._read_file, daemon=True)
        self._thread.start()
        logger.info("[Wardrive] NMEA file backend started (%s)", self._source)
        return True

    def _parse_gga(self, sentence: str) -> None:
        parts = sentence.split(",")
        if len(parts) < 9:
            return
        try:
            lat_raw = parts[2]
            lat_dir = parts[3]
            lon_raw = parts[4]
            lon_dir = parts[5]
            fix_quality = int(parts[6]) if parts[6] else 0
            if fix_quality == 0 or not lat_raw or not lon_raw:
                return

            def _deg(raw: str, direction: str) -> float:
                d = int(float(raw) // 100)
                m = float(raw) - d * 100
                deg = d + m / 60.0
                if direction in ("S", "W"):
                    deg = -deg
                return deg

            with self._lock:
                self._pos.lat = _deg(lat_raw, lat_dir)
                self._pos.lon = _deg(lon_raw, lon_dir)
                self._pos.alt = float(parts[9]) if parts[9] else None
                self._pos.ts = datetime.now(UTC).isoformat()
                self._pos.fix = True
        except (ValueError, IndexError):
            pass

    def _read_file(self) -> None:
        with suppress(Exception), open(self._source, errors="ignore") as fh:
            for line in fh:
                if not self._running:
                    break
                line = line.strip()
                if line.startswith("$GPGGA") or line.startswith("$GNGGA"):
                    self._parse_gga(line)

    def _read_serial(self) -> None:
        while self._running:
            with suppress(Exception):
                line = self._serial.readline().decode("ascii", errors="ignore").strip()
                if line.startswith("$GPGGA") or line.startswith("$GNGGA"):
                    self._parse_gga(line)

    def position(self) -> _GpsPosition:
        with self._lock:
            return self._pos.copy()

    def stop(self) -> None:
        self._running = False


# ---------------------------------------------------------------------------
# Network record
# ---------------------------------------------------------------------------

@dataclass
class WardriveSighting:
    """A single wardrive observation of a WiFi network."""
    ssid: str
    bssid: str
    channel: int
    rssi: int
    security: str
    timestamp: str
    latitude: float | None = None
    longitude: float | None = None
    altitude: float | None = None
    speed: float | None = None
    vendor: str | None = None
    band: str = ""
    hidden: bool = False


# ---------------------------------------------------------------------------
# OUI vendor lookup (top 20 prefixes)
# ---------------------------------------------------------------------------

_OUI_TABLE: dict[str, str] = {
    "00:1A:2B": "Cisco", "00:25:00": "Cisco",
    "30:B5:C2": "TP-Link", "50:C7:BF": "TP-Link", "EC:08:6B": "TP-Link",
    "00:1D:7E": "D-Link", "1C:7E:E5": "D-Link",
    "20:CF:30": "ASUS", "F8:32:E4": "ASUS",
    "00:14:BF": "Linksys", "00:18:F8": "Netgear",
    "20:0C:C8": "Netgear", "E4:F4:C6": "Netgear",
    "7C:61:66": "Huawei", "00:E0:FC": "Huawei",
    "C8:3A:35": "Tenda", "88:C6:26": "Google",
    "00:26:BB": "Apple", "3C:07:54": "Apple",
    "00:17:F2": "Apple",
}


def _resolve_vendor(bssid: str) -> str | None:
    prefix = bssid[:8].upper()
    return _OUI_TABLE.get(prefix)


def _channel_to_band(channel: int) -> str:
    if channel <= 14:
        return "2.4 GHz"
    if channel < 133:
        return "5 GHz"
    return "6 GHz"


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

