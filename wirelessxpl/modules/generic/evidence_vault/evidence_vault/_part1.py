"""Evidence Vault - hash-chained tamper-evident audit ledger for WiFi pentest.

Stores WiFi pentest artifacts in a forensically defensible chain compatible
with ISO/IEC 27037 chain-of-custody requirements.

Each record includes a SHA-256 Merkle-style chain: any modification to a past
record breaks the chain, which verify_chain() detects.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""


import csv
import hashlib
import html
import json
import logging
import sqlite3
import tarfile
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone, UTC
from pathlib import Path
from typing import Any, Optional
from collections.abc import Generator

logger = logging.getLogger(__name__)

_GENESIS = "0" * 64


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_of(obj: dict[str, Any]) -> str:
    """Return deterministic SHA-256 hex digest of a JSON-serialisable dict."""
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Domain objects
# ---------------------------------------------------------------------------

@dataclass
class CaptureRecord:
    """A captured handshake or PCAP file."""
    ssid: str
    bssid: str
    filepath: str
    capture_type: str = "hc22000"
    channel: int | None = None
    rssi: int | None = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = _now_iso()


@dataclass
class CredentialRecord:
    """A recovered WiFi credential."""
    ssid: str
    password: str
    bssid: str | None = None
    method: str = "handshake"
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = _now_iso()


@dataclass
class NetworkRecord:
    """A discovered WiFi network."""
    ssid: str
    bssid: str
    security: str
    channel: int
    rssi: int
    vendor: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = _now_iso()


# ---------------------------------------------------------------------------
# Evidence Vault
# ---------------------------------------------------------------------------

