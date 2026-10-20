"""Session Manager - persistent WiFi pentest session management.

Saves and restores pentest sessions including discovered networks,
executed attacks, captured handshakes, and recovered credentials.
Backed by SQLite with JSON export per session.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""


import json
import logging
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone, UTC
from pathlib import Path
from typing import Any, Optional
from collections.abc import Generator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain records
# ---------------------------------------------------------------------------

@dataclass
class AttackRecord:
    """A recorded attack attempt within a session."""
    attack_type: str
    target_ssid: str
    target_bssid: str
    outcome: str
    timestamp: str = ""
    tool: str | None = None
    notes: str | None = None

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(UTC).isoformat()


@dataclass
class SessionInfo:
    """Lightweight session summary returned by list_sessions()."""
    session_id: str
    name: str
    created_at: str
    updated_at: str
    network_count: int
    attack_count: int
    capture_count: int
    credential_count: int
    notes: str | None = None


# ---------------------------------------------------------------------------
# Session Manager
# ---------------------------------------------------------------------------

