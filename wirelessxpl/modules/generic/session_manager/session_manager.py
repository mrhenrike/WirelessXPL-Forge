"""WiFi Assessment Session Manager.

Save and resume WiFi security testing sessions. Tracks discovered networks,
performed attacks, captured handshakes, and recovered credentials.

Adapted from: salli94/gandalf-the-white (session_logger.py + findings_store.py)
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AssessmentSession:
    """Metadata for a WiFi security assessment session.

    Attributes:
        name: Human-readable session name.
        session_id: Unique session identifier.
        created_at: ISO-8601 creation timestamp.
        networks: List of discovered network dicts.
        attacks: List of attack event dicts.
        captures: List of capture file dicts.
        credentials: List of recovered credential dicts.
        notes: List of analyst note strings.
    """

    name: str
    session_id: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    networks: List[Dict] = field(default_factory=list)
    attacks: List[Dict] = field(default_factory=list)
    captures: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


class SessionManager:
    """WiFi assessment session persistence manager.

    Saves and loads sessions from SQLite, allowing pause/resume of
    long-duration security assessments.

    Usage:
        mgr = SessionManager(db_path=".tmp/sessions.db")
        mgr.create_session("office_pentest_2026")
        mgr.add_network("office_pentest_2026", {"ssid": "OfficeWiFi", "bssid": "AA:BB:CC:DD:EE:FF"})
        mgr.add_credential("office_pentest_2026", {"ssid": "OfficeWiFi", "password": "secret"})
        mgr.export_session("office_pentest_2026", ".tmp/reports/")

    Attributes:
        __info__: Module metadata.
    """

    __info__ = {
        "name": "WiFi Assessment Session Manager",
        "category": "management",
        "adapted_from": "salli94/gandalf-the-white session_logger",
    }

    def __init__(self, db_path: str = ".tmp/sessions.db") -> None:
        """Initialize the session manager.

        Args:
            db_path: Path to SQLite database for session storage.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT,
                    data_json TEXT DEFAULT '{}'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT REFERENCES sessions(session_id),
                    kind TEXT,
                    timestamp TEXT,
                    payload_json TEXT
                )
            """)
            conn.commit()

    def create_session(self, name: str, session_id: Optional[str] = None) -> AssessmentSession:
        """Create a new session.

        Args:
            name: Human-readable session name.
            session_id: Optional custom ID. Auto-generated from timestamp if None.

        Returns:
            New AssessmentSession.

        Raises:
            ValueError: If session_id already exists.
        """
        if session_id is None:
            session_id = f"{name}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

        session = AssessmentSession(name=name, session_id=session_id)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO sessions (session_id, name, created_at, data_json) VALUES (?, ?, ?, ?)",
                (session_id, name, session.created_at, "{}"),
            )
            conn.commit()
        return session

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all saved sessions.

        Returns:
            List of session metadata dicts.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT session_id, name, created_at FROM sessions ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def _add_event(self, session_id: str, kind: str, payload: Dict) -> None:
        """Add an event record to a session.

        Args:
            session_id: Target session.
            kind: Event type (network, attack, capture, credential, note).
            payload: Event data dict.
        """
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO events (session_id, kind, timestamp, payload_json) VALUES (?, ?, ?, ?)",
                (session_id, kind, now, json.dumps(payload)),
            )
            conn.commit()

    def add_network(self, session_id: str, network: Dict) -> None:
        """Record a discovered network in the session.

        Args:
            session_id: Target session.
            network: Network info dict (ssid, bssid, security, etc.).
        """
        self._add_event(session_id, "network", network)

    def add_attack(self, session_id: str, attack: Dict) -> None:
        """Record an attack attempt in the session.

        Args:
            session_id: Target session.
            attack: Attack info dict (type, target, outcome, etc.).
        """
        self._add_event(session_id, "attack", attack)

    def add_capture(self, session_id: str, capture: Dict) -> None:
        """Record a captured file in the session.

        Args:
            session_id: Target session.
            capture: Capture info dict (ssid, bssid, file_path, type).
        """
        self._add_event(session_id, "capture", capture)

    def add_credential(self, session_id: str, credential: Dict) -> None:
        """Record a recovered credential in the session.

        Args:
            session_id: Target session.
            credential: Credential dict (ssid, password, method).
        """
        self._add_event(session_id, "credential", credential)

    def add_note(self, session_id: str, note: str) -> None:
        """Add an analyst note to the session.

        Args:
            session_id: Target session.
            note: Note text.
        """
        self._add_event(session_id, "note", {"text": note})

    def load_session(self, session_id: str) -> Optional[AssessmentSession]:
        """Load a session with all its events.

        Args:
            session_id: Session to load.

        Returns:
            AssessmentSession or None if not found.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if not row:
                return None

            session = AssessmentSession(
                name=row["name"],
                session_id=row["session_id"],
                created_at=row["created_at"],
            )

            events = conn.execute(
                "SELECT kind, payload_json FROM events WHERE session_id = ? ORDER BY id",
                (session_id,),
            ).fetchall()

        for event in events:
            kind = event["kind"]
            payload = json.loads(event["payload_json"])
            if kind == "network":
                session.networks.append(payload)
            elif kind == "attack":
                session.attacks.append(payload)
            elif kind == "capture":
                session.captures.append(payload)
            elif kind == "credential":
                session.credentials.append(payload)
            elif kind == "note":
                session.notes.append(payload.get("text", ""))

        return session

    def export_session(self, session_id: str, output_dir: str) -> Dict[str, str]:
        """Export a session to JSON and HTML report.

        Args:
            session_id: Session to export.
            output_dir: Directory for output files.

        Returns:
            Dict with paths to created files.
        """
        session = self.load_session(session_id)
        if not session:
            return {"error": f"Session {session_id} not found"}

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # JSON export
        json_path = out / f"{session_id}.json"
        json_path.write_text(
            json.dumps(asdict(session), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        # Simple HTML report
        html_path = out / f"{session_id}.html"
        cred_rows = ""
        for c in session.credentials:
            cred_rows += f"<tr><td>{c.get('ssid', '')}</td><td>****</td><td>{c.get('method', '')}</td></tr>"

        net_rows = ""
        for n in session.networks:
            net_rows += (
                f"<tr><td>{n.get('ssid', '')}</td><td>{n.get('bssid', '')}</td>"
                f"<td>{n.get('security', '')}</td><td>{n.get('rssi_dbm', '')}</td></tr>"
            )

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Session Report - {session.name}</title>
<style>
body{{font-family:sans-serif;background:#1a1a2e;color:#eee;margin:2em}}
h1,h2{{color:#4ecca3}} table{{border-collapse:collapse;width:100%;margin:1em 0}}
th{{background:#0f3460;color:#4ecca3;padding:.5em;text-align:left}}
td{{border:1px solid #333;padding:.5em}} tr:nth-child(even){{background:#16213e}}
</style></head><body>
<h1>WiFi Assessment Report</h1>
<p><b>Session:</b> {session.name} | <b>Created:</b> {session.created_at[:19]} UTC</p>
<h2>Networks ({len(session.networks)})</h2>
<table><thead><tr><th>SSID</th><th>BSSID</th><th>Security</th><th>RSSI</th></tr></thead>
<tbody>{net_rows}</tbody></table>
<h2>Credentials Recovered ({len(session.credentials)})</h2>
<table><thead><tr><th>SSID</th><th>Credential</th><th>Method</th></tr></thead>
<tbody>{cred_rows}</tbody></table>
<h2>Notes ({len(session.notes)})</h2>
<ul>{''.join(f'<li>{n}</li>' for n in session.notes)}</ul>
</body></html>"""

        html_path.write_text(html, encoding="utf-8")

        return {"json": str(json_path), "html": str(html_path)}

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all its events.

        Args:
            session_id: Session to delete.

        Returns:
            True if deleted, False if not found.
        """
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "DELETE FROM events WHERE session_id = ?", (session_id,)
            ).rowcount
            conn.execute(
                "DELETE FROM sessions WHERE session_id = ?", (session_id,)
            )
            conn.commit()
        return count > 0
