"""WirelessXPL Operational Database.

Extends EmbedXPL XplDatabase base for WirelessXPL-specific usage.
Stored at ~/.wirelessxpl/wxf.db

Usage::

    from wirelessxpl.core.database import WxfDatabase

    db = WxfDatabase()
    db.workspace("pentest-x")
    db.add_host("192.168.1.1")
    db.add_vuln("192.168.1.1", module_path="wirelessxpl...", cve_ids=["CVE-..."])
    db.add_cred("192.168.1.1", "admin", "admin")
    db.stats()

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

from pathlib import Path

# XplDatabase base from EmbedXPL (shared infrastructure)
try:
    from embedxpl.core.database import XplDatabase
except ImportError:
    # Fallback: re-implement minimal base if EmbedXPL not installed
    import sys
    _SUITE = Path(__file__).resolve().parents[5]
    if str(_SUITE / "EmbedXPL-Forge") not in sys.path:
        sys.path.insert(0, str(_SUITE / "EmbedXPL-Forge"))
    from embedxpl.core.database import XplDatabase


class WxfDatabase(XplDatabase):
    """WirelessXPL operational database stored at ~/.wirelessxpl/wxf.db.

    Domain: WiFi, BLE, LoRaWAN, drones, Sub-GHz, UWB
    """

    _DB_DIR  = Path.home() / ".wirelessxpl"
    _DB_FILE = "wxf.db"
    _TOOL    = "WirelessXPL"
