"""OUI/Vendor lookup with in-memory cache.

Resolves MAC address prefixes to manufacturer names using
IEEE OUI database (24-bit OUI, 28-bit MA-M, 36-bit MA-S).

Conceptual reference: airgorah vendors.rs (MIT, martin-olivier)
Recode: full Python rewrite, no code copied.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import csv
import logging
import re
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

_OUI_DB: Dict[str, str] = {}
_LOADED = False

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]?){5}[0-9A-Fa-f]{2}$")

_BUNDLED_OUI_PATH = Path(__file__).parent.parent / "resources" / "oui.csv"


def _normalize_mac(mac: str) -> str:
    return re.sub(r"[:\-\.]", "", mac.upper())[:12]


def _load_ieee_oui(path: Optional[str] = None) -> None:
    global _OUI_DB, _LOADED

    if _LOADED:
        return

    oui_path = Path(path) if path else _BUNDLED_OUI_PATH

    if not oui_path.exists():
        logger.warning("OUI database not found at %s", oui_path)
        _LOADED = True
        return

    try:
        with open(oui_path, encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if len(row) >= 2:
                    prefix = row[0].strip().upper().replace(":", "").replace("-", "")
                    vendor = row[1].strip()
                    if prefix and vendor:
                        _OUI_DB[prefix] = vendor
        logger.info("Loaded %d OUI entries from %s", len(_OUI_DB), oui_path)
    except Exception as exc:
        logger.error("Failed to load OUI database: %s", exc)

    _LOADED = True


def resolve(mac: str, oui_path: Optional[str] = None) -> Optional[str]:
    """Resolve a MAC address to its manufacturer/vendor name.

    Checks MA-S (36-bit), MA-M (28-bit), then OUI-24 (24-bit) prefixes.

    Args:
        mac: MAC address (any common format).
        oui_path: Optional path to OUI CSV database.

    Returns:
        Vendor name or None if not found.
    """
    _load_ieee_oui(oui_path)

    normalized = _normalize_mac(mac)
    if len(normalized) < 6:
        return None

    for prefix_len in (9, 7, 6):
        prefix = normalized[:prefix_len]
        vendor = _OUI_DB.get(prefix)
        if vendor:
            return vendor

    return None


def resolve_batch(macs: list[str], oui_path: Optional[str] = None) -> Dict[str, Optional[str]]:
    """Resolve multiple MAC addresses to vendors.

    Args:
        macs: List of MAC addresses.
        oui_path: Optional OUI CSV path.

    Returns:
        Dict mapping each MAC to its vendor (or None).
    """
    _load_ieee_oui(oui_path)
    return {mac: resolve(mac) for mac in macs}


def is_valid_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac))


def get_oui_prefix(mac: str) -> str:
    normalized = _normalize_mac(mac)
    return normalized[:6]


def db_size() -> int:
    _load_ieee_oui()
    return len(_OUI_DB)
