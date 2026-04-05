"""Resolve superproject wireless-research submodule checkout status.

Reads ``wireless_research_submodules.json`` and tests path presence relative to
``WXF_SUPERPROJECT_ROOT`` (or an explicit option).

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

from wirelessxpl.core.exploit import *


def _wirelessxpl_package_root() -> Path:
    """Return the ``wirelessxpl/`` package directory."""

    return Path(__file__).resolve().parents[3]


def _load_catalog() -> List[Dict[str, Any]]:
    """Load embedded submodule catalog JSON."""

    path = _wirelessxpl_package_root() / "resources" / "catalogs" / "wireless_research_submodules.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return list(data.get("entries") or [])


def _resolve_superproject_root(candidate: str) -> Path:
    """Pick first existing root: option, env, then heuristic cwd walk."""

    if candidate.strip():
        p = Path(candidate).expanduser().resolve()
        if p.is_dir():
            return p
    env = os.environ.get("WXF_SUPERPROJECT_ROOT", "").strip()
    if env:
        p = Path(env).expanduser().resolve()
        if p.is_dir():
            return p
    cur = Path.cwd().resolve()
    for base in (cur, *cur.parents):
        if (base / "submodules" / "IoT" / "wireless-research").is_dir():
            return base
    return cur


class Exploit(Exploit):
    """Show which vendored research trees are present on disk."""

    __info__ = {
        "name": "Wireless research ecosystem (submodule) status",
        "description": "Maps GitHub WPA3/Wi-Fi research submodules to on-disk paths "
                       "under the SafeLabs-style superproject layout.",
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://wpa3.mathyvanhoef.com/",
            "https://github.com/jabbaw0nky/DragonShift",
        ),
        "devices": ("Workstation with superproject checkout",),
    }

    superproject_root = OptString(
        "",
        "Root of monorepo (or set WXF_SUPERPROJECT_ROOT); empty = auto-detect",
    )
    tag_filter = OptString(
        "",
        "If non-empty, only entries whose tags contain this substring (case-insensitive)",
    )

    def run(self) -> None:
        root = _resolve_superproject_root(str(self.superproject_root))
        print_status("Superproject root: {}".format(root))
        rows = _load_catalog()
        if not rows:
            print_error("Catalog wireless_research_submodules.json missing or invalid.")
            return
        filt = str(self.tag_filter).strip().lower()
        ok = 0
        shown = 0
        for row in rows:
            tags = [str(t).lower() for t in (row.get("tags") or ())]
            if filt and not any(filt in t for t in tags):
                continue
            shown += 1
            rel = row.get("path") or ""
            p = (root / rel).resolve()
            exists = p.is_dir() and any(p.iterdir()) if p.is_dir() else False
            if exists:
                ok += 1
                print_success("{} → {} [{}]".format(row.get("slug"), p, ", ".join(row.get("tags") or [])))
            else:
                print_error("{} — missing or empty: {}".format(row.get("slug"), p))
            note = row.get("notes")
            if note:
                print_status("  note: {}".format(note))
        if shown == 0:
            print_error("No catalog entries matched tag_filter.")
            return
        print_status("Present: {}/{} entries (after tag filter).".format(ok, shown))
