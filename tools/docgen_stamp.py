#!/usr/bin/env python3
"""Deterministic metadata for generated docs (CI / cross-platform safe).

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def repo_label(repo_root: Path) -> str:
    """Short repo directory name (no absolute machine paths)."""

    return repo_root.name or "."


def modules_tree_stamp(repo_root: Path) -> str:
    """Short git object id for ``wirelessxpl/modules`` at HEAD.

    Stable across machines for the same commit and avoids self-referential
    timestamps that change on every new commit that touches the catalog file.
    """

    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD:wirelessxpl/modules"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        out = (completed.stdout or "").strip()
        if completed.returncode == 0 and len(out) >= 12:
            return out[:12]
    except OSError:
        pass
    return "unknown"


def generation_iso_timestamp(repo_root: Path) -> str:
    """ISO timestamp for non-catalog use; prefer :func:`modules_tree_stamp` for docs."""

    try:
        completed = subprocess.run(
            ["git", "log", "-1", "--format=%ct"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        out = (completed.stdout or "").strip()
        if completed.returncode == 0 and out.isdigit():
            ts = int(out)
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except OSError:
        pass
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if epoch and epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()
