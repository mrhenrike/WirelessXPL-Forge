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


def generation_iso_timestamp(repo_root: Path) -> str:
    """ISO timestamp stable for a given git revision.

    Uses the latest commit author date so regenerated files match on Linux,
    macOS and Windows for the same checkout. Falls back to SOURCE_DATE_EPOCH
    or wall clock when git is unavailable.
    """

    try:
        completed = subprocess.run(
            ["git", "log", "-1", "--format=%cI"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if completed.returncode == 0 and (completed.stdout or "").strip():
            return (completed.stdout or "").strip()
    except OSError:
        pass
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if epoch and epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()
