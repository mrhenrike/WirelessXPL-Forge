"""Version consistency checks for WirelessXPL-Forge."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    assert m is not None
    return m.group(1)


def test_version_is_semver() -> None:
    v = _pyproject_version()
    assert re.fullmatch(r"\d+\.\d+\.\d+", v), f"Not semver: {v!r}"


def test_module_version_matches_pyproject() -> None:
    from wirelessxpl import __version__
    assert __version__ == _pyproject_version()


def test_docs_version_matches_pyproject() -> None:
    v = _pyproject_version()
    for doc in [ROOT / "docs/wiki/en-US/00-about.md", ROOT / "docs/wiki/pt-BR/00-sobre.md"]:
        if doc.exists():
            text = doc.read_text(encoding="utf-8")
            assert v in text, f"{doc.name}: version {v!r} not found"
