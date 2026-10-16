"""Project structure smoke tests for WirelessXPL-Forge."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "pyproject.toml",
    "LICENSE",
    "third_party_manifest.json",
    "wirelessxpl/__init__.py",
    "wirelessxpl/__main__.py",
]

REQUIRED_DIRS = [
    "wirelessxpl/core",
    "tests",
]


def test_required_files_present() -> None:
    for rel in REQUIRED_FILES:
        p = ROOT / rel
        assert p.exists(), f"Required file missing: {rel}"


def test_required_dirs_present() -> None:
    for rel in REQUIRED_DIRS:
        p = ROOT / rel
        assert p.is_dir(), f"Required directory missing: {rel}"


def test_pyproject_has_version() -> None:
    import re
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'(?m)^version\s*=\s*"[^"]+"', text)


def test_license_not_empty() -> None:
    lic = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert len(lic.strip()) > 50
