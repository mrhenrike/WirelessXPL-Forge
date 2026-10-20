"""Validate third_party_manifest.json for WirelessXPL-Forge."""


import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_manifest_present() -> None:
    assert (ROOT / "third_party_manifest.json").exists()


def test_manifest_valid_json() -> None:
    data = json.loads((ROOT / "third_party_manifest.json").read_text())
    assert isinstance(data, dict)


def test_manifest_has_components() -> None:
    data = json.loads((ROOT / "third_party_manifest.json").read_text())
    assert len(data.get("components", [])) >= 10


def test_manifest_schema_version() -> None:
    data = json.loads((ROOT / "third_party_manifest.json").read_text())
    assert "schema_version" in data
