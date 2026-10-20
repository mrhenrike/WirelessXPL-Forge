"""Shared fixtures for WirelessXPL-Forge test suite."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
def project_root() -> Path:
    """Return the repository root directory."""
    return ROOT


@pytest.fixture()
def mock_interface() -> str:
    """Return a fake wireless interface name for unit tests."""
    return "wlan0test"


@pytest.fixture()
def mock_bssid() -> str:
    """Return a deterministic fake BSSID."""
    return "AA:BB:CC:DD:EE:FF"


@pytest.fixture()
def mock_scapy_sendp(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Patch scapy.all.sendp to prevent real packet transmission."""
    mock = MagicMock()
    try:
        import scapy.all
        monkeypatch.setattr(scapy.all, "sendp", mock)
    except (ImportError, AttributeError):
        pass
    return mock


@pytest.fixture()
def mock_scapy_sniff(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Patch scapy.all.sniff to prevent real capture."""
    mock = MagicMock(return_value=[])
    try:
        import scapy.all
        monkeypatch.setattr(scapy.all, "sniff", mock)
    except (ImportError, AttributeError):
        pass
    return mock


@pytest.fixture()
def sample_pcap_bytes() -> bytes:
    """Minimal valid pcap file header (empty capture)."""
    import struct
    magic = 0xA1B2C3D4
    header = struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
    return header


@pytest.fixture()
def tmp_capture_dir(tmp_path: Path) -> Path:
    """Temporary directory for capture file output."""
    d = tmp_path / "captures"
    d.mkdir()
    return d
