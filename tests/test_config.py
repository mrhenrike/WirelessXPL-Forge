"""Tests for wirelessxpl.core.config - WXFConfig, parse_timing, interface helpers."""

import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wirelessxpl.core.config import (
    TIMING_BY_NAME,
    TIMING_PROFILES,
    IfaceInfo,
    WXFConfig,
    _is_internal,
    parse_timing,
)

# ---------------------------------------------------------------------------
# parse_timing
# ---------------------------------------------------------------------------

def test_parse_timing_by_number() -> None:
    for n in range(6):
        result = parse_timing(str(n))
        assert result["level"] == n
        assert result["name"] == TIMING_PROFILES[str(n)]["name"]


def test_parse_timing_by_name() -> None:
    for name, key in TIMING_BY_NAME.items():
        result = parse_timing(name)
        assert result["level"] == int(key)


def test_parse_timing_t_prefix() -> None:
    result = parse_timing("T4")
    assert result["name"] == "aggressive"
    assert result["level"] == 4


def test_parse_timing_invalid_defaults_to_normal() -> None:
    result = parse_timing("xyz")
    assert result["level"] == 3
    assert result["name"] == "normal"


def test_parse_timing_case_insensitive() -> None:
    result = parse_timing("INSANE")
    assert result["level"] == 5


# ---------------------------------------------------------------------------
# TIMING_PROFILES structure
# ---------------------------------------------------------------------------

def test_timing_profiles_all_have_required_keys() -> None:
    required = {"name", "level", "scan_delay_ms", "timeout_ms", "retries"}
    for key, profile in TIMING_PROFILES.items():
        assert required.issubset(profile.keys()), f"Missing keys in T{key}"


def test_timing_delay_decreases_with_level() -> None:
    delays = [TIMING_PROFILES[str(i)]["scan_delay_ms"] for i in range(6)]
    for i in range(len(delays) - 1):
        assert delays[i] >= delays[i + 1]


# ---------------------------------------------------------------------------
# _is_internal
# ---------------------------------------------------------------------------

def test_is_internal_pcie_pattern() -> None:
    assert _is_internal("wlp3s0") is True
    assert _is_internal("wlp0s20f3") is True


def test_is_internal_wl0_wl1() -> None:
    assert _is_internal("wl0") is True
    assert _is_internal("wl1") is True


def test_is_internal_wlx_external() -> None:
    with mock.patch("os.path.realpath", return_value="/sys/devices/pci/usb1/1-2/net/wlx00"):
        assert _is_internal("wlx00112233aabb") is False


def test_is_internal_eth_not_internal() -> None:
    assert _is_internal("eth0") is False


# ---------------------------------------------------------------------------
# IfaceInfo dataclass
# ---------------------------------------------------------------------------

def test_iface_info_creation() -> None:
    info = IfaceInfo(name="wlx00", index=1, usb=True, monitor_cap=True,
                     current_mode="monitor", internet=False)
    assert info.name == "wlx00"
    assert info.usb is True
    assert info.monitor_cap is True
    assert info.internet is False


# ---------------------------------------------------------------------------
# WXFConfig singleton
# ---------------------------------------------------------------------------

def test_wxfconfig_defaults() -> None:
    cfg = WXFConfig()
    assert cfg.destructive is True
    assert cfg.simulate is False
    assert cfg.verbose is True
    assert cfg.reverse_port == 4444
    assert cfg.timing == "3"


def test_wxfconfig_set_timing() -> None:
    cfg = WXFConfig()
    cfg.set_timing("5")
    assert cfg.timing == "5"
    assert cfg.timing_name == "insane"
    assert cfg.scan_delay_ms == 0


def test_wxfconfig_set_timing_by_name() -> None:
    cfg = WXFConfig()
    cfg.set_timing("paranoid")
    assert cfg.timing == "0"
    assert cfg.timing_name == "paranoid"


def test_wxfconfig_timeout_ms() -> None:
    cfg = WXFConfig()
    cfg.set_timing("4")
    assert cfg.timeout_ms == 2000


def test_wxfconfig_select_ifaces_empty() -> None:
    cfg = WXFConfig()
    cfg.all_ext_ifaces = []
    assert cfg.select_ifaces("all") == []


def test_wxfconfig_select_ifaces_all() -> None:
    cfg = WXFConfig()
    cfg.all_ext_ifaces = [
        IfaceInfo("wlx01", 1, True, True, "managed", False),
        IfaceInfo("wlx02", 2, True, False, "managed", False),
    ]
    result = cfg.select_ifaces("all")
    assert result == ["wlx01", "wlx02"]


def test_wxfconfig_select_ifaces_by_index() -> None:
    cfg = WXFConfig()
    cfg.all_ext_ifaces = [
        IfaceInfo("wlx01", 1, True, True, "managed", False),
        IfaceInfo("wlx02", 2, True, False, "managed", False),
        IfaceInfo("wlx03", 3, True, False, "managed", False),
    ]
    assert cfg.select_ifaces("2") == ["wlx02"]
    assert cfg.select_ifaces("1,3") == ["wlx01", "wlx03"]


def test_wxfconfig_select_ifaces_by_range() -> None:
    cfg = WXFConfig()
    cfg.all_ext_ifaces = [
        IfaceInfo("wlx01", 1, True, True, "managed", False),
        IfaceInfo("wlx02", 2, True, False, "managed", False),
        IfaceInfo("wlx03", 3, True, False, "managed", False),
    ]
    assert cfg.select_ifaces("1-2") == ["wlx01", "wlx02"]


def test_wxfconfig_select_ifaces_by_name() -> None:
    cfg = WXFConfig()
    cfg.all_ext_ifaces = [
        IfaceInfo("wlx01", 1, True, True, "managed", False),
    ]
    assert cfg.select_ifaces("wlx01") == ["wlx01"]
    assert cfg.select_ifaces("wlxff") == []


def test_wxfconfig_needs_two_ifaces() -> None:
    cfg = WXFConfig()
    assert cfg.needs_two_ifaces("evil_twin_workflow") is True
    assert cfg.needs_two_ifaces("pmkid_autopwn") is True
    assert cfg.needs_two_ifaces("beacon_flood") is False


def test_wxfconfig_repr() -> None:
    cfg = WXFConfig()
    r = repr(cfg)
    assert "WXFConfig" in r
    assert "timing=T3" in r


def test_wxfconfig_reset_clears_singleton() -> None:
    WXFConfig._singleton = None
    with mock.patch("wirelessxpl.core.config._detect_external_ifaces", return_value=[]):
        cfg = WXFConfig.get()
        assert cfg.iface_mon == ""
        WXFConfig._singleton = None
