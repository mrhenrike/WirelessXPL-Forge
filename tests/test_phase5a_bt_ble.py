"""Unit tests for Phase 5A Bluetooth/BLE exploit modules."""
import importlib
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_PHASE5A_MODULES = [
    "wirelessxpl.modules.generic.bluetooth.zephyr_l2cap_overflow_cve_2026_5068",
    "wirelessxpl.modules.generic.bluetooth.linux_bnep_uaf_cve_2026_64178",
    "wirelessxpl.modules.generic.bluetooth.linux_hci_sync_uaf_cve_2026_68393",
    "wirelessxpl.modules.generic.bluetooth.linux_rfcomm_mcc_oob_cve_2026_53254",
    "wirelessxpl.modules.generic.bluetooth.linux_ssp_passkey_uaf_cve_2026_46056",
    "wirelessxpl.modules.generic.bluetooth.apple_bt_dos_cve_2026_20650",
    "wirelessxpl.modules.generic.bluetooth.pebble_ble_missing_auth_cve_2025_69969",
    "wirelessxpl.modules.generic.bluetooth.realtek_ble_ll_length_dos_cve_2025_44526",
    "wirelessxpl.modules.generic.bluetooth.ti_ble_ll_length_dos_cve_2025_44525",
    "wirelessxpl.modules.generic.bluetooth.mousejack_nrf24_hid",
]

_PHASE5A_IDS = [
    ("wirelessxpl.modules.generic.bluetooth.zephyr_l2cap_overflow_cve_2026_5068", "CVE-2026-5068"),
    ("wirelessxpl.modules.generic.bluetooth.linux_bnep_uaf_cve_2026_64178", "CVE-2026-64178"),
    ("wirelessxpl.modules.generic.bluetooth.linux_hci_sync_uaf_cve_2026_68393", "CVE-2026-68393"),
    ("wirelessxpl.modules.generic.bluetooth.linux_rfcomm_mcc_oob_cve_2026_53254", "CVE-2026-53254"),
    ("wirelessxpl.modules.generic.bluetooth.linux_ssp_passkey_uaf_cve_2026_46056", "CVE-2026-46056"),
    ("wirelessxpl.modules.generic.bluetooth.apple_bt_dos_cve_2026_20650", "CVE-2026-20650"),
    ("wirelessxpl.modules.generic.bluetooth.pebble_ble_missing_auth_cve_2025_69969", "CVE-2025-69969"),
    ("wirelessxpl.modules.generic.bluetooth.realtek_ble_ll_length_dos_cve_2025_44526", "CVE-2025-44526"),
    ("wirelessxpl.modules.generic.bluetooth.ti_ble_ll_length_dos_cve_2025_44525", "CVE-2025-44525"),
    ("wirelessxpl.modules.generic.bluetooth.mousejack_nrf24_hid", "MouseJack"),
]


class TestPhase5AModuleImports:
    """Verify all Phase 5A Bluetooth/BLE modules import without error."""

    @pytest.mark.parametrize("module_path", _PHASE5A_MODULES)
    def test_module_imports(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert hasattr(mod, "Exploit")

    @pytest.mark.parametrize("module_path", _PHASE5A_MODULES)
    def test_exploit_has_required_methods(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "check")
        assert hasattr(instance, "run")
        assert callable(instance.check)
        assert callable(instance.run)

    @pytest.mark.parametrize("module_path", _PHASE5A_MODULES)
    def test_exploit_has_exploit_attributes(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        assert hasattr(cls, "exploit_attributes")
        attrs = cls.exploit_attributes
        assert isinstance(attrs, dict)

    @pytest.mark.parametrize("module_path", _PHASE5A_MODULES)
    def test_exploit_has_info_dict(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert "name" in info
        assert "description" in info
        assert "authors" in info
        assert "references" in info

    @pytest.mark.parametrize("module_path,expected_id", _PHASE5A_IDS)
    def test_class_info_contains_identifier(self, module_path: str, expected_id: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert expected_id in info.get("name", ""), (
            f"{expected_id} not found in __info__['name'] for {module_path}"
        )

    @pytest.mark.parametrize("module_path", _PHASE5A_MODULES)
    def test_check_returns_false_on_socket_error(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        with patch("socket.socket", side_effect=OSError):
            assert instance.check() is False

    @pytest.mark.parametrize("module_path", _PHASE5A_MODULES)
    def test_run_no_crash_with_defaults(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        instance.run()
