"""Unit tests for Phase 6B TEMPEST and SATCOM exploit modules."""
import importlib
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_PHASE6B_MODULES = [
    "wirelessxpl.modules.generic.tempest.tempestsdr_hdmi_eavesdrop",
    "wirelessxpl.modules.generic.tempest.deep_tempest_hdmi_dl",
    "wirelessxpl.modules.generic.tempest.gr_tempest_gnuradio",
    "wirelessxpl.modules.generic.tempest.em_eye_camera_emanation",
    "wirelessxpl.modules.generic.tempest.cable_keyboard_emanation",
    "wirelessxpl.modules.generic.satcom.acidrain_satcom_wiper",
    "wirelessxpl.modules.generic.satcom.vsat_terminal_exploit",
    "wirelessxpl.modules.generic.satcom.cobham_vsat7090_vuln",
]

_PHASE6B_IDS = [
    ("wirelessxpl.modules.generic.tempest.tempestsdr_hdmi_eavesdrop", "TempestSDR"),
    ("wirelessxpl.modules.generic.tempest.deep_tempest_hdmi_dl", "Deep-Tempest"),
    ("wirelessxpl.modules.generic.tempest.gr_tempest_gnuradio", "gr-tempest"),
    ("wirelessxpl.modules.generic.tempest.em_eye_camera_emanation", "EM Eye"),
    ("wirelessxpl.modules.generic.tempest.cable_keyboard_emanation", "Keyboard"),
    ("wirelessxpl.modules.generic.satcom.acidrain_satcom_wiper", "AcidRain"),
    ("wirelessxpl.modules.generic.satcom.vsat_terminal_exploit", "VSAT"),
    ("wirelessxpl.modules.generic.satcom.cobham_vsat7090_vuln", "Cobham"),
]


class TestPhase6BModuleImports:
    """Verify all Phase 6B TEMPEST/SATCOM modules import without error."""

    @pytest.mark.parametrize("module_path", _PHASE6B_MODULES)
    def test_module_imports(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert hasattr(mod, "Exploit")

    @pytest.mark.parametrize("module_path", _PHASE6B_MODULES)
    def test_exploit_has_required_methods(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "check")
        assert hasattr(instance, "run")
        assert callable(instance.check)
        assert callable(instance.run)

    @pytest.mark.parametrize("module_path", _PHASE6B_MODULES)
    def test_exploit_has_exploit_attributes(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        assert hasattr(cls, "exploit_attributes")
        attrs = cls.exploit_attributes
        assert isinstance(attrs, dict)

    @pytest.mark.parametrize("module_path", _PHASE6B_MODULES)
    def test_exploit_has_info_dict(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert "name" in info
        assert "description" in info
        assert "authors" in info
        assert "references" in info

    @pytest.mark.parametrize("module_path,expected_id", _PHASE6B_IDS)
    def test_class_info_contains_identifier(self, module_path: str, expected_id: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert expected_id in info.get("name", ""), (
            f"{expected_id} not found in __info__['name'] for {module_path}"
        )

    @pytest.mark.parametrize("module_path", [
        m for m in _PHASE6B_MODULES
        if "vsat_terminal" in m or "cobham" in m
    ])
    def test_check_returns_false_on_socket_error(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        with patch("socket.socket", side_effect=OSError):
            assert instance.check() is False

    @pytest.mark.parametrize("module_path", _PHASE6B_MODULES)
    def test_run_no_crash_with_defaults(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        instance.run()
