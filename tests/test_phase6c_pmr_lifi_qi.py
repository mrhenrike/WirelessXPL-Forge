"""Unit tests for Phase 6C PMR, Li-Fi and Qi exploit modules."""
import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_PHASE6C_MODULES = [
    "wirelessxpl.modules.generic.pmr.tetra_burst_tea1_backdoor",
    "wirelessxpl.modules.generic.pmr.tetra_passive_sniff",
    "wirelessxpl.modules.generic.pmr.dmr_sniffing",
    "wirelessxpl.modules.generic.pmr.p25_eavesdrop_jam",
    "wirelessxpl.modules.generic.pmr.p25_radio_inhibit_dos",
    "wirelessxpl.modules.generic.lifi.lifi_injection_modulated_led",
    "wirelessxpl.modules.generic.lifi.lifi_jamming_light_flood",
    "wirelessxpl.modules.generic.lifi.lifi_wall_leakage_eavesdrop",
    "wirelessxpl.modules.generic.qi.voltschemer_overheating",
    "wirelessxpl.modules.generic.qi.voltschemer_voice_injection",
]

_PHASE6C_IDS = [
    ("wirelessxpl.modules.generic.pmr.tetra_burst_tea1_backdoor", "TETRA"),
    ("wirelessxpl.modules.generic.pmr.tetra_passive_sniff", "TETRA"),
    ("wirelessxpl.modules.generic.pmr.dmr_sniffing", "DMR"),
    ("wirelessxpl.modules.generic.pmr.p25_eavesdrop_jam", "P25"),
    ("wirelessxpl.modules.generic.pmr.p25_radio_inhibit_dos", "P25"),
    ("wirelessxpl.modules.generic.lifi.lifi_injection_modulated_led", "Li-Fi"),
    ("wirelessxpl.modules.generic.lifi.lifi_jamming_light_flood", "Li-Fi"),
    ("wirelessxpl.modules.generic.lifi.lifi_wall_leakage_eavesdrop", "Li-Fi"),
    ("wirelessxpl.modules.generic.qi.voltschemer_overheating", "VoltSchemer"),
    ("wirelessxpl.modules.generic.qi.voltschemer_voice_injection", "VoltSchemer"),
]


class TestPhase6CModuleImports:
    """Verify all Phase 6C PMR/Li-Fi/Qi modules import without error."""

    @pytest.mark.parametrize("module_path", _PHASE6C_MODULES)
    def test_module_imports(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert hasattr(mod, "Exploit")

    @pytest.mark.parametrize("module_path", _PHASE6C_MODULES)
    def test_exploit_has_required_methods(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "check")
        assert hasattr(instance, "run")
        assert callable(instance.check)
        assert callable(instance.run)

    @pytest.mark.parametrize("module_path", _PHASE6C_MODULES)
    def test_exploit_has_exploit_attributes(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        assert hasattr(cls, "exploit_attributes")
        attrs = cls.exploit_attributes
        assert isinstance(attrs, dict)

    @pytest.mark.parametrize("module_path", _PHASE6C_MODULES)
    def test_exploit_has_info_dict(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert "name" in info
        assert "description" in info
        assert "authors" in info
        assert "references" in info

    @pytest.mark.parametrize("module_path,expected_id", _PHASE6C_IDS)
    def test_class_info_contains_identifier(self, module_path: str, expected_id: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert expected_id in info.get("name", ""), (
            f"{expected_id} not found in __info__['name'] for {module_path}"
        )

    @pytest.mark.parametrize("module_path", _PHASE6C_MODULES)
    def test_run_no_crash_with_defaults(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        instance.run()
