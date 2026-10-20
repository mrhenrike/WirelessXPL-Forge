"""Unit tests for Phase 2 vendor CVE modules (Gates 6a, 6b, 6c).

Tests verify that each module:
  - Can be imported without errors
  - Has the Exploit class with required metadata (__info__)
  - Has check() and run() methods
  - Has correct CVE, CVSS, and severity in __info__
  - Does not contain em-dash or en-dash characters
"""
import importlib
import inspect
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Module registry: (module_path, cve_id, cvss, severity)
# ---------------------------------------------------------------------------
VENDOR_CVE_MODULES = [
    # Gate 6a: Cisco + Ubiquiti
    (
        "wirelessxpl.modules.generic.access_points.cisco.catalyst9800_jwt_rce_cve_2025_20188",
        "CVE-2025-20188",
        "10.0",
        "CRITICAL",
    ),
    (
        "wirelessxpl.modules.generic.access_points.ubiquiti.unifi_connect_cmdi_cve_2026_50746",
        "CVE-2026-50746",
        "10.0",
        "CRITICAL",
    ),
    (
        "wirelessxpl.modules.generic.access_points.ubiquiti.unifi_access_cmdi_cve_2026_50748",
        "CVE-2026-50748",
        "9.9",
        "CRITICAL",
    ),
    (
        "wirelessxpl.modules.generic.access_points.ubiquiti.unifi_os_rce_chain_cve_2026_34908",
        "CVE-2026-34908",
        "9.8",
        "CRITICAL",
    ),
    # Gate 6b: MikroTik + D-Link
    (
        "wirelessxpl.modules.generic.access_points.mikrotik.routeros_preauth_rce_cve_2026_84411",
        "CVE-2026-84411",
        "9.8",
        "CRITICAL",
    ),
    (
        "wirelessxpl.modules.generic.access_points.dlink.dwr_m961_rce_cve_2026_71956",
        "CVE-2026-71956",
        "9.8",
        "CRITICAL",
    ),
    (
        "wirelessxpl.modules.generic.access_points.dlink.dwr_m961_ping_rce_cve_2026_71946",
        "CVE-2026-71946",
        "9.8",
        "CRITICAL",
    ),
    (
        "wirelessxpl.modules.generic.access_points.dlink.dwr_m961_l2tp_cmdi_cve_2026_71954",
        "CVE-2026-71954",
        "9.8",
        "CRITICAL",
    ),
    (
        "wirelessxpl.modules.generic.access_points.dlink.dsl_dns_cmdi_cve_2026_0625",
        "CVE-2026-0625",
        "9.3",
        "CRITICAL",
    ),
    # Gate 6c: Android ADB
    (
        "wirelessxpl.modules.generic.mobile.android.adb_wireless_rce_cve_2026_0073",
        "CVE-2026-0073",
        "9.8",
        "CRITICAL",
    ),
]


@pytest.fixture(params=VENDOR_CVE_MODULES, ids=lambda m: m[1])
def module_spec(request):
    """Parametrized fixture returning (module, cve, cvss, severity)."""
    mod_path, cve, cvss, severity = request.param
    mod = importlib.import_module(mod_path)
    return mod, cve, cvss, severity


class TestVendorCVEModuleStructure:
    """Structural tests for all vendor CVE modules."""

    def test_import_clean(self, module_spec) -> None:
        """Module imports without raising exceptions."""
        mod, _, _, _ = module_spec
        assert mod is not None

    def test_has_exploit_class(self, module_spec) -> None:
        """Module exports an Exploit class."""
        mod, _, _, _ = module_spec
        assert hasattr(mod, "Exploit"), f"{mod.__name__} missing Exploit class"
        assert inspect.isclass(mod.Exploit)

    def test_has_info_dict(self, module_spec) -> None:
        """Exploit class has __info__ metadata (via metaclass mangling)."""
        mod, _, _, _ = module_spec
        cls = mod.Exploit
        # The ExploitOptionsAggregator metaclass renames __info__ to _ClassName__info__
        info = None
        for attr in dir(cls):
            if attr.endswith("__info__"):
                info = getattr(cls, attr)
                break
        assert info is not None, f"{cls.__name__} missing __info__"
        assert isinstance(info, dict)
        assert "name" in info
        assert "description" in info

    def test_cve_in_info(self, module_spec) -> None:
        """The CVE ID appears in __info__."""
        mod, cve, _, _ = module_spec
        cls = mod.Exploit
        info = None
        for attr in dir(cls):
            if attr.endswith("__info__"):
                info = getattr(cls, attr)
                break
        assert info is not None
        # Check cve field or name/description
        cve_value = info.get("cve", "")
        name_value = info.get("name", "")
        desc_value = info.get("description", "")
        combined = f"{cve_value} {name_value} {desc_value}"
        assert cve in combined, f"{cve} not found in module info"

    def test_cvss_in_info(self, module_spec) -> None:
        """The CVSS score is present in __info__."""
        mod, _, cvss, _ = module_spec
        cls = mod.Exploit
        info = None
        for attr in dir(cls):
            if attr.endswith("__info__"):
                info = getattr(cls, attr)
                break
        assert info is not None
        assert info.get("cvss") == cvss

    def test_severity_in_info(self, module_spec) -> None:
        """The severity rating is present in __info__."""
        mod, _, _, severity = module_spec
        cls = mod.Exploit
        info = None
        for attr in dir(cls):
            if attr.endswith("__info__"):
                info = getattr(cls, attr)
                break
        assert info is not None
        assert info.get("severity") == severity

    def test_has_check_method(self, module_spec) -> None:
        """Exploit class has a check() method."""
        mod, _, _, _ = module_spec
        cls = mod.Exploit
        assert hasattr(cls, "check"), f"{cls.__name__} missing check()"
        assert callable(cls.check)

    def test_has_run_method(self, module_spec) -> None:
        """Exploit class has a run() method."""
        mod, _, _, _ = module_spec
        cls = mod.Exploit
        assert hasattr(cls, "run"), f"{cls.__name__} missing run()"
        assert callable(cls.run)

    def test_has_all_export(self, module_spec) -> None:
        """Module defines __all__ with Exploit."""
        mod, _, _, _ = module_spec
        assert hasattr(mod, "__all__"), f"{mod.__name__} missing __all__"
        assert "Exploit" in mod.__all__

    def test_no_em_dash(self, module_spec) -> None:
        """Module source must not contain em-dash or en-dash."""
        mod, _, _, _ = module_spec
        source_file = inspect.getfile(mod)
        content = pathlib.Path(source_file).read_text(encoding="utf-8")
        assert "—" not in content, "em-dash found in source"
        assert "–" not in content, "en-dash found in source"

    def test_no_ai_mention(self, module_spec) -> None:
        """Module source must not mention AI/LLM tools."""
        mod, _, _, _ = module_spec
        source_file = inspect.getfile(mod)
        content = pathlib.Path(source_file).read_text(encoding="utf-8").lower()
        forbidden = ["claude", "anthropic", "copilot", "chatgpt", "openai"]
        for term in forbidden:
            assert term not in content, f"AI mention '{term}' found in source"

    def test_has_mitre_techniques(self, module_spec) -> None:
        """Module __info__ includes MITRE ATT&CK technique IDs."""
        mod, _, _, _ = module_spec
        cls = mod.Exploit
        info = None
        for attr in dir(cls):
            if attr.endswith("__info__"):
                info = getattr(cls, attr)
                break
        assert info is not None
        techniques = info.get("mitre_techniques", [])
        assert len(techniques) > 0, "No MITRE techniques defined"
        for t in techniques:
            assert t.startswith("T"), f"Invalid technique ID: {t}"
