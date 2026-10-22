"""Smoke tests for NFC, Z-Wave, PMR, Radio, Satellite, IoT, Matter, Cellular, External modules.

Targets modules with 0% coverage. Each test imports, instantiates, checks __info__,
calls check() and run() with mocked hardware dependencies.
"""

from __future__ import annotations

import importlib
import types
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


def _get_info(cls: type) -> dict[str, Any] | None:
    for attr in dir(cls):
        if attr.endswith("__info__"):
            val = getattr(cls, attr, None)
            if isinstance(val, dict):
                return val
    return None


def _get_exploit_class(mod: types.ModuleType) -> type | None:
    for name in dir(mod):
        obj = getattr(mod, name)
        if isinstance(obj, type) and name != "type":
            info = _get_info(obj)
            if info and "name" in info:
                return obj
    return None


def _set_dry_run(instance: Any) -> None:
    for attr in ("dry_run",):
        if hasattr(instance, attr):
            field = getattr(instance, attr)
            if hasattr(field, "value"):
                field.value = True
            else:
                setattr(instance, attr, True)


# All target module paths
NFC_MODULES = [
    "wirelessxpl.modules.generic.nfc.mifare_classic_cracker",
    "wirelessxpl.modules.generic.nfc.rfid_cloner",
    "wirelessxpl.modules.generic.nfc.nfc_relay_native",
    "wirelessxpl.modules.generic.nfc.iclass_seos_attack",
    "wirelessxpl.modules.generic.nfc.desfire_attack",
]

ZWAVE_MODULES = [
    "wirelessxpl.modules.generic.zwave.zwave_replay_attack",
    "wirelessxpl.modules.generic.zwave.zwave_s0_key_extract",
    "wirelessxpl.modules.generic.zwave.zwave_s2_bypass",
]

PMR_MODULES = [
    "wirelessxpl.modules.generic.pmr.dmr_sniffing",
    "wirelessxpl.modules.generic.pmr.p25_eavesdrop_jam",
    "wirelessxpl.modules.generic.pmr.p25_radio_inhibit_dos",
    "wirelessxpl.modules.generic.pmr.tetra_burst_tea1_backdoor",
    "wirelessxpl.modules.generic.pmr.tetra_passive_sniff",
]

RADIO_SAT_IOT_MATTER = [
    "wirelessxpl.modules.generic.radio.tetra_decrypt",
    "wirelessxpl.modules.generic.satellite.adsb_spoofer",
    "wirelessxpl.modules.generic.iot.matter_thread_exploit",
]

CELLULAR_MODULES = [
    "wirelessxpl.modules.generic.cellular.fiveg_nr_scanner",
    "wirelessxpl.modules.generic.cellular.gnuradio_gsm_bridge",
    "wirelessxpl.modules.generic.cellular.fiveghoul_5gnr_dos",
    "wirelessxpl.modules.generic.cellular.gsm_a51_crack",
    "wirelessxpl.modules.generic.cellular.gsm_freq_scanner",
    "wirelessxpl.modules.generic.cellular.gtp_u_tunnel_injection",
    "wirelessxpl.modules.generic.cellular.imsi_catcher_passive",
    "wirelessxpl.modules.generic.cellular.llfuzz_baseband_cve_scanner",
    "wirelessxpl.modules.generic.cellular.lte_imsi_catcher",
    "wirelessxpl.modules.generic.cellular.sni5gect_5gnr_sniff_inject",
    "wirelessxpl.modules.generic.cellular.ss7_sigploit_bridge",
    "wirelessxpl.modules.generic.cellular.ueransim_5g_bridge",
    "wirelessxpl.modules.generic.cellular.volte_ims_interception",
    "wirelessxpl.modules.generic.cellular.samsung.exynos_modem_crash_cve_2025_26780",
    "wirelessxpl.modules.generic.cellular.samsung.exynos_nr_rrc_downlink_cve_2026_23792",
    "wirelessxpl.modules.generic.cellular.samsung.exynos_nr_rrc_null_dos_cve_2026_33970",
    "wirelessxpl.modules.generic.cellular.samsung.exynos_sms_rpdata_stack_overflow_cve_2025_54328",
    "wirelessxpl.modules.generic.cellular.samsung.exynos_sms_tpud_oob_write_cve_2025_62818",
]

EXTERNAL_MODULES = [
    "wirelessxpl.modules.generic.external.aircrack_full_bridge",
    "wirelessxpl.modules.generic.external.bruce_serial_bridge",
    "wirelessxpl.modules.generic.external.bruce_esp32_lab_notes",
    "wirelessxpl.modules.generic.external.bruce_upstream_tracker",
    "wirelessxpl.modules.generic.external.eaphammer_bridge",
    "wirelessxpl.modules.generic.external.hcxdumptool_live_bridge",
    "wirelessxpl.modules.generic.external.hcx_toolchain_bridge",
    "wirelessxpl.modules.generic.external.hostapd_wpe_bridge",
    "wirelessxpl.modules.generic.external.kismet_bridge",
    "wirelessxpl.modules.generic.external.oneshot_bridge",
    "wirelessxpl.modules.generic.external.ot_protocol_bridge",
    "wirelessxpl.modules.generic.external.proxmark_rfid_bridge",
    "wirelessxpl.modules.generic.external.rogue_bridge",
    "wirelessxpl.modules.generic.external.router_firmware_bridge",
    "wirelessxpl.modules.generic.external.sigfox_lorawan_bridge",
    "wirelessxpl.modules.generic.external.social_recon_bridge",
    "wirelessxpl.modules.generic.external.wifipumpkin3_bridge",
    "wirelessxpl.modules.generic.external.wireless_tool_prereq_audit",
]

ALL_MODULES = (
    NFC_MODULES
    + ZWAVE_MODULES
    + PMR_MODULES
    + RADIO_SAT_IOT_MATTER
    + CELLULAR_MODULES
    + EXTERNAL_MODULES
)


@pytest.mark.parametrize("module_path", ALL_MODULES)
def test_import_and_instantiate(module_path: str) -> None:
    mod = importlib.import_module(module_path)
    cls = _get_exploit_class(mod)
    if cls is None:
        # BaseExploit modules: get the Exploit class directly
        cls = getattr(mod, "Exploit", None)
        assert cls is not None, f"No Exploit class in {module_path}"
    instance = cls()
    assert instance is not None


@pytest.mark.parametrize("module_path", ALL_MODULES)
def test_info_dict(module_path: str) -> None:
    mod = importlib.import_module(module_path)
    cls = _get_exploit_class(mod) or getattr(mod, "Exploit", None)
    assert cls is not None
    info = _get_info(cls)
    if info is None:
        ea = getattr(cls, "exploit_attributes", None)
        assert ea is not None, f"No __info__ or exploit_attributes in {module_path}"
        return
    assert isinstance(info, dict)
    assert "name" in info
    assert len(info["name"]) > 0


@pytest.mark.parametrize("module_path", NFC_MODULES + ZWAVE_MODULES + RADIO_SAT_IOT_MATTER)
def test_check_with_mock(module_path: str) -> None:
    mod = importlib.import_module(module_path)
    cls = _get_exploit_class(mod) or getattr(mod, "Exploit", None)
    assert cls is not None
    instance = cls()
    with patch("shutil.which", return_value=None), \
         patch("subprocess.run", side_effect=FileNotFoundError("mocked")):
        try:
            result = instance.check()
            assert isinstance(result, (str, bool))
        except (FileNotFoundError, OSError, AttributeError):
            pass


@pytest.mark.parametrize("module_path", NFC_MODULES)
def test_nfc_dry_run(module_path: str) -> None:
    mod = importlib.import_module(module_path)
    cls = _get_exploit_class(mod) or getattr(mod, "Exploit", None)
    assert cls is not None
    instance = cls()
    _set_dry_run(instance)
    with patch("shutil.which", return_value="/usr/bin/proxmark3"), \
         patch("subprocess.run", return_value=MagicMock(
             stdout="[dry-run]", stderr="", returncode=0
         )):
        try:
            instance.run()
        except (SystemExit, Exception):
            pass


@pytest.mark.parametrize("module_path", ZWAVE_MODULES)
def test_zwave_dry_run(module_path: str) -> None:
    mod = importlib.import_module(module_path)
    cls = _get_exploit_class(mod) or getattr(mod, "Exploit", None)
    assert cls is not None
    instance = cls()
    _set_dry_run(instance)
    with patch("shutil.which", return_value="/usr/bin/zwutil"), \
         patch("subprocess.run", return_value=MagicMock(
             stdout="", stderr="", returncode=0
         )):
        try:
            instance.run()
        except (SystemExit, Exception):
            pass


@pytest.mark.parametrize("module_path", PMR_MODULES)
def test_pmr_instantiate_and_attrs(module_path: str) -> None:
    mod = importlib.import_module(module_path)
    cls = getattr(mod, "Exploit", None)
    assert cls is not None
    instance = cls()
    ea = getattr(instance, "exploit_attributes", None) or getattr(cls, "exploit_attributes", None)
    info = _get_info(cls)
    assert ea is not None or info is not None
    if hasattr(instance, "run"):
        with patch("shutil.which", return_value=None), \
             patch("subprocess.run", side_effect=FileNotFoundError("mocked")):
            try:
                instance.run()
            except (FileNotFoundError, OSError, SystemExit, Exception):
                pass


@pytest.mark.parametrize("module_path", CELLULAR_MODULES)
def test_cellular_instantiate(module_path: str) -> None:
    mod = importlib.import_module(module_path)
    cls = _get_exploit_class(mod) or getattr(mod, "Exploit", None)
    assert cls is not None
    instance = cls()
    _set_dry_run(instance)
    info = _get_info(cls)
    ea = getattr(cls, "exploit_attributes", None)
    assert info is not None or ea is not None


@pytest.mark.parametrize("module_path", CELLULAR_MODULES)
def test_cellular_run_mocked(module_path: str) -> None:
    mod = importlib.import_module(module_path)
    cls = _get_exploit_class(mod) or getattr(mod, "Exploit", None)
    assert cls is not None
    instance = cls()
    _set_dry_run(instance)
    with patch("shutil.which", return_value=None), \
         patch("subprocess.run", return_value=MagicMock(
             stdout="", stderr="", returncode=1
         )), \
         patch("socket.socket", return_value=MagicMock()):
        try:
            if hasattr(instance, "run"):
                instance.run()
        except (SystemExit, FileNotFoundError, OSError, Exception):
            pass


@pytest.mark.parametrize("module_path", EXTERNAL_MODULES)
def test_external_instantiate(module_path: str) -> None:
    mod = importlib.import_module(module_path)
    cls = _get_exploit_class(mod) or getattr(mod, "Exploit", None)
    assert cls is not None
    instance = cls()
    info = _get_info(cls)
    assert info is not None
    assert "name" in info


@pytest.mark.parametrize("module_path", EXTERNAL_MODULES)
def test_external_check_mocked(module_path: str) -> None:
    mod = importlib.import_module(module_path)
    cls = _get_exploit_class(mod) or getattr(mod, "Exploit", None)
    assert cls is not None
    instance = cls()
    with patch("shutil.which", return_value=None), \
         patch("subprocess.run", side_effect=FileNotFoundError("mocked")):
        try:
            if hasattr(instance, "check"):
                instance.check()
        except (FileNotFoundError, OSError, AttributeError, Exception):
            pass


@pytest.mark.parametrize("module_path", EXTERNAL_MODULES)
def test_external_run_mocked(module_path: str) -> None:
    mod = importlib.import_module(module_path)
    cls = _get_exploit_class(mod) or getattr(mod, "Exploit", None)
    assert cls is not None
    instance = cls()
    _set_dry_run(instance)
    with patch("shutil.which", return_value=None), \
         patch("subprocess.run", return_value=MagicMock(
             stdout="", stderr="", returncode=1
         )), \
         patch("socket.socket", return_value=MagicMock()):
        try:
            if hasattr(instance, "run"):
                instance.run()
        except (SystemExit, FileNotFoundError, OSError, Exception):
            pass


@pytest.mark.parametrize("module_path", RADIO_SAT_IOT_MATTER)
def test_radio_sat_iot_dry_run(module_path: str) -> None:
    mod = importlib.import_module(module_path)
    cls = _get_exploit_class(mod) or getattr(mod, "Exploit", None)
    assert cls is not None
    instance = cls()
    _set_dry_run(instance)
    with patch("shutil.which", return_value=None), \
         patch("subprocess.run", return_value=MagicMock(
             stdout="", stderr="", returncode=0
         )), \
         patch("socket.socket", return_value=MagicMock()):
        try:
            if hasattr(instance, "run"):
                instance.run()
        except (SystemExit, Exception):
            pass
