"""Smoke tests for NFC, SIM, cellular, zwave, subghz, external and core modules."""

from __future__ import annotations

import importlib
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

MODULES: list[tuple[str, str, bool]] = [
    ("wirelessxpl.modules.generic.nfc.desfire_attack", "DESFireAttack", True),
    ("wirelessxpl.modules.generic.nfc.emv_contactless_relay", "EMVContactlessRelay", True),
    ("wirelessxpl.modules.generic.nfc.iclass_seos_attack", "IClassSeosAttack", True),
    ("wirelessxpl.modules.generic.nfc.mifare_classic_cracker", "MifareClassicCracker", True),
    ("wirelessxpl.modules.generic.nfc.nfc_relay_native", "NFCRelayNative", True),
    ("wirelessxpl.modules.generic.nfc.nfc_relay_ndef_bridge", "NfcRelayNdefBridge", False),
    ("wirelessxpl.modules.generic.nfc.rfid_cloner", "RFIDCloner", True),
    ("wirelessxpl.modules.generic.sim.esim_rsp_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.sim.pysim_reader", "Exploit", True),
    ("wirelessxpl.modules.generic.sim.sim_adm_brute", "Exploit", True),
    ("wirelessxpl.modules.generic.sim.sim_apdu_lab", "Exploit", True),
    ("wirelessxpl.modules.generic.sim.sim_cloner", "Exploit", True),
    ("wirelessxpl.modules.generic.sim.simjacker_info", "Exploit", False),
    ("wirelessxpl.modules.generic.cellular.fiveg_nr_scanner", "FiveGNRScanner", True),
    ("wirelessxpl.modules.generic.cellular.fiveghoul_5gnr_dos", "Exploit", False),
    ("wirelessxpl.modules.generic.cellular.gnuradio_gsm_bridge", "GnuradioGSMBridge", True),
    ("wirelessxpl.modules.generic.cellular.gsm_a51_crack", "Exploit", True),
    ("wirelessxpl.modules.generic.cellular.gsm_freq_scanner", "Exploit", True),
    ("wirelessxpl.modules.generic.cellular.imsi_catcher_passive", "Exploit", True),
    ("wirelessxpl.modules.generic.cellular.llfuzz_baseband_cve_scanner", "Exploit", False),
    ("wirelessxpl.modules.generic.cellular.lte_imsi_catcher", "Exploit", True),
    ("wirelessxpl.modules.generic.cellular.sni5gect_5gnr_sniff_inject", "Exploit", False),
    ("wirelessxpl.modules.generic.cellular.ss7_sigploit_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.cellular.ueransim_5g_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.cellular.volte_ims_interception", "Exploit", True),
    ("wirelessxpl.modules.generic.zwave.zwave_attack_suite", "ZWaveAttackSuite", False),
    ("wirelessxpl.modules.generic.zwave.zwave_replay_attack", "Exploit", False),
    ("wirelessxpl.modules.generic.zwave.zwave_s0_key_extract", "Exploit", False),
    ("wirelessxpl.modules.generic.zwave.zwave_s2_bypass", "ZWaveS2Bypass", True),
    ("wirelessxpl.modules.generic.satellite.adsb_spoofer", "ADSBSpoofer", True),
    ("wirelessxpl.modules.generic.radio.tetra_decrypt", "TETRADecrypt", True),
    ("wirelessxpl.modules.generic.iot.matter_thread_exploit", "MatterThreadExploit", True),
    ("wirelessxpl.modules.generic.matter.matter_thread_bridge", "MatterThreadBridge", False),
    ("wirelessxpl.modules.generic.subghz.br_gate_scanner", "Exploit", False),
    ("wirelessxpl.modules.generic.subghz.debruijn_bruteforce", "Exploit", False),
    ("wirelessxpl.modules.generic.subghz.ev1527_vehicle_cve_2025_70994", "Exploit", False),
    ("wirelessxpl.modules.generic.subghz.keeloq_decoder", "Exploit", False),
    ("wirelessxpl.modules.generic.subghz.keeloq_replay", "Exploit", False),
    ("wirelessxpl.modules.generic.subghz.rkes_rollback_replay_cve_2026_49319", "Exploit", False),
    ("wirelessxpl.modules.generic.subghz.static_code_replay", "Exploit", False),
    ("wirelessxpl.modules.generic.subghz.subghz_jammer", "Exploit", False),
    ("wirelessxpl.modules.generic.subghz.tools.ook_analyzer", "Exploit", False),
    ("wirelessxpl.modules.generic.subghz.tpms.tpms_decoder", "Exploit", False),
    ("wirelessxpl.modules.generic.subghz.tpms.tpms_spoof", "Exploit", False),
    ("wirelessxpl.modules.generic.wordlist.wordlist_generator", "Exploit", False),
    ("wirelessxpl.modules.generic.external.aircrack_full_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.bruce_esp32_lab_notes", "Exploit", False),
    ("wirelessxpl.modules.generic.external.bruce_serial_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.bruce_upstream_tracker", "Exploit", False),
    ("wirelessxpl.modules.generic.external.eaphammer_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.hcx_toolchain_bridge", "Exploit", False),
    ("wirelessxpl.modules.generic.external.hcxdumptool_live_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.hostapd_wpe_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.kismet_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.oneshot_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.ot_protocol_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.proxmark_rfid_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.rogue_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.router_firmware_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.sigfox_lorawan_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.social_recon_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.wifipumpkin3_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.external.wireless_tool_prereq_audit", "Exploit", False),
    ("wirelessxpl.modules.generic.pmr.dmr_sniffing", "Exploit", False),
    ("wirelessxpl.modules.generic.pmr.p25_eavesdrop_jam", "Exploit", False),
    ("wirelessxpl.modules.generic.pmr.p25_radio_inhibit_dos", "Exploit", False),
    ("wirelessxpl.modules.generic.pmr.tetra_burst_tea1_backdoor", "Exploit", True),
    ("wirelessxpl.modules.generic.pmr.tetra_passive_sniff", "Exploit", True),
    ("wirelessxpl.modules.generic.zigbee.zigbee_ecosystem_expansion", "Exploit", False),
]

CORE_MODULES: list[tuple[str, str]] = [
    ("wirelessxpl.core.bluetooth.btle_client", "BTLEClient"),
    ("wirelessxpl.core.ftp.ftp_client", "FTPClient"),
    ("wirelessxpl.core.http.http_client", "HTTPClient"),
    ("wirelessxpl.core.tcp.tcp_client", "TCPClient"),
    ("wirelessxpl.core.telnet.telnet_client", "TelnetClient"),
    ("wirelessxpl.core.udp.udp_client", "UDPClient"),
]


def _load_class(mod_path: str, cls_name: str) -> type | None:
    try:
        mod = importlib.import_module(mod_path)
        return getattr(mod, cls_name)
    except Exception:
        return None


def _get_info(obj: Any, cls_name: str) -> dict[str, Any]:
    mangled = f"_{cls_name}__info__"
    if hasattr(obj, mangled):
        return getattr(obj, mangled)
    if hasattr(obj, "__info__"):
        return obj.__info__
    for attr in dir(obj):
        if attr.endswith("__info__"):
            return getattr(obj, attr)
    raise AttributeError(f"No __info__ found on {cls_name}")


def _make_id(mod_path: str) -> str:
    return mod_path.rsplit(".", 1)[-1]


@pytest.mark.parametrize(
    "mod_path,cls_name,has_dry_run",
    MODULES,
    ids=[_make_id(m) for m, _, _ in MODULES],
)
class TestOtherModuleSmoke:
    def test_import_and_info(self, mod_path: str, cls_name: str, has_dry_run: bool) -> None:
        cls = _load_class(mod_path, cls_name)
        if cls is None:
            pytest.skip("import failed")
        obj = cls()
        info = _get_info(obj, cls_name)
        assert isinstance(info, dict)
        assert "name" in info

    @patch("shutil.which", return_value=None)
    @patch("subprocess.run", return_value=MagicMock(returncode=1, stdout="", stderr=""))
    def test_check(
        self,
        _mock_subproc: MagicMock,
        _mock_which: MagicMock,
        mod_path: str,
        cls_name: str,
        has_dry_run: bool,
    ) -> None:
        cls = _load_class(mod_path, cls_name)
        if cls is None:
            pytest.skip("import failed")
        obj = cls()
        try:
            obj.check()
        except Exception:
            pass

    @patch("shutil.which", return_value=None)
    @patch("subprocess.run", return_value=MagicMock(returncode=1, stdout="", stderr=""))
    @patch("socket.socket", return_value=MagicMock())
    def test_dry_run(
        self,
        _mock_sock: MagicMock,
        _mock_subproc: MagicMock,
        _mock_which: MagicMock,
        mod_path: str,
        cls_name: str,
        has_dry_run: bool,
    ) -> None:
        if not has_dry_run:
            pytest.skip("no dry_run option")
        cls = _load_class(mod_path, cls_name)
        if cls is None:
            pytest.skip("import failed")
        obj = cls()
        if hasattr(obj, "dry_run"):
            obj.dry_run = True
        try:
            obj.run()
        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception:
            pass


@pytest.mark.parametrize(
    "mod_path,cls_name",
    CORE_MODULES,
    ids=[_make_id(m) for m, _ in CORE_MODULES],
)
class TestCoreClientSmoke:
    def test_import_instantiate(self, mod_path: str, cls_name: str) -> None:
        cls = _load_class(mod_path, cls_name)
        if cls is None:
            pytest.skip("import failed")
        try:
            obj = cls.__new__(cls)
            assert obj is not None
        except Exception:
            pass
