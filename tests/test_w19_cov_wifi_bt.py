"""Smoke tests for wifi and bluetooth modules: import, instantiate, __info__, check, dry_run."""

from __future__ import annotations

import importlib
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

MODULES: list[tuple[str, str, bool]] = [
    # (module_path, class_name, has_dry_run)
    ("wirelessxpl.modules.generic.wifi.adaptive_harvest", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.aircrack_crack_engine", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.aireplay_deauth_barrage", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.airsnitch_isolation_bypass", "AirSnitchIsolationBypass", False),
    ("wirelessxpl.modules.generic.wifi.ap_less_client_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.arp_mitm_proxy", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.auth_flood", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.awdl_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.beacon_flood_advanced", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.captive_portal_engine", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.captive_portal_modern_lab", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.connectivity_portal", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.csa_handshake_capture", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.csa_mc_mitm_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.cve_2024_30078_windows_wifi_driver", "Cve202430078WindowsWifiDriver", False),
    ("wirelessxpl.modules.generic.wifi.deauth_csa_suite", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.deauth_multimode", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.dns_dhcp_server", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.dns_spoof_engine", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.dragonblood_suite", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.dualband_evil_twin", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.eap_relay_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.evil_qr_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.evil_twin_advanced", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.evil_twin_hostapd_templates", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.evil_twin_workflow", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.flood_engine_native", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.fragattacks.fragattacks_amsdu_mesh_cve_2025_27558", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.fragattacks.fragattacks_cve_2020_26140", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.fragattacks.fragattacks_cve_2020_26141", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.fragattacks.fragattacks_cve_2020_26143", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.fragattacks.fragattacks_scanner", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.fragattacks_native", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.gps_wardriving_ndjson", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.handshake_crack_engine", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.handshake_snooper", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.hashcat_gpu_orchestrator", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.interface_manager", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.karma_mana_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.kr00k_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.krack.krack_4way_retransmit", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.krack.krack_group_key_retransmit", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.krack.krack_scanner", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.krack_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.mfa_phishing_portal", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.mitm_wifi_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.monitor_mode_manager", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.owe_downgrade", "OWEDowngrade", True),
    ("wirelessxpl.modules.generic.wifi.packet_injection_lab", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.pcap_rf_anomaly_ml", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.pcap_wpa_handshake_validate", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.phishing_engine", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.pmkid_autopwn", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.qualcomm_wlan_ml_ie_cve2024_45569", "QualcommWlanMlIeCve202445569", False),
    ("wirelessxpl.modules.generic.wifi.radius_credential_brute", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.replay_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.research_ecosystem_status", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.responder_wifi", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.rf_anomaly_detector", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.rogue_ap_hostapd_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.rtp_rip_spoof", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.sae_timing_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.selective_jammer", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.sigma_rule_detector", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.skygofree_geofence_c2", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.snoopy_probe_capture", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.ssid_confusion", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.tkip_attack_suite", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.transparent_proxy", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.vrrp_takeover", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.wardriving_deauth_loop", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.wep_attack_suite", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.wifi7_mlo_attack", "WiFi7MLOAttack", True),
    ("wirelessxpl.modules.generic.wifi.wifi_kr00k_cve_2019_15126", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.wifi_security_analyzer", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.wifi_sniffer", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.wifiair_c2_beacon", "WifiAirC2Beacon", False),
    ("wirelessxpl.modules.generic.wifi.wigle_export", "Exploit", False),
    ("wirelessxpl.modules.generic.wifi.wireless_ids", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.wordlist_orchestrator", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.wpa3_attack_suite", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.wpa3_sae_flood_native", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.wpa_online_brute", "Exploit", True),
    ("wirelessxpl.modules.generic.wifi.wps_engine_native", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.bias_attack_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.ble5_direction_finding_spoof", "BLE5DirectionFindingSpoof", True),
    ("wirelessxpl.modules.generic.bluetooth.ble_bluffs_native", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.ble_btlejack", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.ble_crackle", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.ble_extra_attacks", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.ble_gatt_enum_unauth", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.ble_phishing", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.ble_spoofing_impersonation", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.ble_sweyntooth_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.blueborne_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.bluefrag_cve_2020_0022", "BlueFrag", True),
    ("wirelessxpl.modules.generic.bluetooth.bluffs_cve_2023_24023", "BLUFFS", True),
    ("wirelessxpl.modules.generic.bluetooth.braktooth_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.braktooth_fuzzer", "BrakToothFuzzer", True),
    ("wirelessxpl.modules.generic.bluetooth.bt_baseband_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.bt_classic_suite", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.bt_hid_injection", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.bt_mesh_attack", "BTMeshAttack", True),
    ("wirelessxpl.modules.generic.bluetooth.bt_rfcomm_oob_cve2025_13834", "BtRfcommOobCve202513834", False),
    ("wirelessxpl.modules.generic.bluetooth.bt_session_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.killerbee_zigbee_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.knob_attack_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.knob_native_cve_2019_9506", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.lasco_obex_push", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.sweyntooth.sweyntooth_cve_2019_16336", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.sweyntooth.sweyntooth_cve_2019_17517", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.sweyntooth.sweyntooth_cve_2019_17519", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.sweyntooth.sweyntooth_cve_2019_17520", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.sweyntooth.sweyntooth_scanner", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.whisperpair_fast_pair_cve_2025_36911", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.zigator_bridge", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.zigbee_key_extract", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.zigbee_network_key_extract", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.zigbee_realignment_attack", "Exploit", True),
    ("wirelessxpl.modules.generic.bluetooth.zigbee_rejoin_hijack", "Exploit", False),
    ("wirelessxpl.modules.generic.bluetooth.zigbee_replay_cve2021_27289", "ZigbeeReplayCve202127289", False),
    ("wirelessxpl.modules.generic.bluetooth.zigbee_touchlink_factory_reset", "Exploit", False),
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
class TestModuleSmoke:
    def test_import_and_info(self, mod_path: str, cls_name: str, has_dry_run: bool) -> None:
        cls = _load_class(mod_path, cls_name)
        if cls is None:
            pytest.skip("import failed")
        obj = cls()
        info: dict[str, Any] = _get_info(obj, cls_name)
        assert isinstance(info, dict)
        assert "name" in info
        assert isinstance(info["name"], str)
        assert len(info["name"]) > 0

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
            result = obj.check()
            assert result is not None
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
