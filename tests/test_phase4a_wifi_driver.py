"""Unit tests for Phase 4A WiFi driver/chipset CVE exploit modules."""
import importlib
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_PHASE4A_MODULES = [
    "wirelessxpl.modules.generic.wifi.block_ack_frame_dos",
    "wirelessxpl.modules.generic.access_points.intel.iwlwifi_ba_uaf_cve_2026_64255",
    "wirelessxpl.modules.generic.access_points.intel.iwlwifi_wifi7_mld_dos_cve_2026_64175",
    "wirelessxpl.modules.generic.access_points.intel.intel_proset_null_deref_cve_2026_20878",
    "wirelessxpl.modules.generic.access_points.mediatek.mediatek_filogic_heap_overflow_cve_2026_20452",
    "wirelessxpl.modules.generic.access_points.mediatek.mt76_clc_buffer_underflow_cve_2026_46136",
    "wirelessxpl.modules.generic.wifi.mac80211_mlo_uaf_cve_2026_64574",
    "wirelessxpl.modules.generic.wifi.linux_wifi_oob_cve_2026_80722",
    "wirelessxpl.modules.generic.access_points.mikrotik.routeros_scep_oob_read_cve_2026_7668",
]

_PHASE4A_CVES = [
    ("wirelessxpl.modules.generic.wifi.block_ack_frame_dos", "Block Ack"),
    ("wirelessxpl.modules.generic.access_points.intel.iwlwifi_ba_uaf_cve_2026_64255", "CVE-2026-64255"),
    ("wirelessxpl.modules.generic.access_points.intel.iwlwifi_wifi7_mld_dos_cve_2026_64175", "CVE-2026-64175"),
    ("wirelessxpl.modules.generic.access_points.intel.intel_proset_null_deref_cve_2026_20878", "CVE-2026-20878"),
    ("wirelessxpl.modules.generic.access_points.mediatek.mediatek_filogic_heap_overflow_cve_2026_20452", "CVE-2026-20452"),
    ("wirelessxpl.modules.generic.access_points.mediatek.mt76_clc_buffer_underflow_cve_2026_46136", "CVE-2026-46136"),
    ("wirelessxpl.modules.generic.wifi.mac80211_mlo_uaf_cve_2026_64574", "CVE-2026-64574"),
    ("wirelessxpl.modules.generic.wifi.linux_wifi_oob_cve_2026_80722", "CVE-2026-80722"),
    ("wirelessxpl.modules.generic.access_points.mikrotik.routeros_scep_oob_read_cve_2026_7668", "CVE-2026-7668"),
]


class TestPhase4AModuleImports:
    """Verify all Phase 4A modules import without error."""

    @pytest.mark.parametrize("module_path", _PHASE4A_MODULES)
    def test_module_imports(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert hasattr(mod, "Exploit")

    @pytest.mark.parametrize("module_path", _PHASE4A_MODULES)
    def test_exploit_has_required_methods(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "check")
        assert hasattr(instance, "run")
        assert callable(instance.check)
        assert callable(instance.run)

    @pytest.mark.parametrize("module_path", _PHASE4A_MODULES)
    def test_exploit_has_timeout_option(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "timeout")

    @pytest.mark.parametrize("module_path", _PHASE4A_MODULES)
    def test_exploit_has_exploit_attributes(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        assert hasattr(cls, "exploit_attributes")
        attrs = cls.exploit_attributes
        assert isinstance(attrs, dict)

    @pytest.mark.parametrize("module_path,expected_id", _PHASE4A_CVES)
    def test_class_info_contains_identifier(self, module_path: str, expected_id: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert expected_id in info.get("name", ""), f"{expected_id} not found in __info__['name'] for {module_path}"

    @pytest.mark.parametrize("module_path", _PHASE4A_MODULES)
    def test_exploit_has_info_dict(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert "name" in info
        assert "description" in info
        assert "authors" in info
        assert "references" in info


# ---------------------------------------------------------------------------
# Block Ack Frame DoS
# ---------------------------------------------------------------------------

class TestBlockAckDoS:
    """Tests for 802.11 Block Ack Frame DoS."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module("wirelessxpl.modules.generic.wifi.block_ack_frame_dos")
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.tid = 0
        instance.ssn_offset = 2048
        instance.injection_rounds = 4
        instance.inter_frame_delay = 0.0
        return instance

    def test_frame_type_constants(self, exploit) -> None:
        assert exploit._FRAME_TYPE_CTL == 0x01
        assert exploit._SUBTYPE_BAR == 0x08

    def test_build_bar_frame(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        dst = b"\xff\xff\xff\xff\xff\xff"
        frame = exploit._build_bar_frame(src, dst, 0, 100)
        assert isinstance(frame, bytes)
        assert len(frame) > 16

    def test_build_bar_frame_ssn_encoding(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        dst = b"\xff\xff\xff\xff\xff\xff"
        frame = exploit._build_bar_frame(src, dst, 2, 500)
        assert isinstance(frame, bytes)

    def test_build_addba_request(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        dst = b"\xff\xff\xff\xff\xff\xff"
        frame = exploit._build_addba_request(src, dst, 3)
        assert isinstance(frame, bytes)
        assert len(frame) > 20

    def test_build_delba_frame(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        dst = b"\xff\xff\xff\xff\xff\xff"
        frame = exploit._build_delba_frame(src, dst, 0)
        assert isinstance(frame, bytes)
        assert len(frame) > 20

    def test_build_probe_request(self, exploit) -> None:
        frame = exploit._build_probe_request()
        assert isinstance(frame, bytes)
        assert len(frame) > 20

    def test_check_no_socket(self, exploit) -> None:
        with patch("socket.socket", side_effect=OSError):
            assert exploit.check() is False

    def test_run_no_interface(self, exploit) -> None:
        exploit.interface = ""
        exploit.run()

    def test_exploit_with_mock_socket(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send = MagicMock(return_value=None)
        with patch.object(exploit, "_open_raw_wifi", return_value=mock_sock):
            exploit._exploit()
        assert mock_sock.send.call_count > 0
        mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# Intel iwlwifi BA UAF (CVE-2026-64255)
# ---------------------------------------------------------------------------

class TestIwlwifiBaUaf:
    """Tests for CVE-2026-64255 iwlwifi Block Ack UAF."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.intel.iwlwifi_ba_uaf_cve_2026_64255"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.tid = 0
        instance.race_rounds = 4
        instance.inter_frame_delay = 0.0
        return instance

    def test_action_category_ba(self, exploit) -> None:
        assert exploit._ACTION_CATEGORY_BA == 3

    def test_build_addba_request(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        dst = b"\xff\xff\xff\xff\xff\xff"
        frame = exploit._build_addba_request(src, dst, 1)
        assert isinstance(frame, bytes)
        assert len(frame) > 20

    def test_build_delba(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        dst = b"\xff\xff\xff\xff\xff\xff"
        frame = exploit._build_delba(src, dst)
        assert isinstance(frame, bytes)
        assert len(frame) > 20

    def test_build_probe_request(self, exploit) -> None:
        frame = exploit._build_probe_request()
        assert isinstance(frame, bytes)

    def test_check_no_socket(self, exploit) -> None:
        with patch("socket.socket", side_effect=OSError):
            assert exploit.check() is False

    def test_run_no_interface(self, exploit) -> None:
        exploit.interface = ""
        exploit.run()

    def test_exploit_with_mock_socket(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send = MagicMock(return_value=None)
        with patch.object(exploit, "_open_raw_wifi", return_value=mock_sock):
            exploit._exploit()
        assert mock_sock.send.call_count == 8  # 4 rounds * 2 (addba + delba)
        mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# Intel iwlwifi WiFi 7 MLD DoS (CVE-2026-64175)
# ---------------------------------------------------------------------------

class TestIwlwifiMldDos:
    """Tests for CVE-2026-64175 iwlwifi WiFi 7 MLD DoS."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.intel.iwlwifi_wifi7_mld_dos_cve_2026_64175"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.fake_link_count = 8
        instance.injection_rounds = 4
        return instance

    def test_ie_extension_constant(self, exploit) -> None:
        assert exploit._IE_EXTENSION == 255
        assert exploit._EXT_MULTI_LINK == 107

    def test_build_multi_link_ie(self, exploit) -> None:
        ie = exploit._build_multi_link_ie(4)
        assert isinstance(ie, bytes)
        assert len(ie) > 20

    def test_build_multi_link_ie_many_links(self, exploit) -> None:
        ie = exploit._build_multi_link_ie(16)
        assert isinstance(ie, bytes)
        ie_small = exploit._build_multi_link_ie(2)
        assert len(ie) > len(ie_small)

    def test_build_mld_beacon(self, exploit) -> None:
        beacon = exploit._build_mld_beacon(0)
        assert isinstance(beacon, bytes)
        assert len(beacon) > 40

    def test_check_no_socket(self, exploit) -> None:
        with patch("socket.socket", side_effect=OSError):
            assert exploit.check() is False

    def test_run_no_interface(self, exploit) -> None:
        exploit.interface = ""
        exploit.run()

    def test_exploit_with_mock_socket(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send = MagicMock(return_value=None)
        with patch.object(exploit, "_open_raw_wifi", return_value=mock_sock):
            exploit._exploit()
        assert mock_sock.send.call_count == 4
        mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# Intel PROSet Null Deref (CVE-2026-20878)
# ---------------------------------------------------------------------------

class TestIntelProsetNullDeref:
    """Tests for CVE-2026-20878 Intel PROSet null pointer DoS."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.intel.intel_proset_null_deref_cve_2026_20878"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.injection_rounds = 4
        return instance

    def test_ie_vendor_specific(self, exploit) -> None:
        assert exploit._IE_VENDOR_SPECIFIC == 221

    def test_build_malformed_ssid_ie(self, exploit) -> None:
        ie = exploit._build_malformed_ssid_ie()
        assert isinstance(ie, bytes)
        assert len(ie) == 2
        assert ie[0] == 0  # SSID IE type
        assert ie[1] == 0  # zero length

    def test_build_trigger_vendor_ie(self, exploit) -> None:
        ie = exploit._build_trigger_vendor_ie()
        assert isinstance(ie, bytes)
        assert ie[0] == 221  # vendor specific
        assert ie[2:5] == b"\x00\x17\xf2"  # Intel OUI

    def test_build_malformed_beacon(self, exploit) -> None:
        beacon = exploit._build_malformed_beacon(0)
        assert isinstance(beacon, bytes)
        assert len(beacon) > 40

    def test_check_no_socket(self, exploit) -> None:
        with patch("socket.socket", side_effect=OSError):
            assert exploit.check() is False

    def test_run_no_interface(self, exploit) -> None:
        exploit.interface = ""
        exploit.run()

    def test_exploit_with_mock_socket(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send = MagicMock(return_value=None)
        with patch.object(exploit, "_open_raw_wifi", return_value=mock_sock):
            exploit._exploit()
        assert mock_sock.send.call_count == 4
        mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# MediaTek Filogic Heap Overflow (CVE-2026-20452)
# ---------------------------------------------------------------------------

class TestMediatekFilogicHeapOverflow:
    """Tests for CVE-2026-20452 MediaTek Filogic heap overflow."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.mediatek.mediatek_filogic_heap_overflow_cve_2026_20452"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.overflow_size = 128
        instance.injection_rounds = 4
        return instance

    def test_mtk_oui(self, exploit) -> None:
        assert exploit._MTK_OUI == b"\x00\x0C\xE7"

    def test_build_mtk_vendor_ie_overflow(self, exploit) -> None:
        ie = exploit._build_mtk_vendor_ie(overflow=True)
        assert isinstance(ie, bytes)
        assert ie[0] == 221

    def test_build_mtk_vendor_ie_normal(self, exploit) -> None:
        ie = exploit._build_mtk_vendor_ie(overflow=False)
        assert isinstance(ie, bytes)
        ie_overflow = exploit._build_mtk_vendor_ie(overflow=True)
        assert len(ie) < len(ie_overflow)

    def test_build_assoc_response(self, exploit) -> None:
        frame = exploit._build_assoc_response(0, overflow=True)
        assert isinstance(frame, bytes)
        assert len(frame) > 40

    def test_build_assoc_response_normal(self, exploit) -> None:
        frame = exploit._build_assoc_response(0, overflow=False)
        assert isinstance(frame, bytes)

    def test_check_no_socket(self, exploit) -> None:
        with patch("socket.socket", side_effect=OSError):
            assert exploit.check() is False

    def test_run_no_interface(self, exploit) -> None:
        exploit.interface = ""
        exploit.run()

    def test_exploit_with_mock_socket(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send = MagicMock(return_value=None)
        with patch.object(exploit, "_open_raw_wifi", return_value=mock_sock):
            exploit._exploit()
        assert mock_sock.send.call_count == 4
        mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# MediaTek mt76 CLC Buffer Underflow (CVE-2026-46136)
# ---------------------------------------------------------------------------

class TestMt76ClcUnderflow:
    """Tests for CVE-2026-46136 mt76 CLC buffer underflow."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.mediatek.mt76_clc_buffer_underflow_cve_2026_46136"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.injection_rounds = 4
        return instance

    def test_mtk_oui(self, exploit) -> None:
        assert exploit._MTK_OUI == b"\x00\x0C\xE7"

    def test_build_clc_vendor_ie(self, exploit) -> None:
        ie = exploit._build_clc_vendor_ie()
        assert isinstance(ie, bytes)
        assert ie[0] == 221

    def test_build_trigger_beacon(self, exploit) -> None:
        beacon = exploit._build_trigger_beacon(0)
        assert isinstance(beacon, bytes)
        assert len(beacon) > 40

    def test_check_no_socket(self, exploit) -> None:
        with patch("socket.socket", side_effect=OSError):
            assert exploit.check() is False

    def test_run_no_interface(self, exploit) -> None:
        exploit.interface = ""
        exploit.run()

    def test_exploit_with_mock_socket(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send = MagicMock(return_value=None)
        with patch.object(exploit, "_open_raw_wifi", return_value=mock_sock):
            exploit._exploit()
        assert mock_sock.send.call_count == 4
        mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# mac80211 MLO UAF (CVE-2026-64574)
# ---------------------------------------------------------------------------

class TestMac80211MloUaf:
    """Tests for CVE-2026-64574 mac80211 MLO UAF."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.wifi.mac80211_mlo_uaf_cve_2026_64574"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.deauth_rounds = 4
        instance.burst_delay = 0.0
        return instance

    def test_subtype_deauth(self, exploit) -> None:
        assert exploit._SUBTYPE_DEAUTH == 0x0C

    def test_build_deauth_frame(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        dst = b"\x02\x00\x00\x00\x00\x03"
        frame = exploit._build_deauth_frame(src, dst, 1)
        assert isinstance(frame, bytes)
        assert len(frame) > 20

    def test_build_mlo_assoc_response(self, exploit) -> None:
        frame = exploit._build_mlo_assoc_response(0, 1)
        assert isinstance(frame, bytes)
        assert len(frame) > 40

    def test_build_mlo_assoc_varying_link_id(self, exploit) -> None:
        frame1 = exploit._build_mlo_assoc_response(0, 1)
        frame2 = exploit._build_mlo_assoc_response(0, 2)
        assert frame1 != frame2

    def test_check_no_socket(self, exploit) -> None:
        with patch("socket.socket", side_effect=OSError):
            assert exploit.check() is False

    def test_run_no_interface(self, exploit) -> None:
        exploit.interface = ""
        exploit.run()

    def test_exploit_with_mock_socket(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send = MagicMock(return_value=None)
        with patch.object(exploit, "_open_raw_wifi", return_value=mock_sock):
            exploit._exploit()
        assert mock_sock.send.call_count == 8  # 4 rounds * 2 (deauth + assoc)
        mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# Linux WiFi OOB Write (CVE-2026-80722)
# ---------------------------------------------------------------------------

class TestLinuxWifiOob:
    """Tests for CVE-2026-80722 Linux WiFi OOB write."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.wifi.linux_wifi_oob_cve_2026_80722"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.overflow_ie_size = 255
        instance.injection_rounds = 4
        return instance

    def test_build_corrupted_ie(self, exploit) -> None:
        ie = exploit._build_corrupted_ie()
        assert isinstance(ie, bytes)
        assert ie[0] == 50
        assert ie[1] == 255

    def test_build_corrupted_ie_actual_data_short(self, exploit) -> None:
        ie = exploit._build_corrupted_ie()
        actual_data_len = len(ie) - 2
        assert actual_data_len == 16
        assert ie[1] == 255  # declared much larger

    def test_build_oob_beacon(self, exploit) -> None:
        beacon = exploit._build_oob_beacon(0)
        assert isinstance(beacon, bytes)
        assert len(beacon) > 40

    def test_check_no_socket(self, exploit) -> None:
        with patch("socket.socket", side_effect=OSError):
            assert exploit.check() is False

    def test_run_no_interface(self, exploit) -> None:
        exploit.interface = ""
        exploit.run()

    def test_exploit_with_mock_socket(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send = MagicMock(return_value=None)
        with patch.object(exploit, "_open_raw_wifi", return_value=mock_sock):
            exploit._exploit()
        assert mock_sock.send.call_count == 4
        mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# MikroTik RouterOS SCEP OOB Read (CVE-2026-7668)
# ---------------------------------------------------------------------------

class TestRouterosScepOob:
    """Tests for CVE-2026-7668 MikroTik RouterOS SCEP OOB read."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.mikrotik.routeros_scep_oob_read_cve_2026_7668"
        )
        instance = mod.Exploit()
        instance.target = "192.168.88.1"
        instance.port = 80
        instance.timeout = 1.0
        instance.scep_path = "/scep/pkiclient.exe"
        instance.leak_attempts = 2
        return instance

    def test_scep_operation(self, exploit) -> None:
        assert exploit._SCEP_OPERATION == "PKIOperation"

    def test_build_truncated_pkcs7(self, exploit) -> None:
        pkcs7 = exploit._build_truncated_pkcs7()
        assert isinstance(pkcs7, bytes)
        assert len(pkcs7) > 20
        assert pkcs7[0] == 0x30  # SEQUENCE

    def test_build_scep_request(self, exploit) -> None:
        request = exploit._build_scep_request()
        assert isinstance(request, bytes)
        assert b"POST" in request
        assert b"PKIOperation" in request
        assert b"x-pki-message" in request

    def test_check_connection_refused(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.connect = MagicMock(side_effect=OSError)
            assert exploit.check() is False

    def test_run_no_target(self, exploit) -> None:
        exploit.target = ""
        exploit.run()

    def test_send_scep_request_connection_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.connect = MagicMock(side_effect=OSError)
            result = exploit._send_scep_request()
            assert result is None

    def test_exploit_all_fail(self, exploit) -> None:
        with patch.object(exploit, "_send_scep_request", return_value=None):
            exploit._exploit()

    def test_exploit_with_response(self, exploit) -> None:
        fake_response = b"HTTP/1.1 200 OK\r\nContent-Length: 128\r\n\r\n" + b"\x00" * 128
        with patch.object(exploit, "_send_scep_request", return_value=fake_response):
            exploit._exploit()

    def test_info_platform(self, exploit) -> None:
        cls = type(exploit)
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert info.get("platform") == "routeros"
