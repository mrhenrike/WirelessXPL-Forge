"""Unit tests for Phase 3 Batch 3 driver/mac80211 CVE exploit modules."""
import importlib
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_BATCH3_MODULES = [
    "wirelessxpl.modules.generic.access_points.qualcomm.ath11k_double_free_cve_2026_63822",
    "wirelessxpl.modules.generic.access_points.intel.iwlwifi_lmac_oob_cve_2026_43172",
    "wirelessxpl.modules.generic.access_points.intel.iwlwifi_scan_oob_read_cve_2026_31779",
    "wirelessxpl.modules.generic.wifi.mac80211_8023_xmit_cve_2026_98700",
    "wirelessxpl.modules.generic.wifi.mac80211_skb_double_free_cve_2026_23444",
]

_BATCH3_CVES = [
    ("wirelessxpl.modules.generic.access_points.qualcomm.ath11k_double_free_cve_2026_63822", "CVE-2026-63822"),
    ("wirelessxpl.modules.generic.access_points.intel.iwlwifi_lmac_oob_cve_2026_43172", "CVE-2026-43172"),
    ("wirelessxpl.modules.generic.access_points.intel.iwlwifi_scan_oob_read_cve_2026_31779", "CVE-2026-31779"),
    ("wirelessxpl.modules.generic.wifi.mac80211_8023_xmit_cve_2026_98700", "CVE-2026-98700"),
    ("wirelessxpl.modules.generic.wifi.mac80211_skb_double_free_cve_2026_23444", "CVE-2026-23444"),
]


class TestBatch3ModuleImports:
    """Verify all Phase 3 Batch 3 modules import without error."""

    @pytest.mark.parametrize("module_path", _BATCH3_MODULES)
    def test_module_imports(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert hasattr(mod, "Exploit")

    @pytest.mark.parametrize("module_path", _BATCH3_MODULES)
    def test_exploit_has_required_methods(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "check")
        assert hasattr(instance, "run")
        assert callable(instance.check)
        assert callable(instance.run)

    @pytest.mark.parametrize("module_path", _BATCH3_MODULES)
    def test_exploit_has_timeout_option(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "timeout")

    @pytest.mark.parametrize("module_path", _BATCH3_MODULES)
    def test_exploit_has_exploit_attributes(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        assert hasattr(cls, "exploit_attributes")
        attrs = cls.exploit_attributes
        assert isinstance(attrs, dict)

    @pytest.mark.parametrize("module_path,expected_cve", _BATCH3_CVES)
    def test_class_info_contains_cve(self, module_path: str, expected_cve: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert expected_cve in info.get("name", ""), f"CVE not found in __info__['name'] for {module_path}"

    @pytest.mark.parametrize("module_path", _BATCH3_MODULES)
    def test_exploit_has_info_dict(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert "name" in info
        assert "description" in info
        assert "authors" in info
        assert "references" in info


# ---------------------------------------------------------------------------
# ath11k Double-Free (CVE-2026-63822)
# ---------------------------------------------------------------------------

class TestAth11kDoubleFree:
    """Tests for CVE-2026-63822 ath11k double-free in teardown."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.qualcomm.ath11k_double_free_cve_2026_63822"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.channel = 36
        instance.deauth_rounds = 4
        instance.burst_delay = 0.0
        return instance

    def test_frame_type_mgmt(self, exploit) -> None:
        assert exploit._FRAME_TYPE_MGMT == 0x00

    def test_deauth_subtype(self, exploit) -> None:
        assert exploit._SUBTYPE_DEAUTH == 0x0C

    def test_build_frame_control(self, exploit) -> None:
        fc = exploit._build_frame_control(exploit._SUBTYPE_DEAUTH)
        assert isinstance(fc, bytes)
        assert len(fc) == 2

    def test_build_deauth_frame(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        dst = b"\xff\xff\xff\xff\xff\xff"
        frame = exploit._build_deauth_frame(src, dst, 1)
        assert isinstance(frame, bytes)
        assert len(frame) > 20

    def test_build_disassoc_frame(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        dst = b"\xff\xff\xff\xff\xff\xff"
        frame = exploit._build_disassoc_frame(src, dst, 3)
        assert isinstance(frame, bytes)
        assert len(frame) > 20

    def test_build_probe_request(self, exploit) -> None:
        probe = exploit._build_probe_request()
        assert isinstance(probe, bytes)
        assert len(probe) > 20

    def test_inject_frame_success(self, exploit) -> None:
        mock_sock = MagicMock()
        assert exploit._inject_frame(mock_sock, b"\x00") is True

    def test_inject_frame_failure(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send.side_effect = OSError("broken")
        assert exploit._inject_frame(mock_sock, b"\x00") is False

    def test_open_raw_wifi_returns_none_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit._open_raw_wifi() is None

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_raw_wifi", return_value=None):
            assert exploit.check() is False

    def test_reason_constants(self, exploit) -> None:
        assert exploit._REASON_UNSPECIFIED == 1
        assert exploit._REASON_PREV_AUTH_INVALID == 2
        assert exploit._REASON_DEAUTH_LEAVING == 3


# ---------------------------------------------------------------------------
# iwlwifi LMAC OOB Access (CVE-2026-43172)
# ---------------------------------------------------------------------------

class TestIwlwifiLmacOob:
    """Tests for CVE-2026-43172 iwlwifi LMAC out-of-bounds access."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.intel.iwlwifi_lmac_oob_cve_2026_43172"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.channel = 36
        instance.target_channel = 149
        instance.csa_count = 4
        return instance

    def test_ie_csa_constant(self, exploit) -> None:
        assert exploit._IE_CSA == 37

    def test_ie_extended_csa_constant(self, exploit) -> None:
        assert exploit._IE_EXTENDED_CSA == 60

    def test_build_csa_ie(self, exploit) -> None:
        ie = exploit._build_csa_ie(149, count=3)
        assert isinstance(ie, bytes)
        assert ie[0] == 37
        assert ie[1] == 3

    def test_build_extended_csa_ie(self, exploit) -> None:
        ie = exploit._build_extended_csa_ie(149, count=3)
        assert isinstance(ie, bytes)
        assert ie[0] == 60

    def test_build_csa_beacon(self, exploit) -> None:
        bssid = b"\x02\x00\x00\x00\x00\x01"
        beacon = exploit._build_csa_beacon(bssid, 0)
        assert isinstance(beacon, bytes)
        assert len(beacon) > 50

    def test_build_csa_action_frame(self, exploit) -> None:
        bssid = b"\x02\x00\x00\x00\x00\x01"
        action = exploit._build_csa_action_frame(bssid)
        assert isinstance(action, bytes)
        assert len(action) > 30

    def test_build_probe_request(self, exploit) -> None:
        probe = exploit._build_probe_request()
        assert isinstance(probe, bytes)
        assert len(probe) > 20

    def test_build_frame_control(self, exploit) -> None:
        fc = exploit._build_frame_control(exploit._SUBTYPE_BEACON)
        assert isinstance(fc, bytes)
        assert len(fc) == 2

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_raw_wifi", return_value=None):
            assert exploit.check() is False

    def test_csa_beacon_contains_ssid(self, exploit) -> None:
        bssid = b"\x02\x00\x00\x00\x00\x01"
        beacon = exploit._build_csa_beacon(bssid, 0)
        assert b"iwl-fuzz" in beacon


# ---------------------------------------------------------------------------
# iwlwifi Scan OOB Read (CVE-2026-31779)
# ---------------------------------------------------------------------------

class TestIwlwifiScanOobRead:
    """Tests for CVE-2026-31779 iwlwifi scan results OOB read."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.intel.iwlwifi_scan_oob_read_cve_2026_31779"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.channel = 36
        instance.probe_count = 4
        instance.ie_padding = 512
        return instance

    def test_ie_vendor_specific(self, exploit) -> None:
        assert exploit._IE_VENDOR_SPECIFIC == 221

    def test_build_oversized_probe_response(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        resp = exploit._build_oversized_probe_response(src, 0)
        assert isinstance(resp, bytes)
        assert len(resp) > 100

    def test_probe_response_contains_ssid(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        resp = exploit._build_oversized_probe_response(src, 0)
        assert b"iwl-probe" in resp

    def test_ie_padding_affects_size(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        exploit.ie_padding = 128
        small = exploit._build_oversized_probe_response(src, 0)
        exploit.ie_padding = 2048
        large = exploit._build_oversized_probe_response(src, 0)
        assert len(large) > len(small)

    def test_build_probe_request(self, exploit) -> None:
        probe = exploit._build_probe_request()
        assert isinstance(probe, bytes)
        assert len(probe) > 20

    def test_inject_frame_success(self, exploit) -> None:
        mock_sock = MagicMock()
        assert exploit._inject_frame(mock_sock, b"\x00") is True

    def test_inject_frame_failure(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send.side_effect = OSError("broken")
        assert exploit._inject_frame(mock_sock, b"\x00") is False

    def test_open_raw_wifi_returns_none_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit._open_raw_wifi() is None

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_raw_wifi", return_value=None):
            assert exploit.check() is False


# ---------------------------------------------------------------------------
# mac80211 802.3 Encap Offload (CVE-2026-98700)
# ---------------------------------------------------------------------------

class TestMac80211XmitValidation:
    """Tests for CVE-2026-98700 mac80211 ieee80211_8023_xmit."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.wifi.mac80211_8023_xmit_cve_2026_98700"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.payload_size = 256
        instance.injection_rounds = 2
        return instance

    def test_ether_type_constants(self, exploit) -> None:
        assert exploit._ETHER_TYPE_IPV4 == 0x0800
        assert exploit._ETHER_HEADER_LEN == 14

    def test_llc_snap_header(self, exploit) -> None:
        assert exploit._LLC_SNAP_HEADER == b"\xAA\xAA\x03\x00\x00\x00"

    def test_build_radiotap_header(self, exploit) -> None:
        hdr = exploit._build_radiotap_header()
        assert isinstance(hdr, bytes)
        assert len(hdr) == 8

    def test_build_8023_frame_oversized(self, exploit) -> None:
        frame = exploit._build_8023_frame(oversized=True)
        assert isinstance(frame, bytes)
        assert len(frame) > 256

    def test_build_8023_frame_normal(self, exploit) -> None:
        frame = exploit._build_8023_frame(oversized=False)
        assert isinstance(frame, bytes)

    def test_oversized_larger_than_normal(self, exploit) -> None:
        normal = exploit._build_8023_frame(oversized=False)
        oversized = exploit._build_8023_frame(oversized=True)
        assert len(oversized) > len(normal)

    def test_build_injection_frame(self, exploit) -> None:
        frame = exploit._build_injection_frame(6)
        assert isinstance(frame, bytes)
        assert len(frame) > 100

    def test_build_probe_frame(self, exploit) -> None:
        frame = exploit._build_probe_frame()
        assert isinstance(frame, bytes)
        assert len(frame) > 30

    def test_inject_frame_success(self, exploit) -> None:
        mock_sock = MagicMock()
        assert exploit._inject_frame(mock_sock, b"\x00") is True

    def test_inject_frame_failure(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send.side_effect = OSError("broken")
        assert exploit._inject_frame(mock_sock, b"\x00") is False

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_raw_wifi", return_value=None):
            assert exploit.check() is False

    def test_payload_size_affects_frame(self, exploit) -> None:
        exploit.payload_size = 128
        small = exploit._build_8023_frame(oversized=True)
        exploit.payload_size = 4096
        large = exploit._build_8023_frame(oversized=True)
        assert len(large) > len(small)


# ---------------------------------------------------------------------------
# mac80211 SKB Double-Free (CVE-2026-23444)
# ---------------------------------------------------------------------------

class TestMac80211SkbDoubleFree:
    """Tests for CVE-2026-23444 mac80211 SKB double-free in TX prep."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.wifi.mac80211_skb_double_free_cve_2026_23444"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.burst_size = 8
        instance.burst_rounds = 2
        instance.inter_frame_delay = 0.0
        return instance

    def test_frame_type_data(self, exploit) -> None:
        assert exploit._FRAME_TYPE_DATA == 0x02

    def test_subtype_qos_data(self, exploit) -> None:
        assert exploit._SUBTYPE_QOS_DATA == 0x08

    def test_to_ds_flag(self, exploit) -> None:
        assert exploit._TO_DS == 0x01

    def test_build_radiotap_header(self, exploit) -> None:
        hdr = exploit._build_radiotap_header()
        assert isinstance(hdr, bytes)
        assert len(hdr) == 8

    def test_build_frame_control(self, exploit) -> None:
        fc = exploit._build_frame_control(0x02, 0x08, 0x01)
        assert isinstance(fc, bytes)
        assert len(fc) == 2

    def test_build_qos_data_frame(self, exploit) -> None:
        frame = exploit._build_qos_data_frame(0, tid=0)
        assert isinstance(frame, bytes)
        assert len(frame) > 40

    def test_qos_data_frame_sequence_varies(self, exploit) -> None:
        f1 = exploit._build_qos_data_frame(1, tid=0)
        f2 = exploit._build_qos_data_frame(100, tid=0)
        assert f1 != f2

    def test_qos_data_frame_tid_varies(self, exploit) -> None:
        f1 = exploit._build_qos_data_frame(0, tid=0)
        f2 = exploit._build_qos_data_frame(0, tid=7)
        assert f1 != f2

    def test_build_null_frame(self, exploit) -> None:
        frame = exploit._build_null_frame()
        assert isinstance(frame, bytes)
        assert len(frame) > 20

    def test_build_probe_request(self, exploit) -> None:
        probe = exploit._build_probe_request()
        assert isinstance(probe, bytes)
        assert len(probe) > 20

    def test_inject_frame_success(self, exploit) -> None:
        mock_sock = MagicMock()
        assert exploit._inject_frame(mock_sock, b"\x00") is True

    def test_inject_frame_failure(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send.side_effect = OSError("broken")
        assert exploit._inject_frame(mock_sock, b"\x00") is False

    def test_open_raw_wifi_returns_none_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit._open_raw_wifi() is None

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_raw_wifi", return_value=None):
            assert exploit.check() is False
