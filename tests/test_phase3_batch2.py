"""Unit tests for Phase 3 Batch 2 driver/BLE CVE exploit modules."""
import importlib
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Module paths for Phase 3 Batch 2
_PHASE3B2_MODULES = [
    "wirelessxpl.modules.generic.wifi.mac80211_bss_refcount_uaf_cve_2022_42720",
    "wirelessxpl.modules.generic.bluetooth.bluez_pbap_heap_overflow_cve_2023_50230",
    "wirelessxpl.modules.generic.bluetooth.bluez_avrcp_stack_overflow_cve_2023_44431",
    "wirelessxpl.modules.generic.access_points.broadcom.brcmfmac_wakeup_heap_overflow_cve_2019_9500",
    "wirelessxpl.modules.generic.bluetooth.bluez_eir_stack_overflow_cve_2026_80186",
]

_PHASE3B2_CVES = [
    ("wirelessxpl.modules.generic.wifi.mac80211_bss_refcount_uaf_cve_2022_42720", "CVE-2022-42720"),
    ("wirelessxpl.modules.generic.bluetooth.bluez_pbap_heap_overflow_cve_2023_50230", "CVE-2023-50230"),
    ("wirelessxpl.modules.generic.bluetooth.bluez_avrcp_stack_overflow_cve_2023_44431", "CVE-2023-44431"),
    ("wirelessxpl.modules.generic.access_points.broadcom.brcmfmac_wakeup_heap_overflow_cve_2019_9500", "CVE-2019-9500"),
    ("wirelessxpl.modules.generic.bluetooth.bluez_eir_stack_overflow_cve_2026_80186", "CVE-2026-80186"),
]


class TestBatch2ModuleImports:
    """Verify all Phase 3 Batch 2 modules import without error."""

    @pytest.mark.parametrize("module_path", _PHASE3B2_MODULES)
    def test_module_imports(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert hasattr(mod, "Exploit")

    @pytest.mark.parametrize("module_path", _PHASE3B2_MODULES)
    def test_exploit_has_required_methods(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "check")
        assert hasattr(instance, "run")
        assert callable(instance.check)
        assert callable(instance.run)

    @pytest.mark.parametrize("module_path", _PHASE3B2_MODULES)
    def test_exploit_has_timeout_option(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "timeout")

    @pytest.mark.parametrize("module_path,expected_cve", _PHASE3B2_CVES)
    def test_class_info_contains_cve(self, module_path: str, expected_cve: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert expected_cve in info.get("name", ""), f"CVE not found in __info__['name'] for {module_path}"

    @pytest.mark.parametrize("module_path", _PHASE3B2_MODULES)
    def test_exploit_has_info_dict(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert "name" in info
        assert "description" in info
        assert "authors" in info
        assert "references" in info


# ---------------------------------------------------------------------------
# mac80211 BSS Refcount UAF (CVE-2022-42720)
# ---------------------------------------------------------------------------

class TestMac80211BssRefcountUAF:
    """Tests for CVE-2022-42720 mac80211 BSS refcounting use-after-free."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.wifi.mac80211_bss_refcount_uaf_cve_2022_42720"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.bss_count = 4
        instance.injection_rounds = 2
        return instance

    def test_frame_constants(self, exploit) -> None:
        assert exploit._FRAME_TYPE_MGMT == 0x00
        assert exploit._SUBTYPE_BEACON == 0x08
        assert exploit._IE_MULTIPLE_BSSID == 71

    def test_build_radiotap_header(self, exploit) -> None:
        hdr = exploit._build_radiotap_header()
        assert isinstance(hdr, bytes)
        assert len(hdr) == 8

    def test_build_frame_control(self, exploit) -> None:
        fc = exploit._build_frame_control(0x00, 0x08)
        assert isinstance(fc, bytes)
        assert len(fc) == 2

    def test_build_ie(self, exploit) -> None:
        ie = exploit._build_ie(0, b"test")
        assert ie[0] == 0
        assert ie[1] == 4
        assert ie[2:] == b"test"

    def test_build_ie_empty(self, exploit) -> None:
        ie = exploit._build_ie(0, b"")
        assert ie[0] == 0
        assert ie[1] == 0

    def test_build_nontransmitted_profile(self, exploit) -> None:
        profile = exploit._build_nontransmitted_profile(1, 0)
        assert isinstance(profile, bytes)
        assert len(profile) > 4
        assert profile[0] == exploit._IE_NONTRANSMITTED_BSSID_PROFILE

    def test_build_multi_bss_beacon(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        frame = exploit._build_multi_bss_beacon(src, 6)
        assert isinstance(frame, bytes)
        assert len(frame) > 100
        assert b"trigger-refcount" in frame

    def test_build_multi_bss_beacon_contains_radiotap(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        frame = exploit._build_multi_bss_beacon(src, 6)
        radiotap = exploit._build_radiotap_header()
        assert frame[:len(radiotap)] == radiotap

    def test_build_probe_request(self, exploit) -> None:
        probe = exploit._build_probe_request()
        assert isinstance(probe, bytes)
        assert len(probe) > 20

    def test_inject_frame_returns_true_on_success(self, exploit) -> None:
        mock_sock = MagicMock()
        assert exploit._inject_frame(mock_sock, b"\x00") is True
        mock_sock.send.assert_called_once_with(b"\x00")

    def test_inject_frame_returns_false_on_error(self, exploit) -> None:
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

    def test_bss_count_affects_beacon_size(self, exploit) -> None:
        src = b"\x02\x00\x00\x00\x00\x01"
        exploit.bss_count = 2
        small = exploit._build_multi_bss_beacon(src, 6)
        exploit.bss_count = 8
        large = exploit._build_multi_bss_beacon(src, 6)
        assert len(large) > len(small)


# ---------------------------------------------------------------------------
# BlueZ PBAP Heap Overflow (CVE-2023-50230)
# ---------------------------------------------------------------------------

class TestBlueZPbapHeap:
    """Tests for CVE-2023-50230 BlueZ PBAP heap buffer overflow."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.bluez_pbap_heap_overflow_cve_2023_50230"
        )
        instance = mod.Exploit()
        instance.target = "192.168.1.100"
        instance.port = 19
        instance.timeout = 1.0
        instance.overflow_size = 4096
        instance.interface = "hci0"
        return instance

    def test_obex_constants(self, exploit) -> None:
        assert exploit._OBEX_CONNECT == 0x80
        assert exploit._OBEX_CONNECT_RSP == 0xA0
        assert exploit._OBEX_GET_FINAL == 0x83
        assert exploit._OBEX_SUCCESS == 0xA0

    def test_pbap_target_uuid_length(self, exploit) -> None:
        assert len(exploit._PBAP_TARGET_UUID) == 16

    def test_build_obex_header(self, exploit) -> None:
        hdr = exploit._build_obex_header(0x48, b"test")
        assert isinstance(hdr, bytes)
        assert hdr[0] == 0x48
        length = struct.unpack(">H", hdr[1:3])[0]
        assert length == 3 + 4

    def test_build_obex_connect_response(self, exploit) -> None:
        rsp = exploit._build_obex_connect_response()
        assert isinstance(rsp, bytes)
        assert rsp[0] == exploit._OBEX_CONNECT_RSP
        assert exploit._PBAP_TARGET_UUID in rsp

    def test_build_pbap_response(self, exploit) -> None:
        rsp = exploit._build_pbap_response(128)
        assert isinstance(rsp, bytes)
        assert rsp[0] == exploit._OBEX_SUCCESS
        assert b"BEGIN:VCARD" in rsp
        assert b"END:VCARD" in rsp

    def test_build_pbap_response_overflow_size(self, exploit) -> None:
        small = exploit._build_pbap_response(64)
        large = exploit._build_pbap_response(4096)
        assert len(large) > len(small)

    def test_build_pbap_response_contains_padding(self, exploit) -> None:
        rsp = exploit._build_pbap_response(100)
        assert b"X" * 100 in rsp

    def test_setup_sdp_record(self, exploit) -> None:
        record = exploit._setup_sdp_record()
        assert "ServiceClassIDList" in record
        assert "0x112f" in record["ServiceClassIDList"]

    def test_bt_listen_returns_none_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no bt")
            assert exploit._bt_listen() is None

    def test_bt_scan_returns_none_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.connect.side_effect = OSError("no bt")
            assert exploit._bt_scan() is None

    def test_check_returns_false_on_bt_scan_failure(self, exploit) -> None:
        with patch.object(exploit, "_bt_scan", return_value=None):
            assert exploit.check() is False

    def test_check_returns_true_on_bt_scan_success(self, exploit) -> None:
        mock_sock = MagicMock()
        with patch.object(exploit, "_bt_scan", return_value=mock_sock):
            assert exploit.check() is True
        mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# BlueZ AVRCP Stack Overflow (CVE-2023-44431)
# ---------------------------------------------------------------------------

class TestBlueZAvrcpStack:
    """Tests for CVE-2023-44431 BlueZ AVRCP stack buffer overflow."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.bluez_avrcp_stack_overflow_cve_2023_44431"
        )
        instance = mod.Exploit()
        instance.target = "192.168.1.100"
        instance.port = 23
        instance.timeout = 1.0
        instance.overflow_size = 2048
        instance.interface = "hci0"
        return instance

    def test_avctp_constants(self, exploit) -> None:
        assert exploit._AVCTP_PSM == 23
        assert exploit._AVCTP_CR_RESPONSE == 0x01
        assert exploit._AVC_OPCODE_VENDOR == 0x00

    def test_avrcp_pdu_constant(self, exploit) -> None:
        assert exploit._AVRCP_PDU_GET_ELEMENT_ATTR == 0x20

    def test_company_bt_sig(self, exploit) -> None:
        assert bytes([0x00, 0x19, 0x58]) == exploit._AVRCP_COMPANY_BT_SIG

    def test_build_oversized_attribute(self, exploit) -> None:
        attr = exploit._build_oversized_attribute(0x01, 100)
        assert isinstance(attr, bytes)
        attr_id = struct.unpack(">H", attr[0:2])[0]
        assert attr_id == 0x01
        assert b"A" * 100 in attr

    def test_build_oversized_attribute_size(self, exploit) -> None:
        small = exploit._build_oversized_attribute(0x01, 64)
        large = exploit._build_oversized_attribute(0x01, 512)
        assert len(large) > len(small)

    def test_build_avrcp_response(self, exploit) -> None:
        params = b"\x01\x00\x00\x00\x01\x00\x6A\x00\x04test"
        rsp = exploit._build_avrcp_response(0x20, params)
        assert isinstance(rsp, bytes)
        assert len(rsp) > len(params)

    def test_build_get_element_attr_response(self, exploit) -> None:
        rsp = exploit._build_get_element_attr_response()
        assert isinstance(rsp, bytes)
        assert len(rsp) > 2048

    def test_build_avctp_packet(self, exploit) -> None:
        pkt = exploit._build_avctp_packet(1, b"\x00\x01\x02")
        assert isinstance(pkt, bytes)
        assert len(pkt) == 3 + 3
        first_byte = pkt[0]
        tl = (first_byte >> 4) & 0x0F
        assert tl == 1

    def test_l2cap_send_returns_true(self, exploit) -> None:
        mock_sock = MagicMock()
        assert exploit._l2cap_send(mock_sock, b"\x00") is True

    def test_l2cap_send_returns_false_on_error(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send.side_effect = OSError("broken")
        assert exploit._l2cap_send(mock_sock, b"\x00") is False

    def test_bt_listen_l2cap_returns_none_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no bt")
            assert exploit._bt_listen_l2cap() is None

    def test_bt_connect_l2cap_returns_none_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.connect.side_effect = OSError("no bt")
            assert exploit._bt_connect_l2cap() is None

    def test_check_returns_false_on_failure(self, exploit) -> None:
        with patch.object(exploit, "_bt_connect_l2cap", return_value=None):
            assert exploit.check() is False


# ---------------------------------------------------------------------------
# Broadcom brcmfmac Wakeup Heap Overflow (CVE-2019-9500)
# ---------------------------------------------------------------------------

class TestBrcmfmacWakeupHeap:
    """Tests for CVE-2019-9500 brcmfmac wake-up frame heap overflow."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.broadcom.brcmfmac_wakeup_heap_overflow_cve_2019_9500"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0"
        instance.target = "192.168.1.100"
        instance.timeout = 1.0
        instance.channel = 6
        instance.overflow_size = 4096
        return instance

    def test_broadcom_oui(self, exploit) -> None:
        assert exploit._BROADCOM_OUI == b"\x00\x10\x18"

    def test_wow_event_type(self, exploit) -> None:
        assert exploit._WOW_EVENT_TYPE == 0x004E

    def test_mac_to_bytes(self, exploit) -> None:
        result = exploit._mac_to_bytes("02:00:DE:AD:BE:EF")
        assert result == b"\x02\x00\xDE\xAD\xBE\xEF"

    def test_build_wakeup_event_normal(self, exploit) -> None:
        frame = exploit._build_wakeup_event(oversized=False)
        assert isinstance(frame, bytes)
        assert len(frame) > 50

    def test_build_wakeup_event_oversized(self, exploit) -> None:
        frame = exploit._build_wakeup_event(oversized=True)
        assert isinstance(frame, bytes)
        assert len(frame) > exploit.overflow_size

    def test_oversized_larger_than_normal(self, exploit) -> None:
        normal = exploit._build_wakeup_event(oversized=False)
        oversized = exploit._build_wakeup_event(oversized=True)
        assert len(oversized) > len(normal)

    def test_build_wakeup_event_contains_ether_type(self, exploit) -> None:
        frame = exploit._build_wakeup_event(oversized=False)
        assert b"\x88\x6C" in frame[:20]

    def test_build_vendor_ie_probe(self, exploit) -> None:
        probe = exploit._build_vendor_ie_probe()
        assert isinstance(probe, bytes)
        assert exploit._BROADCOM_OUI in probe

    def test_inject_wakeup_frame_returns_true(self, exploit) -> None:
        mock_sock = MagicMock()
        assert exploit._inject_wakeup_frame(mock_sock, b"\x00") is True

    def test_inject_wakeup_frame_returns_false_on_error(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send.side_effect = OSError("broken")
        assert exploit._inject_wakeup_frame(mock_sock, b"\x00") is False

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit.check() is False

    def test_overflow_size_affects_frame(self, exploit) -> None:
        exploit.overflow_size = 256
        small = exploit._build_wakeup_event(oversized=True)
        exploit.overflow_size = 8192
        large = exploit._build_wakeup_event(oversized=True)
        assert len(large) > len(small)


# ---------------------------------------------------------------------------
# BlueZ EIR Stack Overflow (CVE-2026-80186)
# ---------------------------------------------------------------------------

class TestBlueZEirStack:
    """Tests for CVE-2026-80186 BlueZ EIR stack buffer overflow."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.bluez_eir_stack_overflow_cve_2026_80186"
        )
        instance = mod.Exploit()
        instance.target = "192.168.1.100"
        instance.timeout = 1.0
        instance.hci_device = "hci0"
        instance.overflow_size = 512
        return instance

    def test_eir_constants(self, exploit) -> None:
        assert exploit._EIR_FLAGS == 0x01
        assert exploit._EIR_NAME_COMPLETE == 0x09
        assert exploit._EIR_MANUFACTURER == 0xFF
        assert exploit._EIR_MAX_SIZE == 240

    def test_hci_constants(self, exploit) -> None:
        assert exploit._HCI_EVENT_PKT == 0x04

    def test_bd_addr_to_bytes(self, exploit) -> None:
        result = exploit._bd_addr_to_bytes("AA:BB:CC:DD:EE:FF")
        assert len(result) == 6
        assert result == bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])

    def test_build_eir_data_normal(self, exploit) -> None:
        eir = exploit._build_eir_data(oversized=False)
        assert isinstance(eir, bytes)
        assert b"TestDevice" in eir

    def test_build_eir_data_oversized(self, exploit) -> None:
        eir = exploit._build_eir_data(oversized=True)
        assert isinstance(eir, bytes)
        assert len(eir) > exploit._EIR_MAX_SIZE

    def test_oversized_larger_than_normal(self, exploit) -> None:
        normal = exploit._build_eir_data(oversized=False)
        oversized = exploit._build_eir_data(oversized=True)
        assert len(oversized) > len(normal)

    def test_build_eir_data_starts_with_flags(self, exploit) -> None:
        eir = exploit._build_eir_data(oversized=False)
        assert eir[0] == 2
        assert eir[1] == exploit._EIR_FLAGS

    def test_build_inquiry_response_normal(self, exploit) -> None:
        pkt = exploit._build_inquiry_response(oversized=False)
        assert isinstance(pkt, bytes)
        assert pkt[1] == 0x2F

    def test_build_inquiry_response_oversized(self, exploit) -> None:
        exploit.overflow_size = 200
        pkt = exploit._build_inquiry_response(oversized=True)
        assert isinstance(pkt, bytes)
        assert len(pkt) > exploit._EIR_MAX_SIZE

    def test_inquiry_response_event_code(self, exploit) -> None:
        pkt = exploit._build_inquiry_response(oversized=False)
        assert pkt[1] == 0x2F

    def test_hci_send_returns_false_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no bt")
            assert exploit._hci_send(b"\x00") is False

    def test_check_returns_false_on_error(self, exploit) -> None:
        with patch.object(exploit, "_check_hci_available", return_value=False):
            assert exploit.check() is False

    def test_check_returns_true_on_success(self, exploit) -> None:
        with patch.object(exploit, "_check_hci_available", return_value=True):
            assert exploit.check() is True

    def test_overflow_size_affects_eir(self, exploit) -> None:
        exploit.overflow_size = 128
        small = exploit._build_eir_data(oversized=True)
        exploit.overflow_size = 512
        large = exploit._build_eir_data(oversized=True)
        assert len(large) > len(small)
