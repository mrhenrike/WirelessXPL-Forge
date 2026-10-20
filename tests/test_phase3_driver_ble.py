"""Unit tests for Phase 3 Batch 1 driver/BLE CVE exploit modules."""
import importlib
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Module paths for Phase 3 Batch 1
_PHASE3_MODULES = [
    "wirelessxpl.modules.generic.wifi.mac80211_mbssid_uaf_rce_cve_2022_42719",
    "wirelessxpl.modules.generic.wifi.mac80211_bss_oob_write_cve_2022_41674",
    "wirelessxpl.modules.generic.bluetooth.l2cap_uaf_rce_cve_2022_42896",
    "wirelessxpl.modules.generic.bluetooth.bluez_hid_gatt_rce_cve_2024_8805",
    "wirelessxpl.modules.generic.access_points.broadcom.brcmfmac_sae_heap_overflow_cve_2026_72003",
]

_PHASE3_CVES = [
    ("wirelessxpl.modules.generic.wifi.mac80211_mbssid_uaf_rce_cve_2022_42719", "CVE-2022-42719"),
    ("wirelessxpl.modules.generic.wifi.mac80211_bss_oob_write_cve_2022_41674", "CVE-2022-41674"),
    ("wirelessxpl.modules.generic.bluetooth.l2cap_uaf_rce_cve_2022_42896", "CVE-2022-42896"),
    ("wirelessxpl.modules.generic.bluetooth.bluez_hid_gatt_rce_cve_2024_8805", "CVE-2024-8805"),
    ("wirelessxpl.modules.generic.access_points.broadcom.brcmfmac_sae_heap_overflow_cve_2026_72003", "CVE-2026-72003"),
]


class TestModuleImports:
    """Verify all Phase 3 Batch 1 modules import without error."""

    @pytest.mark.parametrize("module_path", _PHASE3_MODULES)
    def test_module_imports(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert hasattr(mod, "Exploit")

    @pytest.mark.parametrize("module_path", _PHASE3_MODULES)
    def test_exploit_has_required_methods(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "check")
        assert hasattr(instance, "run")
        assert callable(instance.check)
        assert callable(instance.run)

    @pytest.mark.parametrize("module_path", _PHASE3_MODULES)
    def test_exploit_has_target_option(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "timeout")

    @pytest.mark.parametrize("module_path,expected_cve", _PHASE3_CVES)
    def test_class_info_contains_cve(self, module_path: str, expected_cve: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert expected_cve in info.get("name", ""), f"CVE not found in __info__['name'] for {module_path}"


# ---------------------------------------------------------------------------
# mac80211 MBSSID UAF (CVE-2022-42719)
# ---------------------------------------------------------------------------

class TestMac80211MbssidUAF:
    """Tests for CVE-2022-42719 mac80211 MBSSID use-after-free RCE."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.wifi.mac80211_mbssid_uaf_rce_cve_2022_42719"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.channel = 6
        instance.timeout = 1.0
        instance.nesting_depth = 4
        instance.spray_count = 2
        return instance

    def test_ie_constants(self, exploit) -> None:
        assert exploit._IE_MULTI_BSSID == 71
        assert exploit._FC_BEACON == 0x0080
        assert exploit._FC_PROBE_RESPONSE == 0x0050

    def test_build_ie(self, exploit) -> None:
        ie = exploit._build_ie(0, b"test")
        assert ie[0] == 0
        assert ie[1] == 4
        assert ie[2:] == b"test"

    def test_build_mbssid_subelement(self, exploit) -> None:
        sub = exploit._build_mbssid_subelement(1)
        assert isinstance(sub, bytes)
        assert len(sub) > 4
        assert sub[0] == exploit._MBSSID_SUBELEMENT_PROFILE

    def test_build_nested_mbssid_returns_bytes(self, exploit) -> None:
        nested = exploit._build_nested_mbssid(3)
        assert isinstance(nested, bytes)
        assert len(nested) > 10

    def test_build_nested_mbssid_depth_zero(self, exploit) -> None:
        result = exploit._build_nested_mbssid(0)
        assert isinstance(result, bytes)
        assert result[0] == exploit._MBSSID_SUBELEMENT_PROFILE

    def test_build_beacon_frame(self, exploit) -> None:
        frame = exploit._build_beacon_frame()
        assert isinstance(frame, bytes)
        fc = struct.unpack("<H", frame[0:2])[0]
        assert fc == exploit._FC_BEACON
        assert len(frame) > 50

    def test_build_trigger_frame(self, exploit) -> None:
        frame = exploit._build_trigger_frame()
        assert isinstance(frame, bytes)
        fc = struct.unpack("<H", frame[0:2])[0]
        assert fc == exploit._FC_PROBE_RESPONSE

    def test_mac_to_bytes(self, exploit) -> None:
        result = exploit._mac_to_bytes("02:00:de:ad:be:ef")
        assert result == b"\x02\x00\xde\xad\xbe\xef"

    def test_check_returns_false_on_oserror(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit.check() is False

    def test_send_raw_returns_false_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit._send_raw(b"\x00") is False


# ---------------------------------------------------------------------------
# mac80211 BSS OOB Write (CVE-2022-41674)
# ---------------------------------------------------------------------------

class TestMac80211BssOobWrite:
    """Tests for CVE-2022-41674 mac80211 BSS info out-of-bounds write."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.wifi.mac80211_bss_oob_write_cve_2022_41674"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.channel = 6
        instance.timeout = 1.0
        instance.overflow_size = 512
        instance.spray_count = 2
        return instance

    def test_constants(self, exploit) -> None:
        assert exploit._IE_VENDOR_SPECIFIC == 221
        assert exploit._FC_BEACON == 0x0080

    def test_build_oversized_ies_returns_bytes(self, exploit) -> None:
        ies = exploit._build_oversized_ies()
        assert isinstance(ies, bytes)
        assert len(ies) > exploit.overflow_size

    def test_build_oversized_ies_contains_vendor_ies(self, exploit) -> None:
        ies = exploit._build_oversized_ies()
        assert b"\x00\x50\xf2" in ies

    def test_build_probe_response(self, exploit) -> None:
        frame = exploit._build_probe_response()
        assert isinstance(frame, bytes)
        fc = struct.unpack("<H", frame[0:2])[0]
        assert fc == exploit._FC_PROBE_RESPONSE
        assert len(frame) > 100

    def test_build_beacon_frame(self, exploit) -> None:
        frame = exploit._build_beacon_frame()
        assert isinstance(frame, bytes)
        fc = struct.unpack("<H", frame[0:2])[0]
        assert fc == exploit._FC_BEACON

    def test_check_returns_false_on_oserror(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit.check() is False

    def test_inject_frame_returns_false_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit._inject_frame(b"\x00") is False

    def test_overflow_size_affects_ies_length(self, exploit) -> None:
        exploit.overflow_size = 256
        small = exploit._build_oversized_ies()
        exploit.overflow_size = 1024
        large = exploit._build_oversized_ies()
        assert len(large) > len(small)


# ---------------------------------------------------------------------------
# L2CAP UAF RCE (CVE-2022-42896)
# ---------------------------------------------------------------------------

class TestL2capUAF:
    """Tests for CVE-2022-42896 Linux Kernel Bluetooth L2CAP UAF."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.l2cap_uaf_rce_cve_2022_42896"
        )
        instance = mod.Exploit()
        instance.target = "192.168.1.100"
        instance.port = 1
        instance.timeout = 1.0
        instance.race_iterations = 4
        instance.spray_count = 2
        return instance

    def test_l2cap_constants(self, exploit) -> None:
        assert exploit._L2CAP_CID_SIGNALING == 0x0001
        assert exploit._L2CAP_CMD_CONN_REQ == 0x02
        assert exploit._L2CAP_CMD_DISCONN_REQ == 0x06

    def test_build_l2cap_connect_req(self, exploit) -> None:
        pkt = exploit._build_l2cap_connect_req(psm=1, scid=0x0040, ident=1)
        assert isinstance(pkt, bytes)
        # L2CAP header (4) + command header (4) + payload (4) = 12
        assert len(pkt) == 12
        # L2CAP CID should be signaling channel
        cid = struct.unpack_from("<H", pkt, 2)[0]
        assert cid == exploit._L2CAP_CID_SIGNALING
        # Command code
        assert pkt[4] == exploit._L2CAP_CMD_CONN_REQ

    def test_build_l2cap_disconnect(self, exploit) -> None:
        pkt = exploit._build_l2cap_disconnect(dcid=0x0040, scid=0x0040, ident=2)
        assert isinstance(pkt, bytes)
        assert len(pkt) == 12
        assert pkt[4] == exploit._L2CAP_CMD_DISCONN_REQ

    def test_build_connect_req_psm_encoded(self, exploit) -> None:
        pkt = exploit._build_l2cap_connect_req(psm=3, scid=0x0050, ident=5)
        # PSM is at offset 8 (after L2CAP header 4 + cmd header 4)
        psm = struct.unpack_from("<H", pkt, 8)[0]
        assert psm == 3
        scid = struct.unpack_from("<H", pkt, 10)[0]
        assert scid == 0x0050

    def test_trigger_uaf_sequence_sends_packets(self, exploit) -> None:
        mock_sock = MagicMock()
        result = exploit._trigger_uaf_sequence(mock_sock, 0)
        assert result is True
        assert mock_sock.send.call_count == 2

    def test_trigger_uaf_sequence_handles_oserror(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send.side_effect = OSError("broken")
        result = exploit._trigger_uaf_sequence(mock_sock, 0)
        assert result is False

    def test_check_returns_false_on_connection_failure(self, exploit) -> None:
        with patch.object(exploit, "_bt_connect", return_value=None):
            assert exploit.check() is False

    def test_check_returns_true_on_response(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x03\x01\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        with patch.object(exploit, "_bt_connect", return_value=mock_sock):
            assert exploit.check() is True
        mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# BlueZ HID over GATT (CVE-2024-8805)
# ---------------------------------------------------------------------------

class TestBlueZHidGatt:
    """Tests for CVE-2024-8805 BlueZ HID over GATT unauthorized RCE."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.bluez_hid_gatt_rce_cve_2024_8805"
        )
        instance = mod.Exploit()
        instance.target = "192.168.1.100"
        instance.port = 4
        instance.timeout = 1.0
        instance.command = "id"
        instance.keystroke_delay = 0.001
        return instance

    def test_gatt_constants(self, exploit) -> None:
        assert exploit._HID_SERVICE_UUID == 0x1812
        assert exploit._HID_REPORT_CHAR_UUID == 0x2A4D
        assert exploit._BLE_ATT_CID == 0x0004

    def test_build_hid_report(self, exploit) -> None:
        report = exploit._build_hid_report(modifier=0, keycode=0x04)
        assert isinstance(report, bytes)
        assert len(report) == 8
        assert report[0] == 0
        assert report[2] == 0x04

    def test_build_hid_report_with_modifier(self, exploit) -> None:
        report = exploit._build_hid_report(modifier=0x02, keycode=0x04)
        assert report[0] == 0x02
        assert report[2] == 0x04

    def test_build_att_read_by_group_type(self, exploit) -> None:
        pkt = exploit._build_att_read_by_group_type(0x0001, 0xFFFF, 0x2800)
        assert isinstance(pkt, bytes)
        assert pkt[0] == exploit._ATT_READ_BY_GROUP_TYPE_REQ
        start = struct.unpack_from("<H", pkt, 1)[0]
        assert start == 0x0001

    def test_build_att_write(self, exploit) -> None:
        pkt = exploit._build_att_write(0x0010, b"\x00\x00\x04\x00\x00\x00\x00\x00")
        assert pkt[0] == exploit._ATT_WRITE_REQ
        handle = struct.unpack_from("<H", pkt, 1)[0]
        assert handle == 0x0010

    def test_char_to_hid_lowercase(self, exploit) -> None:
        mod, key = exploit._char_to_hid("a")
        assert mod == 0x00
        assert key == 0x04

    def test_char_to_hid_uppercase(self, exploit) -> None:
        mod, key = exploit._char_to_hid("A")
        assert mod == 0x02
        assert key == 0x04

    def test_char_to_hid_unknown(self, exploit) -> None:
        mod, key = exploit._char_to_hid("~")
        assert key == 0

    def test_keymap_has_common_chars(self, exploit) -> None:
        for c in "abcdefghijklmnopqrstuvwxyz0123456789 ":
            assert c in exploit._KEYMAP

    def test_scan_gatt_services_returns_none_on_error(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError("timeout")
        result = exploit._scan_gatt_services(mock_sock)
        assert result is None

    def test_scan_gatt_services_finds_hid(self, exploit) -> None:
        mock_sock = MagicMock()
        # ATT Read By Group Type Response: opcode=0x11, length=6, handle=0x0010, end=0x001A, uuid=0x1812
        response = struct.pack("<BBHHH", 0x11, 6, 0x0010, 0x001A, 0x1812)
        mock_sock.recv.return_value = response
        result = exploit._scan_gatt_services(mock_sock)
        assert result == 0x0010

    def test_check_returns_false_on_connection_failure(self, exploit) -> None:
        with patch.object(exploit, "_ble_connect", return_value=None):
            assert exploit.check() is False

    def test_write_gatt_returns_true_on_success(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = bytes([exploit._ATT_WRITE_RSP])
        result = exploit._write_gatt_characteristic(mock_sock, 0x0010, b"\x00" * 8)
        assert result is True

    def test_write_gatt_returns_false_on_error(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = bytes([exploit._ATT_ERROR_RSP, 0x12, 0x00, 0x10, 0x05])
        result = exploit._write_gatt_characteristic(mock_sock, 0x0010, b"\x00" * 8)
        assert result is False


# ---------------------------------------------------------------------------
# Broadcom brcmfmac SAE Heap Overflow (CVE-2026-72003)
# ---------------------------------------------------------------------------

class TestBrcmfmacSaeHeap:
    """Tests for CVE-2026-72003 Broadcom brcmfmac SAE heap overflow."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.broadcom.brcmfmac_sae_heap_overflow_cve_2026_72003"
        )
        instance = mod.Exploit()
        instance.interface = "wlan0"
        instance.target = "192.168.1.100"
        instance.port = 1
        instance.timeout = 1.0
        instance.channel = 6
        instance.ssid = "TestAP"
        return instance

    def test_sae_constants(self, exploit) -> None:
        assert exploit._AUTH_ALG_SAE == 3
        assert exploit._SAE_COMMIT == 1
        assert exploit._SAE_GROUP_19 == 19
        assert exploit._SAE_SCALAR_SIZE == 32
        assert exploit._SAE_ELEMENT_SIZE == 64

    def test_build_sae_commit_frame_normal(self, exploit) -> None:
        frame = exploit._build_sae_commit_frame(truncated=False)
        assert isinstance(frame, bytes)
        # 802.11 header (24) + auth_alg(2) + auth_seq(2) + status(2) + group(2) + scalar(32) + element(64) = 128
        assert len(frame) == 128

    def test_build_sae_commit_frame_truncated(self, exploit) -> None:
        frame = exploit._build_sae_commit_frame(truncated=True)
        assert isinstance(frame, bytes)
        # truncated: 24 + 2 + 2 + 2 + 2 + 8 = 40
        assert len(frame) == 40
        # Verify the truncated payload is 0xCC fill
        assert frame[-8:] == b"\xCC" * 8

    def test_truncated_shorter_than_normal(self, exploit) -> None:
        normal = exploit._build_sae_commit_frame(truncated=False)
        truncated = exploit._build_sae_commit_frame(truncated=True)
        assert len(truncated) < len(normal)

    def test_build_sae_auth_frame(self, exploit) -> None:
        frame = exploit._build_sae_auth_frame(auth_seq=1)
        assert isinstance(frame, bytes)
        fc = struct.unpack("<H", frame[0:2])[0]
        assert fc == exploit._FC_AUTH

    def test_build_beacon_frame(self, exploit) -> None:
        frame = exploit._build_beacon_frame()
        assert isinstance(frame, bytes)
        fc = struct.unpack("<H", frame[0:2])[0]
        assert fc == exploit._FC_BEACON
        assert b"TestAP" in frame

    def test_build_rsn_ie_sae(self, exploit) -> None:
        rsn = exploit._build_rsn_ie_sae()
        assert isinstance(rsn, bytes)
        assert rsn[0] == 48  # RSN IE tag
        # Check SAE AKM suite type 8
        assert b"\x00\x0F\xAC\x08" in rsn

    def test_check_returns_true_on_socket_success(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            assert exploit.check() is True
            mock_sock.close.assert_called_once()

    def test_check_returns_false_on_oserror(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit.check() is False

    def test_mac_to_bytes(self, exploit) -> None:
        result = exploit._mac_to_bytes("AA:BB:CC:DD:EE:FF")
        assert result == bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
