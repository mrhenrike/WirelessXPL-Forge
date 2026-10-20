# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Phase 5A: Bluetooth/BLE kernel CVE modules test suite.

Tests for 10 modules:
  1. zephyr_l2cap_overflow_cve_2026_5068
  2. linux_ssp_passkey_uaf_cve_2026_46056
  3. linux_rfcomm_mcc_oob_cve_2026_53254
  4. linux_hci_sync_uaf_cve_2026_68393
  5. linux_bnep_uaf_cve_2026_64178
  6. apple_bt_dos_cve_2026_20650
  7. ti_ble_ll_length_dos_cve_2025_44525
  8. realtek_ble_ll_length_dos_cve_2025_44526
  9. pebble_ble_missing_auth_cve_2025_69969
 10. mousejack_nrf24_hid
"""
from __future__ import annotations

import importlib
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = str(Path(__file__).resolve().parent.parent)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


PHASE5A_MODULES = [
    "wirelessxpl.modules.generic.bluetooth.zephyr_l2cap_overflow_cve_2026_5068",
    "wirelessxpl.modules.generic.bluetooth.linux_ssp_passkey_uaf_cve_2026_46056",
    "wirelessxpl.modules.generic.bluetooth.linux_rfcomm_mcc_oob_cve_2026_53254",
    "wirelessxpl.modules.generic.bluetooth.linux_hci_sync_uaf_cve_2026_68393",
    "wirelessxpl.modules.generic.bluetooth.linux_bnep_uaf_cve_2026_64178",
    "wirelessxpl.modules.generic.bluetooth.apple_bt_dos_cve_2026_20650",
    "wirelessxpl.modules.generic.bluetooth.ti_ble_ll_length_dos_cve_2025_44525",
    "wirelessxpl.modules.generic.bluetooth.realtek_ble_ll_length_dos_cve_2025_44526",
    "wirelessxpl.modules.generic.bluetooth.pebble_ble_missing_auth_cve_2025_69969",
    "wirelessxpl.modules.generic.bluetooth.mousejack_nrf24_hid",
]

CVE_MODULES = PHASE5A_MODULES[:9]


# ---------------------------------------------------------------------------
# Parametrised: import, required methods, timeout, exploit_attributes, __info__
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module_path", PHASE5A_MODULES)
class TestPhase5ACommon:
    def test_import(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert hasattr(mod, "Exploit")

    def test_has_check(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert callable(getattr(mod.Exploit, "check", None))

    def test_has_run(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert callable(getattr(mod.Exploit, "run", None))

    def test_has_exploit(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert callable(getattr(mod.Exploit, "_exploit", None))

    def test_timeout_option(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "timeout")
        assert float(instance.timeout) > 0

    def test_exploit_attributes_returns_dict(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        attrs = instance.exploit_attributes
        assert isinstance(attrs, dict)

    def test_info_dict_has_required_keys(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        info = mod.Exploit._Exploit__info__
        assert isinstance(info, dict)
        for key in ("name", "description", "authors", "references"):
            assert key in info, f"Missing key: {key}"

    def test_info_name_not_empty(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        info = mod.Exploit._Exploit__info__
        assert len(info["name"]) > 0

    def test_info_authors_is_tuple(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        info = mod.Exploit._Exploit__info__
        assert isinstance(info["authors"], tuple)
        assert len(info["authors"]) >= 1


@pytest.mark.parametrize("module_path", CVE_MODULES)
class TestPhase5ACVEInName:
    def test_cve_in_module_name(self, module_path: str) -> None:
        assert "cve_20" in module_path.lower()

    def test_cve_in_info_name(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        info = mod.Exploit._Exploit__info__
        assert "CVE-20" in info["name"]


# ---------------------------------------------------------------------------
# Zephyr L2CAP Overflow (CVE-2026-5068)
# ---------------------------------------------------------------------------

class TestZephyrL2capOverflow:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.zephyr_l2cap_overflow_cve_2026_5068"
        )
        instance = mod.Exploit()
        instance.interface = "hci0"
        instance.timeout = 1.0
        instance.mtu_overflow = 8192
        instance.mps_overflow = 4096
        instance.sdu_size = 16384
        return instance

    def test_l2cap_signaling_cid(self, exploit) -> None:
        assert exploit._L2CAP_CID_LE_SIGNALING == 0x0005

    def test_le_credit_conn_req_code(self, exploit) -> None:
        assert exploit._L2CAP_LE_CREDIT_CONN_REQ == 0x14

    def test_build_le_credit_conn_req(self, exploit) -> None:
        pkt = exploit._build_le_credit_conn_req(psm=0x0025, scid=0x0040, identifier=1)
        assert isinstance(pkt, bytes)
        assert pkt[0] == 0x14
        assert len(pkt) == 4 + 10

    def test_build_le_sdu_segment_first(self, exploit) -> None:
        seg = exploit._build_le_sdu_segment(0x0040, b"\x41" * 100, first=True, sdu_length=1000)
        assert isinstance(seg, bytes)
        sdu_len = struct.unpack_from("<H", seg, 4)[0]
        assert sdu_len == 1000

    def test_build_le_sdu_segment_continuation(self, exploit) -> None:
        seg = exploit._build_le_sdu_segment(0x0040, b"\x42" * 50, first=False)
        assert isinstance(seg, bytes)
        dcid = struct.unpack_from("<H", seg, 0)[0]
        assert dcid == 0x0040

    def test_open_hci_returns_none_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit._open_hci_socket() is None

    def test_open_l2cap_returns_none_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit._open_l2cap_socket() is None

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_hci_socket", return_value=None):
            assert exploit.check() is False

    def test_bd_addr_to_bytes(self, exploit) -> None:
        result = exploit._bd_addr_to_bytes("AA:BB:CC:DD:EE:FF")
        assert result == bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])


# ---------------------------------------------------------------------------
# Linux SSP Passkey UAF (CVE-2026-46056)
# ---------------------------------------------------------------------------

class TestLinuxSSPPasskeyUAF:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.linux_ssp_passkey_uaf_cve_2026_46056"
        )
        instance = mod.Exploit()
        instance.interface = "hci0"
        instance.timeout = 1.0
        return instance

    def test_hci_ev_passkey_notify(self, exploit) -> None:
        assert exploit._HCI_EV_USER_PASSKEY_NOTIFY == 0x3B

    def test_ogf_link_ctl(self, exploit) -> None:
        assert exploit._OGF_LINK_CTL == 0x01

    def test_build_hci_command(self, exploit) -> None:
        cmd = exploit._build_hci_command(0x01, 0x0006, b"\x40\x00\x13")
        assert isinstance(cmd, bytes)
        assert cmd[0] == exploit._HCI_COMMAND_PKT

    def test_build_passkey_notify_event(self, exploit) -> None:
        evt = exploit._build_passkey_notify_event(123456)
        assert isinstance(evt, bytes)
        assert evt[0] == exploit._HCI_EVENT_PKT

    def test_build_disconnect_command(self, exploit) -> None:
        cmd = exploit._build_disconnect_command(0x0040, reason=0x13)
        assert isinstance(cmd, bytes)

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_hci_socket", return_value=None):
            assert exploit.check() is False

    def test_bd_addr_to_bytes(self, exploit) -> None:
        result = exploit._bd_addr_to_bytes("11:22:33:44:55:66")
        assert result == bytes([0x66, 0x55, 0x44, 0x33, 0x22, 0x11])


# ---------------------------------------------------------------------------
# Linux RFCOMM MCC OOB (CVE-2026-53254)
# ---------------------------------------------------------------------------

class TestLinuxRFCOMMMCCOOB:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.linux_rfcomm_mcc_oob_cve_2026_53254"
        )
        instance = mod.Exploit()
        instance.interface = "hci0"
        instance.timeout = 1.0
        return instance

    def test_rfcomm_frame_constants(self, exploit) -> None:
        assert exploit._RFCOMM_SABM == 0x2F
        assert exploit._RFCOMM_UA == 0x63
        assert exploit._RFCOMM_UIH == 0xEF
        assert exploit._RFCOMM_DM == 0x0F

    def test_mcc_type_constants(self, exploit) -> None:
        assert exploit._MCC_TEST == 0x08
        assert exploit._MCC_MSC == 0x0E
        assert exploit._MCC_RPN == 0x09

    def test_build_rfcomm_mcc_frame(self, exploit) -> None:
        frame = exploit._build_rfcomm_mcc_frame(exploit._MCC_TEST, b"\xFF" * 300)
        assert isinstance(frame, bytes)
        assert len(frame) > 300

    def test_compute_fcs(self, exploit) -> None:
        fcs = exploit._compute_fcs(b"\x03\xEF")
        assert isinstance(fcs, int)
        assert 0 <= fcs <= 255

    def test_dlci_control(self, exploit) -> None:
        assert exploit._DLCI_CONTROL == 0x00

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_hci_socket", return_value=None):
            assert exploit.check() is False

    def test_hci_send_success(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            assert exploit._hci_send(b"\x00") is True

    def test_hci_send_failure(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("fail")
            assert exploit._hci_send(b"\x00") is False


# ---------------------------------------------------------------------------
# Linux hci_sync UAF (CVE-2026-68393)
# ---------------------------------------------------------------------------

class TestLinuxHCISyncUAF:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.linux_hci_sync_uaf_cve_2026_68393"
        )
        instance = mod.Exploit()
        instance.interface = "hci0"
        instance.timeout = 1.0
        return instance

    def test_hci_event_constants(self, exploit) -> None:
        assert exploit._HCI_EV_CMD_COMPLETE == 0x0E
        assert exploit._HCI_EV_CMD_STATUS == 0x0F
        assert exploit._HCI_EV_DISCONN_COMPLETE == 0x05

    def test_build_cmd_complete_event(self, exploit) -> None:
        evt = exploit._build_cmd_complete_event(opcode=0x0406, status=0)
        assert isinstance(evt, bytes)
        assert evt[0] == exploit._HCI_EVENT_PKT

    def test_build_cmd_status_event(self, exploit) -> None:
        evt = exploit._build_cmd_status_event(opcode=0x0406, status=0)
        assert isinstance(evt, bytes)
        assert evt[0] == exploit._HCI_EVENT_PKT

    def test_build_disconn_event(self, exploit) -> None:
        evt = exploit._build_disconn_event(handle=0x0040, reason=0x13)
        assert isinstance(evt, bytes)
        assert evt[0] == exploit._HCI_EVENT_PKT

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_hci_socket", return_value=None):
            assert exploit.check() is False

    def test_bd_addr_to_bytes(self, exploit) -> None:
        result = exploit._bd_addr_to_bytes("AA:BB:CC:DD:EE:FF")
        assert result == bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])


# ---------------------------------------------------------------------------
# Linux BNEP UAF (CVE-2026-64178)
# ---------------------------------------------------------------------------

class TestLinuxBNEPUAF:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.linux_bnep_uaf_cve_2026_64178"
        )
        instance = mod.Exploit()
        instance.interface = "hci0"
        instance.timeout = 1.0
        return instance

    def test_bnep_constants(self, exploit) -> None:
        assert exploit._BNEP_SETUP_CONN_REQ == 0x01
        assert exploit._BNEP_GENERAL_ETHERNET == 0x00
        assert exploit._BNEP_COMPRESSED == 0x02

    def test_bnep_service_uuids(self, exploit) -> None:
        assert exploit._BNEP_SVC_PANU == 0x1115
        assert exploit._BNEP_SVC_NAP == 0x1116
        assert exploit._BNEP_SVC_GN == 0x1117

    def test_build_bnep_setup_req(self, exploit) -> None:
        pkt = exploit._build_bnep_setup_req(dst_service=0x1116, src_service=0x1115)
        assert isinstance(pkt, bytes)
        assert pkt[0] == exploit._BNEP_SETUP_CONN_REQ

    def test_build_bnep_ethernet_frame(self, exploit) -> None:
        frame = exploit._build_bnep_ethernet_frame(seq=0)
        assert isinstance(frame, bytes)
        assert len(frame) > 10

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_hci_socket", return_value=None):
            assert exploit.check() is False

    def test_bd_addr_to_bytes(self, exploit) -> None:
        result = exploit._bd_addr_to_bytes("11:22:33:44:55:66")
        assert result == bytes([0x66, 0x55, 0x44, 0x33, 0x22, 0x11])


# ---------------------------------------------------------------------------
# Apple BT DoS (CVE-2026-20650)
# ---------------------------------------------------------------------------

class TestAppleBTDoS:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.apple_bt_dos_cve_2026_20650"
        )
        instance = mod.Exploit()
        instance.interface = "hci0"
        instance.timeout = 1.0
        instance.crash_attempts = 4
        return instance

    def test_l2cap_signaling_cid(self, exploit) -> None:
        assert exploit._L2CAP_CID_SIGNALING == 0x0001

    def test_l2cap_info_rsp_code(self, exploit) -> None:
        assert exploit._L2CAP_INFO_RSP == 0x0B

    def test_l2cap_result_constants(self, exploit) -> None:
        assert exploit._L2CAP_IR_SUCCESS == 0x0000
        assert exploit._L2CAP_IR_NOTSUPP == 0x0001

    def test_build_l2cap_info_response_normal(self, exploit) -> None:
        pkt = exploit._build_l2cap_info_response(
            identifier=1,
            info_type=0xFF00,
            result=exploit._L2CAP_IR_SUCCESS,
            data=b""
        )
        assert isinstance(pkt, bytes)
        assert len(pkt) > 8

    def test_build_l2cap_info_response_with_data(self, exploit) -> None:
        pkt = exploit._build_l2cap_info_response(
            identifier=1,
            info_type=exploit._L2CAP_IT_FEAT_MASK,
            result=exploit._L2CAP_IR_SUCCESS,
            data=b"\x00\x00\x00\x00"
        )
        assert isinstance(pkt, bytes)

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_hci_socket", return_value=None):
            assert exploit.check() is False

    def test_bd_addr_to_bytes(self, exploit) -> None:
        result = exploit._bd_addr_to_bytes("AA:BB:CC:DD:EE:FF")
        assert result == bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])


# ---------------------------------------------------------------------------
# TI BLE LL_LENGTH_REQ DoS (CVE-2025-44525)
# ---------------------------------------------------------------------------

class TestTIBLELLLengthDoS:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.ti_ble_ll_length_dos_cve_2025_44525"
        )
        instance = mod.Exploit()
        instance.interface = "hci0"
        instance.timeout = 1.0
        instance.max_octets = 65535
        instance.max_time = 65535
        instance.repeat_count = 2
        return instance

    def test_hci_command_pkt(self, exploit) -> None:
        assert exploit._HCI_COMMAND_PKT == 0x01

    def test_ogf_le(self, exploit) -> None:
        assert exploit._OGF_LE == 0x08

    def test_ll_length_req_opcode(self, exploit) -> None:
        assert exploit._LL_LENGTH_REQ_OPCODE == 0x14

    def test_build_le_set_data_length(self, exploit) -> None:
        cmd = exploit._build_le_set_data_length(handle=0x0040)
        assert isinstance(cmd, bytes)
        assert cmd[0] == exploit._HCI_COMMAND_PKT

    def test_build_ll_length_req_raw(self, exploit) -> None:
        pdu = exploit._build_ll_length_req_raw()
        assert isinstance(pdu, bytes)
        assert pdu[0] == exploit._LL_LENGTH_REQ_OPCODE

    def test_build_le_set_data_length_contains_max_octets(self, exploit) -> None:
        cmd = exploit._build_le_set_data_length(handle=0x0040)
        assert struct.pack("<H", 65535) in cmd

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_hci_socket", return_value=None):
            assert exploit.check() is False

    def test_bd_addr_to_bytes(self, exploit) -> None:
        result = exploit._bd_addr_to_bytes("AA:BB:CC:DD:EE:FF")
        assert result == bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])


# ---------------------------------------------------------------------------
# Realtek BLE LL_LENGTH_REQ DoS (CVE-2025-44526)
# ---------------------------------------------------------------------------

class TestRealtekBLELLLengthDoS:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.realtek_ble_ll_length_dos_cve_2025_44526"
        )
        instance = mod.Exploit()
        instance.interface = "hci0"
        instance.timeout = 1.0
        instance.use_zero = True
        instance.repeat_count = 2
        return instance

    def test_hci_command_pkt(self, exploit) -> None:
        assert exploit._HCI_COMMAND_PKT == 0x01

    def test_ogf_le(self, exploit) -> None:
        assert exploit._OGF_LE == 0x08

    def test_build_le_set_data_length_zero_mode(self, exploit) -> None:
        exploit.use_zero = True
        cmd = exploit._build_le_set_data_length(handle=0x0040)
        assert isinstance(cmd, bytes)
        assert struct.pack("<H", 0) in cmd

    def test_build_le_set_data_length_oversized_mode(self, exploit) -> None:
        exploit.use_zero = False
        cmd = exploit._build_le_set_data_length(handle=0x0040)
        assert isinstance(cmd, bytes)
        assert struct.pack("<H", 0xFFFF) in cmd

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_hci_socket", return_value=None):
            assert exploit.check() is False

    def test_hci_send_success(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_cls.return_value = mock_sock
            assert exploit._hci_send(b"\x00") is True

    def test_hci_send_failure(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("fail")
            assert exploit._hci_send(b"\x00") is False


# ---------------------------------------------------------------------------
# Pebble BLE Missing Auth (CVE-2025-69969)
# ---------------------------------------------------------------------------

class TestPebbleBLEMissingAuth:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.pebble_ble_missing_auth_cve_2025_69969"
        )
        instance = mod.Exploit()
        instance.interface = "hci0"
        instance.timeout = 1.0
        instance.notification_text = "Test alert"
        instance.action = "notify"
        return instance

    def test_pebble_svc_uuid(self, exploit) -> None:
        assert "fed9" in exploit._PEBBLE_SVC_UUID

    def test_att_write_cmd_opcode(self, exploit) -> None:
        assert exploit._ATT_WRITE_CMD == 0x52

    def test_l2cap_cid_att(self, exploit) -> None:
        assert exploit._L2CAP_CID_ATT == 0x0004

    def test_pebble_handles(self, exploit) -> None:
        assert exploit._PEBBLE_NOTIFY_HANDLE == 0x0025
        assert exploit._PEBBLE_CONFIG_HANDLE == 0x0029
        assert exploit._PEBBLE_FWUPDATE_HANDLE == 0x002D

    def test_build_att_write_cmd(self, exploit) -> None:
        pkt = exploit._build_att_write_cmd(0x0025, b"hello")
        assert isinstance(pkt, bytes)
        assert len(pkt) > 4

    def test_build_notification_payload(self, exploit) -> None:
        payload = exploit._build_notification_payload("Test alert")
        assert isinstance(payload, bytes)
        assert b"Test alert" in payload

    def test_build_notification_payload_truncation(self, exploit) -> None:
        long_text = "A" * 200
        payload = exploit._build_notification_payload(long_text)
        text_part = payload[3:]
        assert len(text_part) <= 128

    def test_build_config_payload(self, exploit) -> None:
        payload = exploit._build_config_payload()
        assert isinstance(payload, bytes)
        assert len(payload) == 2

    def test_build_fwupdate_trigger(self, exploit) -> None:
        payload = exploit._build_fwupdate_trigger()
        assert isinstance(payload, bytes)
        assert len(payload) == 3

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_hci_socket", return_value=None):
            assert exploit.check() is False

    def test_bd_addr_to_bytes(self, exploit) -> None:
        result = exploit._bd_addr_to_bytes("AA:BB:CC:DD:EE:FF")
        assert result == bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])


# ---------------------------------------------------------------------------
# MouseJack nRF24 HID Injection
# ---------------------------------------------------------------------------

class TestMouseJackNRF24HID:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.bluetooth.mousejack_nrf24_hid"
        )
        instance = mod.Exploit()
        instance.timeout = 1.0
        instance.interface = "/dev/crazyradio"
        instance.channel = 0
        instance.keystroke_payload = "echo pwned"
        instance.keystroke_delay = 0.0
        return instance

    def test_nrf24_channels(self, exploit) -> None:
        assert exploit._NRF24_CHANNELS == list(range(2, 84))

    def test_hid_modifier_none(self, exploit) -> None:
        assert exploit._HID_MODIFIER_NONE == 0x00

    def test_hid_modifier_lshift(self, exploit) -> None:
        assert exploit._HID_MODIFIER_LSHIFT == 0x02

    def test_hid_key_enter(self, exploit) -> None:
        assert exploit._HID_KEY_ENTER == 0x28

    def test_char_to_hid_lowercase(self, exploit) -> None:
        mod, key = exploit._char_to_hid('a')
        assert mod == 0x00
        assert key == 0x04

    def test_char_to_hid_uppercase(self, exploit) -> None:
        mod, key = exploit._char_to_hid('A')
        assert mod == exploit._HID_MODIFIER_LSHIFT
        assert key == 0x04

    def test_char_to_hid_space(self, exploit) -> None:
        mod, key = exploit._char_to_hid(' ')
        assert mod == 0x00
        assert key == 0x2C

    def test_char_to_hid_unknown(self, exploit) -> None:
        mod, key = exploit._char_to_hid('\x01')
        assert mod == 0x00
        assert key == exploit._HID_KEY_NONE

    def test_build_hid_frame(self, exploit) -> None:
        frame = exploit._build_hid_frame(0x00, 0x04)
        assert isinstance(frame, bytes)
        assert len(frame) == 8

    def test_build_hid_frame_checksum(self, exploit) -> None:
        frame = exploit._build_hid_frame(0x00, 0x04)
        xor = 0
        for b in frame[:-1]:
            xor ^= b
        assert xor == frame[-1]

    def test_build_key_release_frame(self, exploit) -> None:
        frame = exploit._build_key_release_frame()
        assert isinstance(frame, bytes)
        assert frame[3] == 0x00

    def test_open_crazyradio_returns_none_without_pyusb(self, exploit) -> None:
        with patch.dict("sys.modules", {"usb": None, "usb.core": None}):
            result = exploit._open_crazyradio()
            assert result is None

    def test_check_returns_false_without_dongle(self, exploit) -> None:
        with patch.object(exploit, "_open_crazyradio", return_value=None):
            assert exploit.check() is False

    def test_key_map_completeness(self, exploit) -> None:
        for char in "abcdefghijklmnopqrstuvwxyz0123456789":
            assert char in exploit._KEY_MAP

    def test_shift_map_completeness(self, exploit) -> None:
        for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()":
            assert char in exploit._SHIFT_MAP

    def test_info_no_cve(self, exploit) -> None:
        info = exploit._Exploit__info__
        assert "MouseJack" in info["name"]
