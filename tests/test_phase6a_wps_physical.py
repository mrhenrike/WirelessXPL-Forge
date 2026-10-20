"""Unit tests for Phase 6A: WPS + Physical Protocol exploit modules."""
import importlib
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_PHASE6A_MODULES = [
    "wirelessxpl.modules.generic.wifi.wps.wps_pbc_hijack",
    "wirelessxpl.modules.generic.wifi.wps.wps_nfc_token_clone",
    "wirelessxpl.modules.generic.wifi.wps.wps_usb_token_extraction",
    "wirelessxpl.modules.generic.physical.rolljam_replay",
    "wirelessxpl.modules.generic.physical.badusb_wifi_pivot",
    "wirelessxpl.modules.generic.physical.ir_remote_replay",
]


class TestPhase6AModuleImports:
    """Verify all Phase 6A modules import without error."""

    @pytest.mark.parametrize("module_path", _PHASE6A_MODULES)
    def test_module_imports(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert hasattr(mod, "Exploit")

    @pytest.mark.parametrize("module_path", _PHASE6A_MODULES)
    def test_exploit_has_required_methods(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "check")
        assert hasattr(instance, "run")
        assert callable(instance.check)
        assert callable(instance.run)

    @pytest.mark.parametrize("module_path", _PHASE6A_MODULES)
    def test_exploit_has_timeout_option(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "timeout")

    @pytest.mark.parametrize("module_path", _PHASE6A_MODULES)
    def test_exploit_has_info_dict(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert "name" in info
        assert "description" in info
        assert "authors" in info
        assert "references" in info

    @pytest.mark.parametrize("module_path", _PHASE6A_MODULES)
    def test_exploit_has_exploit_attributes(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        assert hasattr(cls, "exploit_attributes")
        attrs = cls.exploit_attributes
        assert isinstance(attrs, dict)


# ---------------------------------------------------------------------------
# WPS PBC Hijack
# ---------------------------------------------------------------------------

class TestWpsPbcHijack:
    """Tests for WPS PBC window race exploitation."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module("wirelessxpl.modules.generic.wifi.wps.wps_pbc_hijack")
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.pbc_scan_time = 5.0
        instance.channel = 6
        return instance

    def test_wps_ie_vendor_type(self, exploit) -> None:
        assert exploit._WPS_IE_VENDOR_TYPE == b"\x00\x50\xf2\x04"

    def test_wps_dev_password_pbc(self, exploit) -> None:
        assert exploit._WPS_DEV_PASSWORD_PBC == 0x0004

    def test_build_wps_probe_request(self, exploit) -> None:
        probe = exploit._build_wps_probe_request()
        assert isinstance(probe, bytes)
        assert len(probe) > 20
        # Should contain WPS vendor IE
        assert b"\x00\x50\xf2\x04" in probe

    def test_parse_wps_ie_empty(self, exploit) -> None:
        result = exploit._parse_wps_ie(b"")
        assert result == {}

    def test_parse_wps_ie_wrong_vendor(self, exploit) -> None:
        result = exploit._parse_wps_ie(b"\x00\x00\x00\x00")
        assert result == {}

    def test_parse_wps_ie_valid(self, exploit) -> None:
        # Build a valid WPS IE with Selected Registrar attribute
        ie_data = exploit._WPS_IE_VENDOR_TYPE
        ie_data += struct.pack(">HH", 0x1041, 1) + b"\x01"  # Selected Registrar = True
        ie_data += struct.pack(">HHH", 0x1012, 2, 0x0004)  # Device Password = PBC
        result = exploit._parse_wps_ie(ie_data)
        assert 0x1041 in result
        assert 0x1012 in result

    def test_build_eap_wsc_m1(self, exploit) -> None:
        m1 = exploit._build_eap_wsc_m1(eap_id=1)
        assert isinstance(m1, bytes)
        assert len(m1) > 10
        # EAP code should be Response (2)
        assert m1[0] == exploit._EAP_CODE_RESPONSE
        # EAP id should be 1
        assert m1[1] == 1

    def test_open_raw_wifi_returns_none_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit._open_raw_wifi() is None

    def test_check_returns_false_on_socket_error(self, exploit) -> None:
        with patch.object(exploit, "_open_raw_wifi", return_value=None):
            assert exploit.check() is False

    def test_inject_frame_success(self, exploit) -> None:
        mock_sock = MagicMock()
        assert exploit._inject_frame(mock_sock, b"\x00") is True

    def test_inject_frame_failure(self, exploit) -> None:
        mock_sock = MagicMock()
        mock_sock.send.side_effect = OSError("broken")
        assert exploit._inject_frame(mock_sock, b"\x00") is False


# ---------------------------------------------------------------------------
# WPS NFC Token Clone
# ---------------------------------------------------------------------------

class TestWpsNfcTokenClone:
    """Tests for WPS NFC OOB token cloning."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module("wirelessxpl.modules.generic.wifi.wps.wps_nfc_token_clone")
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        return instance

    def test_ndef_rtd_wsc(self, exploit) -> None:
        assert exploit._NDEF_RTD_WSC == b"application/vnd.wfa.wsc"

    def test_build_ndef_record(self, exploit) -> None:
        payload = b"\x00" * 10
        record = exploit._build_ndef_record(payload)
        assert isinstance(record, bytes)
        assert len(record) > len(payload)

    def test_build_wps_credential(self, exploit) -> None:
        ssid = b"TestNetwork"
        key = b"password123"
        cred = exploit._build_wps_credential(ssid, key)
        assert isinstance(cred, bytes)
        # Should contain the SSID
        assert ssid in cred
        # Should contain the key
        assert key in cred

    def test_parse_ndef_wps_with_ssid_and_key(self, exploit) -> None:
        ssid = b"MyWiFi"
        key = b"secret"
        # Build credential attrs directly
        data = struct.pack(">HH", 0x1045, len(ssid)) + ssid
        data += struct.pack(">HH", 0x1027, len(key)) + key
        result = exploit._parse_ndef_wps(data)
        assert result["ssid"] == ssid
        assert result["key"] == key

    def test_parse_ndef_wps_oob_password(self, exploit) -> None:
        oob = b"\xDE\xAD\xBE\xEF" * 4
        data = struct.pack(">HH", 0x102C, len(oob)) + oob
        result = exploit._parse_ndef_wps(data)
        assert result["oob_password"] == oob

    def test_parse_ndef_wps_empty(self, exploit) -> None:
        result = exploit._parse_ndef_wps(b"")
        assert result["ssid"] is None
        assert result["key"] is None

    def test_build_oob_hash(self, exploit) -> None:
        oob = b"test_oob_password"
        h = exploit._build_oob_hash(oob)
        assert isinstance(h, bytes)
        assert len(h) == 16  # SHA256[:16]

    def test_open_raw_wifi_returns_none_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit._open_raw_wifi() is None

    def test_check_false_without_socket(self, exploit) -> None:
        with patch.object(exploit, "_open_raw_wifi", return_value=None):
            assert exploit.check() is False

    def test_parse_nested_credential(self, exploit) -> None:
        ssid = b"NestedSSID"
        key = b"NestedKey"
        inner = struct.pack(">HH", 0x1045, len(ssid)) + ssid
        inner += struct.pack(">HH", 0x1027, len(key)) + key
        outer = struct.pack(">HH", 0x100E, len(inner)) + inner
        result = exploit._parse_ndef_wps(outer)
        assert result["ssid"] == ssid
        assert result["key"] == key


# ---------------------------------------------------------------------------
# WPS USB Token Extraction
# ---------------------------------------------------------------------------

class TestWpsUsbTokenExtraction:
    """Tests for WPS USB Flash Drive credential extraction."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module("wirelessxpl.modules.generic.wifi.wps.wps_usb_token_extraction")
        instance = mod.Exploit()
        instance.interface = "wlan0mon"
        instance.timeout = 1.0
        instance.usb_mount_path = "/nonexistent"
        return instance

    def test_wps_ufd_filenames(self, exploit) -> None:
        assert len(exploit._WPS_UFD_FILENAMES) > 0

    def test_parse_wps_xml_with_ssid_and_key(self, exploit) -> None:
        xml = """<?xml version="1.0"?>
        <WLANProfile>
            <ssid>TestNetwork</ssid>
            <authentication>WPA2PSK</authentication>
            <encryption>AES</encryption>
            <networkKey>SuperSecret</networkKey>
        </WLANProfile>"""
        creds = exploit._parse_wps_xml(xml)
        assert creds["ssid"] == "TestNetwork"
        assert creds["key"] == "SuperSecret"
        assert creds["auth_type"] == "WPA2PSK"

    def test_parse_wps_xml_empty(self, exploit) -> None:
        creds = exploit._parse_wps_xml("")
        assert creds["ssid"] is None
        assert creds["key"] is None

    def test_compute_pmk(self, exploit) -> None:
        pmk = exploit._compute_pmk("testpass", "TestSSID")
        assert isinstance(pmk, bytes)
        assert len(pmk) == 32

    def test_scan_usb_volumes_nonexistent_path(self, exploit) -> None:
        exploit.usb_mount_path = "/nonexistent_path_xyz"
        found = exploit._scan_usb_volumes()
        assert found == []

    def test_check_with_credential_file(self, exploit) -> None:
        exploit.credential_file = "/nonexistent/file.xml"
        assert exploit.check() is False

    def test_open_raw_wifi_returns_none_on_error(self, exploit) -> None:
        with patch("socket.socket") as mock_cls:
            mock_cls.return_value.bind.side_effect = OSError("no device")
            assert exploit._open_raw_wifi() is None

    def test_parse_wps_xml_partial(self, exploit) -> None:
        xml = "<config><ssid>OnlySSID</ssid></config>"
        creds = exploit._parse_wps_xml(xml)
        assert creds["ssid"] == "OnlySSID"
        assert creds["key"] is None


# ---------------------------------------------------------------------------
# RollJam Replay
# ---------------------------------------------------------------------------

class TestRollJamReplay:
    """Tests for RollJam rolling code capture/jam/replay."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module("wirelessxpl.modules.generic.physical.rolljam_replay")
        instance = mod.Exploit()
        instance.timeout = 5.0
        instance.frequency = 433.92
        instance.jam_offset = 0.5
        instance.jam_power = 0.8
        instance.sample_rate = 2.0
        instance.modulation = "OOK"
        return instance

    def test_keeloq_frame_len(self, exploit) -> None:
        assert exploit._KEELOQ_FRAME_LEN == 66

    def test_build_jam_signal(self, exploit) -> None:
        sig = exploit._build_jam_signal(duration_ms=10)
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_build_ook_frame(self, exploit) -> None:
        code = b"\xAA\x55"
        frame = exploit._build_ook_frame(code)
        assert isinstance(frame, bytes)
        assert len(frame) > 0

    def test_detect_preamble_with_valid_data(self, exploit) -> None:
        # Build data with alternating high/low amplitudes
        data = bytearray()
        for i in range(100):
            if i % 2 == 0:
                data.extend(b"\x7f\x00")
            else:
                data.extend(b"\x01\x00")
        offset = exploit._detect_preamble(bytes(data))
        assert offset >= 0

    def test_detect_preamble_no_preamble(self, exploit) -> None:
        data = b"\x00\x00" * 100
        offset = exploit._detect_preamble(data)
        assert offset == -1

    def test_extract_code_bits(self, exploit) -> None:
        # Create some IQ data with detectable patterns
        iq = b"\x7f\x00" * 200 + b"\x00\x00" * 100
        bits = exploit._extract_code_bits(iq, 0)
        assert isinstance(bits, bytes)

    def test_save_code_no_file(self, exploit) -> None:
        exploit.capture_file = ""
        # Should not raise
        exploit._save_code(b"\xAA\xBB", 1)

    def test_save_code_with_file(self, exploit, tmp_path) -> None:
        exploit.capture_file = str(tmp_path / "test_code")
        exploit._save_code(b"\xAA\xBB", 1)
        saved = (tmp_path / "test_code.code1").read_bytes()
        assert saved == b"\xAA\xBB"

    def test_check_returns_true(self, exploit) -> None:
        with patch("os.path.exists", return_value=True):
            assert exploit.check() is True


# ---------------------------------------------------------------------------
# BadUSB WiFi Pivot
# ---------------------------------------------------------------------------

class TestBadUsbWifiPivot:
    """Tests for BadUSB WiFi credential harvesting."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module("wirelessxpl.modules.generic.physical.badusb_wifi_pivot")
        instance = mod.Exploit()
        instance.target = "192.168.1.100"
        instance.port = 8080
        instance.target_os = "windows"
        instance.exfil_method = "http"
        instance.keystroke_delay = 50
        return instance

    def test_build_windows_payload(self, exploit) -> None:
        payload = exploit._build_windows_payload()
        assert isinstance(payload, str)
        assert "netsh wlan" in payload
        assert "key=clear" in payload

    def test_build_linux_payload(self, exploit) -> None:
        exploit.target_os = "linux"
        payload = exploit._build_linux_payload()
        assert isinstance(payload, str)
        assert "NetworkManager" in payload

    def test_build_macos_payload(self, exploit) -> None:
        exploit.target_os = "macos"
        payload = exploit._build_macos_payload()
        assert isinstance(payload, str)
        assert "security find-generic-password" in payload

    def test_build_exfil_http_windows(self, exploit) -> None:
        cmd = exploit._build_exfil_command("$output")
        assert "Invoke-WebRequest" in cmd
        assert "192.168.1.100" in cmd

    def test_build_exfil_http_linux(self, exploit) -> None:
        exploit.target_os = "linux"
        cmd = exploit._build_exfil_command("$output")
        assert "curl" in cmd

    def test_build_exfil_dns(self, exploit) -> None:
        exploit.exfil_method = "dns"
        cmd = exploit._build_exfil_command("$output")
        assert "nslookup" in cmd or "base64" in cmd

    def test_build_exfil_file(self, exploit) -> None:
        exploit.exfil_method = "file"
        cmd = exploit._build_exfil_command("$output")
        assert "/tmp/" in cmd

    def test_build_duckyscript_windows(self, exploit) -> None:
        ducky = exploit._build_duckyscript("test command")
        assert "GUI r" in ducky
        assert "powershell" in ducky
        assert "test command" in ducky

    def test_build_duckyscript_linux(self, exploit) -> None:
        exploit.target_os = "linux"
        ducky = exploit._build_duckyscript("bash command")
        assert "bash command" in ducky

    def test_build_duckyscript_macos(self, exploit) -> None:
        exploit.target_os = "macos"
        ducky = exploit._build_duckyscript("osx cmd")
        assert "Terminal" in ducky
        assert "osx cmd" in ducky

    def test_build_hid_report(self, exploit) -> None:
        report = exploit._build_hid_report(0x28, modifier=0)
        assert isinstance(report, bytes)
        assert len(report) == 8

    def test_check_valid_os(self, exploit) -> None:
        assert exploit.check() is True

    def test_check_invalid_os(self, exploit) -> None:
        exploit.target_os = "freebsd"
        assert exploit.check() is False

    def test_output_file(self, exploit, tmp_path) -> None:
        exploit.output_path = str(tmp_path / "payload.txt")
        exploit._exploit()
        assert (tmp_path / "payload.txt").exists()


# ---------------------------------------------------------------------------
# IR Remote Replay
# ---------------------------------------------------------------------------

class TestIrRemoteReplay:
    """Tests for IR remote replay/brute force + IrDA."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module("wirelessxpl.modules.generic.physical.ir_remote_replay")
        instance = mod.Exploit()
        instance.timeout = 1.0
        instance.protocol = "NEC"
        instance.mode = "replay"
        instance.brute_address = 4
        instance.brute_start = 0
        instance.brute_end = 5
        instance.brute_delay = 0.01
        return instance

    def test_nec_leader_pulse(self, exploit) -> None:
        assert exploit._NEC_LEADER_PULSE == 9000

    def test_nec_carrier_freq(self, exploit) -> None:
        assert exploit._NEC_CARRIER_FREQ == 38000

    def test_encode_nec(self, exploit) -> None:
        timings = exploit._encode_nec(address=0x04, command=0x08)
        assert isinstance(timings, list)
        # NEC: leader(2) + 32 bits * 2 + stop(1) = 67 values
        assert len(timings) == 67
        # Leader pulse
        assert timings[0] == 9000
        assert timings[1] == 4500

    def test_encode_rc5(self, exploit) -> None:
        timings = exploit._encode_rc5(toggle=0, address=5, command=12)
        assert isinstance(timings, list)
        # RC5: 14 bits * 2 timings = 28
        assert len(timings) == 28

    def test_encode_sirc(self, exploit) -> None:
        timings = exploit._encode_sirc(command=21, address=1)
        assert isinstance(timings, list)
        assert len(timings) > 0
        # Leader
        assert timings[0] == 2400

    def test_timings_to_bytes(self, exploit) -> None:
        timings = [9000, 4500, 562]
        raw = exploit._timings_to_bytes(timings)
        assert isinstance(raw, bytes)
        assert len(raw) == 12  # 3 * 4 bytes

    def test_decode_raw_capture_nec(self, exploit) -> None:
        timings = exploit._encode_nec(0x04, 0x08)
        raw = exploit._timings_to_bytes(timings)
        decoded = exploit._decode_raw_capture(raw)
        assert decoded["protocol"] == "NEC"
        assert decoded["address"] == 0x04
        assert decoded["command"] == 0x08

    def test_decode_raw_capture_too_short(self, exploit) -> None:
        decoded = exploit._decode_raw_capture(b"\x00\x00")
        assert decoded["protocol"] == "unknown"

    def test_build_irda_sniffer_frame(self, exploit) -> None:
        frame = exploit._build_irda_sniffer_frame()
        assert isinstance(frame, bytes)
        assert len(frame) > 10
        assert b"IrDA_Sniffer" in frame

    def test_check_replay_mode(self, exploit) -> None:
        exploit.mode = "replay"
        assert exploit.check() is True

    def test_run_invalid_mode(self, exploit) -> None:
        exploit.mode = "invalid"
        # Should print error but not crash
        exploit.run()

    def test_capture_mode(self, exploit) -> None:
        exploit.mode = "capture"
        exploit._capture_mode()

    def test_replay_mode_with_code(self, exploit) -> None:
        exploit.captured_code = "AA55"
        exploit._replay_mode()

    def test_replay_mode_without_code(self, exploit) -> None:
        exploit.captured_code = ""
        exploit.brute_address = 4
        exploit.brute_start = 8
        exploit._replay_mode()

    def test_bruteforce_mode(self, exploit) -> None:
        exploit.brute_start = 0
        exploit.brute_end = 2
        exploit._bruteforce_mode()

    def test_irda_mode(self, exploit) -> None:
        exploit._irda_mode()
