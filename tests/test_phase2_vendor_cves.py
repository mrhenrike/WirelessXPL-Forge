"""Unit tests for Phase 2 vendor CVE exploit modules."""
import importlib
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class TestModuleImports:
    """Verify all Phase 2 modules import without error."""

    @pytest.mark.parametrize(
        "module_path",
        [
            "wirelessxpl.modules.generic.access_points.ubiquiti.unifi_connect_cmdinj_cve_2026_50746",
            "wirelessxpl.modules.generic.access_points.ubiquiti.unifi_access_cmdi_cve_2026_50748",
            "wirelessxpl.modules.generic.access_points.mikrotik.routeros_preauth_rce_cve_2026_84411",
            "wirelessxpl.modules.generic.access_points.dlink.dsl_dns_cmdi_cve_2026_0625",
            "wirelessxpl.modules.generic.wifi.adb_wireless_rce_cve_2026_0073",
        ],
    )
    def test_module_imports(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert hasattr(mod, "Exploit")

    @pytest.mark.parametrize(
        "module_path",
        [
            "wirelessxpl.modules.generic.access_points.ubiquiti.unifi_connect_cmdinj_cve_2026_50746",
            "wirelessxpl.modules.generic.access_points.ubiquiti.unifi_access_cmdi_cve_2026_50748",
            "wirelessxpl.modules.generic.access_points.mikrotik.routeros_preauth_rce_cve_2026_84411",
            "wirelessxpl.modules.generic.access_points.dlink.dsl_dns_cmdi_cve_2026_0625",
            "wirelessxpl.modules.generic.wifi.adb_wireless_rce_cve_2026_0073",
        ],
    )
    def test_exploit_has_required_methods(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "check")
        assert hasattr(instance, "run")
        assert callable(instance.check)
        assert callable(instance.run)

    @pytest.mark.parametrize(
        "module_path",
        [
            "wirelessxpl.modules.generic.access_points.ubiquiti.unifi_connect_cmdinj_cve_2026_50746",
            "wirelessxpl.modules.generic.access_points.ubiquiti.unifi_access_cmdi_cve_2026_50748",
            "wirelessxpl.modules.generic.access_points.mikrotik.routeros_preauth_rce_cve_2026_84411",
            "wirelessxpl.modules.generic.access_points.dlink.dsl_dns_cmdi_cve_2026_0625",
            "wirelessxpl.modules.generic.wifi.adb_wireless_rce_cve_2026_0073",
        ],
    )
    def test_exploit_has_target_option(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "target")
        assert hasattr(instance, "port")

    @pytest.mark.parametrize(
        "module_path,expected_cve",
        [
            ("wirelessxpl.modules.generic.access_points.ubiquiti.unifi_connect_cmdinj_cve_2026_50746", "CVE-2026-50746"),
            ("wirelessxpl.modules.generic.access_points.ubiquiti.unifi_access_cmdi_cve_2026_50748", "CVE-2026-50748"),
            ("wirelessxpl.modules.generic.access_points.mikrotik.routeros_preauth_rce_cve_2026_84411", "CVE-2026-84411"),
            ("wirelessxpl.modules.generic.access_points.dlink.dsl_dns_cmdi_cve_2026_0625", "CVE-2026-0625"),
            ("wirelessxpl.modules.generic.wifi.adb_wireless_rce_cve_2026_0073", "CVE-2026-0073"),
        ],
    )
    def test_class_info_contains_cve(self, module_path: str, expected_cve: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert expected_cve in info.get("name", ""), f"CVE not found in __info__['name'] for {module_path}"


class TestUniFiConnectCVE202650746:
    """Tests for CVE-2026-50746 Ubiquiti UniFi Connect command injection."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.ubiquiti.unifi_connect_cmdinj_cve_2026_50746"
        )
        instance = mod.Exploit()
        instance.target = "192.168.1.100"
        instance.port = 443
        instance.timeout = 1.0
        instance.command = "id"
        return instance

    def test_check_no_connection(self, exploit) -> None:
        with patch.object(exploit, "_http_request", return_value=(0, b"")):
            assert exploit.check() is False

    def test_has_provision_endpoint(self, exploit) -> None:
        assert hasattr(exploit, "_PROVISION_ENDPOINT")

    def test_run_with_failed_check(self, exploit) -> None:
        with patch.object(exploit, "check", return_value=False):
            exploit.run()


class TestUniFiAccessCVE202650748:
    """Tests for CVE-2026-50748 Ubiquiti UniFi Access command injection."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.ubiquiti.unifi_access_cmdi_cve_2026_50748"
        )
        instance = mod.Exploit()
        instance.target = "192.168.1.100"
        instance.port = 443
        instance.timeout = 1.0
        instance.username = "testuser"
        instance.password = "testpass"
        instance.command = "id"
        return instance

    def test_has_authenticate_method(self, exploit) -> None:
        assert hasattr(exploit, "_authenticate")

    def test_requires_credentials(self, exploit) -> None:
        exploit.username = ""
        exploit.password = ""
        with patch.object(exploit, "check", return_value=True):
            exploit.run()

    def test_check_no_connection(self, exploit) -> None:
        with patch.object(exploit, "_http_request", return_value=(0, {}, b"")):
            assert exploit.check() is False


class TestMikroTikCVE202684411:
    """Tests for CVE-2026-84411 MikroTik RouterOS pre-auth RCE."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.mikrotik.routeros_preauth_rce_cve_2026_84411"
        )
        instance = mod.Exploit()
        instance.target = "192.168.88.1"
        instance.port = 8291
        instance.timeout = 1.0
        return instance

    def test_build_winbox_header(self, exploit) -> None:
        header = exploit._build_winbox_header(6, 0x01, 0x01)
        assert len(header) == 4
        length, msg_type, flags = struct.unpack("!HBB", header)
        assert length == 6
        assert msg_type == 0x01
        assert flags == 0x01

    def test_build_trigger_packet(self, exploit) -> None:
        exploit.trigger_length = 1
        pkt = exploit._build_trigger_packet()
        assert len(pkt) > 4
        length_field = struct.unpack("!H", pkt[:2])[0]
        assert length_field == 1

    def test_build_probe_packet(self, exploit) -> None:
        pkt = exploit._build_probe_packet()
        assert len(pkt) >= 4
        length_field = struct.unpack("!H", pkt[:2])[0]
        assert length_field > 2

    def test_check_no_connection(self, exploit) -> None:
        with patch.object(exploit, "_tcp_connect", return_value=None):
            assert exploit.check() is False

    def test_check_winbox_responds(self, exploit) -> None:
        mock_sock = MagicMock()
        with patch.object(exploit, "_tcp_connect", return_value=mock_sock):
            valid_response = struct.pack("!HBB", 6, 1, 0) + b"\x00\x00"
            with patch.object(exploit, "_send_recv", return_value=valid_response):
                assert exploit.check() is True
        mock_sock.close.assert_called_once()


class TestDLinkCVE20260625:
    """Tests for CVE-2026-0625 D-Link DSL DNS command injection."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.access_points.dlink.dsl_dns_cmdi_cve_2026_0625"
        )
        instance = mod.Exploit()
        instance.target = "192.168.1.1"
        instance.port = 80
        instance.timeout = 1.0
        instance.command = "id"
        return instance

    def test_has_cgi_path(self, exploit) -> None:
        assert hasattr(exploit, "_CGI_PATH")
        assert "/dnscfg.cgi" in exploit._CGI_PATH

    def test_build_url(self, exploit) -> None:
        url = exploit._build_url("/test")
        assert "192.168.1.1" in url
        assert ":80" in url

    def test_check_endpoint_found(self, exploit) -> None:
        with patch.object(exploit, "_http_get", return_value=(200, "<html>dns primary</html>")):
            assert exploit.check() is True

    def test_check_endpoint_not_found(self, exploit) -> None:
        with patch.object(exploit, "_http_get", return_value=(0, "")):
            assert exploit.check() is False

    def test_run_with_failed_check(self, exploit) -> None:
        with patch.object(exploit, "check", return_value=False):
            exploit.run()


class TestADBWirelessCVE20260073:
    """Tests for CVE-2026-0073 Android ADB wireless TLS auth bypass."""

    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.wifi.adb_wireless_rce_cve_2026_0073"
        )
        instance = mod.Exploit()
        instance.target = "192.168.1.50"
        instance.port = 5555
        instance.timeout = 1.0
        instance.command = "id"
        return instance

    def test_build_adb_message(self, exploit) -> None:
        data = b"test_data"
        packed = exploit._build_adb_message(exploit._ADB_MAGIC_CNXN, 1, 2, data)
        assert isinstance(packed, bytes)
        assert len(packed) > len(data)

    def test_check_connection_refused(self, exploit) -> None:
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = ConnectionRefusedError("refused")
            mock_sock_cls.return_value = mock_sock
            assert exploit.check() is False

    def test_adb_constants(self, exploit) -> None:
        assert exploit._ADB_MAGIC_CNXN == b"CNXN"
        assert exploit._ADB_VERSION == 0x01000001
        assert exploit._ADB_MAX_DATA == 256 * 1024
