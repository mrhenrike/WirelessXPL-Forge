# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Unit tests for Phase 4C Enterprise AP CVE modules.

Covers: Cisco CW9800 CAPWAP DoS, Cisco IOS XE WLC Multi,
Aruba AOS Auth Bypass, Client Isolation Bypass, CMDI Batch, Unauth DoS,
FortiAP OS CMDI, Apple CoreAudio+BCMWLan Chain.
"""
import importlib
import struct

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_exploit(module_path: str):
    mod = importlib.import_module(module_path)
    return mod.Exploit


# ---------------------------------------------------------------------------
# Module paths
# ---------------------------------------------------------------------------

CISCO_CAPWAP = "wirelessxpl.modules.generic.access_points.cisco.catalyst_cw9800_capwap_dos_cve_2026_20086"
CISCO_WLC_MULTI = "wirelessxpl.modules.generic.access_points.cisco.ios_xe_wlc_multi_cve_2026_20267"
ARUBA_AUTH_BYPASS = "wirelessxpl.modules.generic.access_points.aruba.aruba_aos_auth_bypass_cve_2026_23595"
ARUBA_CLIENT_ISO = "wirelessxpl.modules.generic.access_points.aruba.aruba_aos_client_isolation_bypass_cve_2026_23601"
ARUBA_CMDI = "wirelessxpl.modules.generic.access_points.aruba.aruba_aos_cmdi_batch_cve_2026_44865"
ARUBA_DOS = "wirelessxpl.modules.generic.access_points.aruba.aruba_aos_unauth_dos_cve_2026_23824"
FORTIAP_CMDI = "wirelessxpl.modules.generic.access_points.fortinet.fortiap_os_cmdi_cve_2025_53680"
APPLE_CHAIN = "wirelessxpl.modules.generic.access_points.apple.apple_coreaudio_bcmwlan_chain_cve_2025_31200"


# ===================================================================
# Cisco Catalyst CW9800 CAPWAP DoS
# ===================================================================

class TestCiscoCAPWAPDoS:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.Exploit = _load_exploit(CISCO_CAPWAP)
        self.exp = self.Exploit()

    def test_class_exists(self):
        assert self.Exploit is not None

    def test_info_name(self):
        info = self.exp._Exploit__info__
        assert "CW9800" in info["name"] or "CAPWAP" in info["name"]

    def test_info_cve(self):
        info = self.exp._Exploit__info__
        assert "CVE-2026-20086" in info["name"] or "CVE-2026-20086" in info["description"]

    def test_info_references(self):
        info = self.exp._Exploit__info__
        assert any("nvd.nist.gov" in r for r in info["references"])

    def test_info_targets(self):
        info = self.exp._Exploit__info__
        assert len(info["targets"]) >= 2

    def test_default_port(self):
        assert int(self.exp.port) == 5246

    def test_default_timeout(self):
        assert float(self.exp.timeout) == 5.0

    def test_capwap_header_build(self):
        hdr = self.exp._build_capwap_header(100)
        assert isinstance(hdr, bytes)
        assert len(hdr) >= 7

    def test_message_element_build(self):
        elem = self.exp._build_message_element(1, b"test")
        assert isinstance(elem, bytes)
        elem_type, elem_len = struct.unpack(">HH", elem[:4])
        assert elem_type == 1
        assert elem_len == 4

    def test_malformed_element_length(self):
        elem = self.exp._build_malformed_element()
        assert isinstance(elem, bytes)
        _, length = struct.unpack(">HH", elem[:4])
        assert length == 0xFFFF

    def test_discovery_request_normal(self):
        pkt = self.exp._build_discovery_request(malformed=False)
        assert isinstance(pkt, bytes)
        assert len(pkt) > 20

    def test_discovery_request_malformed(self):
        pkt = self.exp._build_discovery_request(malformed=True)
        assert isinstance(pkt, bytes)
        normal = self.exp._build_discovery_request(malformed=False)
        assert len(pkt) > len(normal)

    def test_has_run_method(self):
        assert hasattr(self.exp, "run")
        assert callable(self.exp.run)

    def test_has_check_method(self):
        assert hasattr(self.exp, "check")
        assert callable(self.exp.check)

    def test_has_exploit_method(self):
        assert hasattr(self.exp, "_exploit")


# ===================================================================
# Cisco IOS XE WLC Multi CVE
# ===================================================================

class TestCiscoWLCMulti:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.Exploit = _load_exploit(CISCO_WLC_MULTI)
        self.exp = self.Exploit()

    def test_class_exists(self):
        assert self.Exploit is not None

    def test_info_cve_range(self):
        info = self.exp._Exploit__info__
        assert "CVE-2026-20267" in info["name"]

    def test_info_description(self):
        info = self.exp._Exploit__info__
        assert "CVE-2026-20267" in info["description"]

    def test_default_port(self):
        assert int(self.exp.port) == 443

    def test_command_option(self):
        assert hasattr(self.exp, "command")
        assert str(self.exp.command) == "id"

    def test_webauth_path(self):
        assert self.exp._WEBAUTH_PATH == "/webauth/login.html"

    def test_injection_payload_build(self):
        payload = self.exp._build_injection_payload()
        assert isinstance(payload, bytes)
        assert b"username=" in payload
        assert b"password=" in payload

    def test_injection_contains_semicolon(self):
        payload = self.exp._build_injection_payload()
        assert b"test" in payload or b"%22" in payload

    def test_has_run_method(self):
        assert callable(self.exp.run)

    def test_has_check_method(self):
        assert callable(self.exp.check)


# ===================================================================
# Aruba AOS Auth Bypass
# ===================================================================

class TestArubaAuthBypass:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.Exploit = _load_exploit(ARUBA_AUTH_BYPASS)
        self.exp = self.Exploit()

    def test_class_exists(self):
        assert self.Exploit is not None

    def test_info_cve(self):
        info = self.exp._Exploit__info__
        assert "CVE-2026-23595" in info["name"]

    def test_default_port(self):
        assert int(self.exp.port) == 4343

    def test_login_path(self):
        assert "login" in self.exp._LOGIN_PATH.lower() or "wms" in self.exp._LOGIN_PATH.lower()

    def test_forge_session_cookie(self):
        cookie = self.exp._forge_session_cookie()
        assert isinstance(cookie, str)
        assert "SESSION=" in cookie

    def test_forge_session_cookie_not_empty(self):
        cookie = self.exp._forge_session_cookie()
        token = cookie.split("=", 1)[1]
        assert len(token) > 10

    def test_info_targets(self):
        info = self.exp._Exploit__info__
        assert len(info["targets"]) >= 2
        assert any("AOS" in t for t in info["targets"])

    def test_has_run_method(self):
        assert callable(self.exp.run)

    def test_has_check_method(self):
        assert callable(self.exp.check)

    def test_has_exploit_method(self):
        assert hasattr(self.exp, "_exploit")


# ===================================================================
# Aruba Client Isolation Bypass
# ===================================================================

class TestArubaClientIsolation:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.Exploit = _load_exploit(ARUBA_CLIENT_ISO)
        self.exp = self.Exploit()

    def test_class_exists(self):
        assert self.Exploit is not None

    def test_info_cve(self):
        info = self.exp._Exploit__info__
        assert "CVE-2026-23601" in info["name"]

    def test_info_description_gtk(self):
        info = self.exp._Exploit__info__
        assert "GTK" in info["description"]

    def test_interface_option(self):
        assert str(self.exp.interface) == "wlan0mon"

    def test_radiotap_header(self):
        hdr = self.exp._build_radiotap_header()
        assert isinstance(hdr, bytes)
        assert len(hdr) == 8

    def test_frame_control_build(self):
        fc = self.exp._build_frame_control(0x02, 0x08, 0x01)
        assert isinstance(fc, bytes)
        assert len(fc) == 2

    def test_gtk_probe_frame_build(self):
        bssid = b"\x02\x00\x00\x00\x00\x01"
        src = b"\x02\x00\x00\x00\x00\x02"
        frame = self.exp._build_gtk_probe_frame(bssid, src)
        assert isinstance(frame, bytes)
        assert b"GTK_BYPASS_PROBE" in frame

    def test_has_run_method(self):
        assert callable(self.exp.run)

    def test_has_check_method(self):
        assert callable(self.exp.check)


# ===================================================================
# Aruba CMDI Batch
# ===================================================================

class TestArubaCMDIBatch:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.Exploit = _load_exploit(ARUBA_CMDI)
        self.exp = self.Exploit()

    def test_class_exists(self):
        assert self.Exploit is not None

    def test_info_cve(self):
        info = self.exp._Exploit__info__
        assert "CVE-2026-44865" in info["name"]

    def test_default_port(self):
        assert int(self.exp.port) == 4343

    def test_injection_endpoints_exist(self):
        assert len(self.exp._INJECTION_ENDPOINTS) >= 5

    def test_injection_endpoint_structure(self):
        for key, (endpoint, param) in self.exp._INJECTION_ENDPOINTS.items():
            assert isinstance(endpoint, str)
            assert isinstance(param, str)
            assert endpoint.startswith("/")

    def test_command_option(self):
        assert str(self.exp.command) == "id"

    def test_username_option(self):
        assert str(self.exp.username) == "operator"

    def test_injection_vector_option(self):
        assert int(self.exp.injection_vector) == 1

    def test_has_run_method(self):
        assert callable(self.exp.run)

    def test_has_authenticate_method(self):
        assert callable(self.exp._authenticate)


# ===================================================================
# Aruba Unauth DoS
# ===================================================================

class TestArubaUnauthDoS:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.Exploit = _load_exploit(ARUBA_DOS)
        self.exp = self.Exploit()

    def test_class_exists(self):
        assert self.Exploit is not None

    def test_info_cve(self):
        info = self.exp._Exploit__info__
        assert "CVE-2026-23824" in info["name"]

    def test_default_port(self):
        assert int(self.exp.port) == 8211

    def test_papi_magic(self):
        assert self.exp._PAPI_MAGIC == 0x4972

    def test_papi_header_build(self):
        hdr = self.exp._build_papi_header(0x0001, 100)
        assert isinstance(hdr, bytes)
        magic = struct.unpack(">H", hdr[:2])[0]
        assert magic == 0x4972

    def test_tlv_build(self):
        tlv = self.exp._build_tlv(0x0001, b"test")
        assert isinstance(tlv, bytes)
        t, l = struct.unpack(">HH", tlv[:4])
        assert t == 1
        assert l == 4

    def test_malformed_papi_build(self):
        pkt = self.exp._build_malformed_papi()
        assert isinstance(pkt, bytes)
        assert len(pkt) > 20

    def test_malformed_papi_contains_oversized_tlv(self):
        pkt = self.exp._build_malformed_papi()
        assert b"\x42" * 16 in pkt

    def test_normal_papi_build(self):
        pkt = self.exp._build_normal_papi()
        assert isinstance(pkt, bytes)
        magic = struct.unpack(">H", pkt[:2])[0]
        assert magic == 0x4972

    def test_has_run_method(self):
        assert callable(self.exp.run)


# ===================================================================
# FortiAP OS CMDI
# ===================================================================

class TestFortiAPCMDI:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.Exploit = _load_exploit(FORTIAP_CMDI)
        self.exp = self.Exploit()

    def test_class_exists(self):
        assert self.Exploit is not None

    def test_info_cve(self):
        info = self.exp._Exploit__info__
        assert "CVE-2025-53680" in info["name"]

    def test_info_targets(self):
        info = self.exp._Exploit__info__
        targets_str = " ".join(info["targets"])
        assert "FortiAP" in targets_str

    def test_default_port(self):
        assert int(self.exp.port) == 443

    def test_command_option(self):
        assert str(self.exp.command) == "id"

    def test_username_option(self):
        assert str(self.exp.username) == "admin"

    def test_login_path(self):
        assert self.exp._LOGIN_PATH.startswith("/")

    def test_diag_path(self):
        assert "diagnostic" in self.exp._DIAG_PATH or "diag" in self.exp._DIAG_PATH

    def test_has_run_method(self):
        assert callable(self.exp.run)

    def test_has_check_method(self):
        assert callable(self.exp.check)

    def test_has_authenticate_method(self):
        assert callable(self.exp._authenticate)


# ===================================================================
# Apple CoreAudio + BCMWLan Chain
# ===================================================================

class TestAppleChain:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.Exploit = _load_exploit(APPLE_CHAIN)
        self.exp = self.Exploit()

    def test_class_exists(self):
        assert self.Exploit is not None

    def test_info_cve(self):
        info = self.exp._Exploit__info__
        assert "CVE-2025-31200" in info["name"]

    def test_info_description(self):
        info = self.exp._Exploit__info__
        assert "CoreAudio" in info["description"]

    def test_info_platform(self):
        info = self.exp._Exploit__info__
        assert info["platform"] == "ios"

    def test_info_references(self):
        info = self.exp._Exploit__info__
        assert any("apple.com" in r for r in info["references"])

    def test_malformed_aac_frame_build(self):
        frame = self.exp._build_malformed_aac_frame()
        assert isinstance(frame, bytes)
        assert len(frame) > 30

    def test_aac_frame_starts_with_sync(self):
        frame = self.exp._build_malformed_aac_frame()
        sync = struct.unpack(">H", frame[:2])[0]
        assert sync == 0xFFF1

    def test_radiotap_header(self):
        hdr = self.exp._build_radiotap_header()
        assert len(hdr) == 8

    def test_wifi_delivery_frame_build(self):
        payload = b"test_payload"
        frame = self.exp._build_wifi_delivery_frame(payload)
        assert isinstance(frame, bytes)
        assert payload in frame

    def test_delivery_method_option(self):
        assert str(self.exp.delivery_method) in ("wifi", "simulate")

    def test_delivery_method_default(self):
        assert str(self.exp.delivery_method) in ("wifi", "simulate")

    def test_has_run_method(self):
        assert callable(self.exp.run)

    def test_has_exploit_method(self):
        assert hasattr(self.exp, "_exploit")
