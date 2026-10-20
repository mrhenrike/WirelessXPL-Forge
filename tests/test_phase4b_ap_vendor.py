# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Tests for Phase 4B: AP Vendor CVE modules (TP-Link, NETGEAR, ASUS, D-Link, Cudy)."""
import importlib

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_module(rel_path: str):
    """Import an exploit module by dotted path and return the Exploit class."""
    mod = importlib.import_module(rel_path)
    return mod.Exploit


def _make_exploit(cls, **overrides):
    """Instantiate an Exploit with sensible defaults, applying overrides."""
    obj = cls.__new__(cls)
    # Set default option values from class attributes
    for attr_name in dir(cls):
        attr = getattr(cls, attr_name, None)
        if hasattr(attr, "value"):
            setattr(obj, attr_name, overrides.get(attr_name, attr.value))
    for k, v in overrides.items():
        setattr(obj, k, v)
    return obj


# ============================================================================
# TP-Link modules
# ============================================================================

class TestTPLinkCmdiCVE2026_3227:
    MODULE = "wirelessxpl.modules.generic.access_points.tplink.tplink_cmdi_cve_2026_3227"

    def test_import(self):
        cls = _load_module(self.MODULE)
        assert cls is not None

    def test_info_name(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        assert "CVE-2026-3227" in info["name"]

    def test_info_has_required_fields(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        for field in ("name", "description", "authors", "references", "targets"):
            assert field in info, f"Missing field: {field}"

    def test_default_target(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.target is not None

    def test_default_port(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.port == 80

    def test_default_command(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.command == "id"

    def test_has_check_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "check", None))

    def test_has_run_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "run", None))

    def test_has_exploit_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_exploit", None))

    def test_ping_path_constant(self):
        cls = _load_module(self.MODULE)
        assert hasattr(cls, "_PING_PATH")


class TestTPLinkDhcpCmdiCVE2026_11834:
    MODULE = "wirelessxpl.modules.generic.access_points.tplink.tplink_dhcp_cmdi_cve_2026_11834"

    def test_import(self):
        cls = _load_module(self.MODULE)
        assert cls is not None

    def test_info_name(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        assert "CVE-2026-11834" in info["name"]

    def test_info_fields(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        for field in ("name", "description", "authors", "references"):
            assert field in info

    def test_default_port(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.port == 67

    def test_dhcp_constants(self):
        cls = _load_module(self.MODULE)
        assert cls._DHCP_DISCOVER == 1
        assert cls._OPT_HOSTNAME == 12
        assert cls._OPT_END == 255

    def test_build_dhcp_discover(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls, target="192.168.1.1", command="whoami")
        packet = obj._build_dhcp_discover()
        assert isinstance(packet, bytes)
        assert len(packet) > 240
        # DHCP magic cookie present
        assert b"\x63\x82\x53\x63" in packet

    def test_dhcp_discover_contains_hostname(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls, target="192.168.1.1", command="uname")
        packet = obj._build_dhcp_discover()
        assert b"host;uname;" in packet

    def test_has_check_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "check", None))

    def test_has_run_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "run", None))

    def test_has_exploit_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_exploit", None))


class TestTPLinkCmdiCVE2026_11814:
    MODULE = "wirelessxpl.modules.generic.access_points.tplink.tplink_cmdi_cve_2026_11814"

    def test_import(self):
        cls = _load_module(self.MODULE)
        assert cls is not None

    def test_info_name(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        assert "CVE-2026-11814" in info["name"]

    def test_info_fields(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        for field in ("name", "description", "authors", "references"):
            assert field in info

    def test_default_port(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.port == 80

    def test_default_credentials(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.username == "admin"
        assert obj.password == "admin"

    def test_trace_path_constant(self):
        cls = _load_module(self.MODULE)
        assert hasattr(cls, "_TRACE_PATH")
        assert "Trace" in cls._TRACE_PATH or "trace" in cls._TRACE_PATH

    def test_has_check_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "check", None))

    def test_has_run_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "run", None))

    def test_has_exploit_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_exploit", None))


# ============================================================================
# NETGEAR modules
# ============================================================================

class TestNetgearCertCmdiCVE2026_9213:
    MODULE = "wirelessxpl.modules.generic.access_points.netgear.netgear_cert_cmdi_cve_2026_9213"

    def test_import(self):
        cls = _load_module(self.MODULE)
        assert cls is not None

    def test_info_name(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        assert "CVE-2026-9213" in info["name"]

    def test_info_fields(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        for field in ("name", "description", "authors", "references"):
            assert field in info

    def test_default_port(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.port == 443

    def test_soap_path_constant(self):
        cls = _load_module(self.MODULE)
        assert hasattr(cls, "_SOAP_PATH")

    def test_has_check_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "check", None))

    def test_has_run_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "run", None))

    def test_has_exploit_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_exploit", None))


class TestNetgearTrafficRceCVE2026_62656:
    MODULE = "wirelessxpl.modules.generic.access_points.netgear.netgear_traffic_rce_cve_2026_62656"

    def test_import(self):
        cls = _load_module(self.MODULE)
        assert cls is not None

    def test_info_name(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        assert "CVE-2026-62656" in info["name"]

    def test_info_fields(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        for field in ("name", "description", "authors", "references"):
            assert field in info

    def test_default_port(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.port == 1900

    def test_ssdp_constants(self):
        cls = _load_module(self.MODULE)
        assert cls._SSDP_PORT == 1900
        assert cls._SSDP_MULTICAST == "239.255.255.250"

    def test_build_ssdp_overflow(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls, target="192.168.1.1", overflow_size=512)
        packet = obj._build_ssdp_overflow()
        assert isinstance(packet, bytes)
        assert b"NOTIFY" in packet
        assert b"AAAA" in packet
        assert len(packet) > 512

    def test_overflow_size_in_packet(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls, target="192.168.1.1", overflow_size=256)
        packet = obj._build_ssdp_overflow()
        assert packet.count(b"A") >= 256

    def test_has_check_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "check", None))

    def test_has_exploit_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_exploit", None))


class TestNetgearWebCmdiCVE2026_62657:
    MODULE = "wirelessxpl.modules.generic.access_points.netgear.netgear_web_cmdi_cve_2026_62657"

    def test_import(self):
        cls = _load_module(self.MODULE)
        assert cls is not None

    def test_info_name(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        assert "CVE-2026-62657" in info["name"]

    def test_default_port(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.port == 80

    def test_default_credentials(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.username == "admin"
        assert obj.password == "password"

    def test_device_path_constant(self):
        cls = _load_module(self.MODULE)
        assert hasattr(cls, "_DEVICE_PATH")

    def test_has_check_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "check", None))

    def test_has_run_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "run", None))

    def test_has_exploit_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_exploit", None))


class TestNetgearDhcpv6CmdiCVE2026_0404:
    MODULE = "wirelessxpl.modules.generic.access_points.netgear.netgear_dhcpv6_cmdi_cve_2026_0404"

    def test_import(self):
        cls = _load_module(self.MODULE)
        assert cls is not None

    def test_info_name(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        assert "CVE-2026-0404" in info["name"]

    def test_info_fields(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        for field in ("name", "description", "authors", "references"):
            assert field in info

    def test_default_port(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.port == 547

    def test_dhcpv6_constants(self):
        cls = _load_module(self.MODULE)
        assert cls._DHCPV6_REPLY == 7
        assert cls._OPT_SERVERID == 2
        assert cls._OPT_DOMAIN_SEARCH == 24

    def test_build_dhcpv6_reply(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls, target="192.168.1.1", command="whoami")
        packet = obj._build_dhcpv6_reply()
        assert isinstance(packet, bytes)
        assert len(packet) > 10
        # First byte is message type (REPLY = 7)
        assert packet[0] == 7

    def test_dhcpv6_reply_contains_command(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls, target="192.168.1.1", command="uname")
        packet = obj._build_dhcpv6_reply()
        assert b"uname" in packet

    def test_has_check_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "check", None))

    def test_has_exploit_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_exploit", None))


class TestNetgearExtenderAuthBypassCVE2026_0407:
    MODULE = "wirelessxpl.modules.generic.access_points.netgear.netgear_extender_auth_bypass_cve_2026_0407"

    def test_import(self):
        cls = _load_module(self.MODULE)
        assert cls is not None

    def test_info_name(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        assert "CVE-2026-0407" in info["name"]

    def test_info_fields(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        for field in ("name", "description", "authors", "references"):
            assert field in info

    def test_default_port(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.port == 80

    def test_setup_path_constant(self):
        cls = _load_module(self.MODULE)
        assert hasattr(cls, "_SETUP_PATH")
        assert hasattr(cls, "_SETTINGS_PATH")

    def test_has_check_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "check", None))

    def test_has_run_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "run", None))

    def test_has_exploit_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_exploit", None))


class TestNetgearCertWeakCVE2026_62658:
    MODULE = "wirelessxpl.modules.generic.access_points.netgear.netgear_cert_weak_cve_2026_62658"

    def test_import(self):
        cls = _load_module(self.MODULE)
        assert cls is not None

    def test_info_name(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        assert "CVE-2026-62658" in info["name"]

    def test_info_fields(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        for field in ("name", "description", "authors", "references"):
            assert field in info

    def test_default_port(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.port == 443

    def test_has_check_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "check", None))

    def test_has_run_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "run", None))

    def test_has_exploit_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_exploit", None))

    def test_check_cert_validation_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_check_cert_validation", None))


# ============================================================================
# ASUS module
# ============================================================================

class TestAsusMitmCertCVE2026_13385:
    MODULE = "wirelessxpl.modules.generic.access_points.asus.asus_mitm_cert_cve_2026_13385"

    def test_import(self):
        cls = _load_module(self.MODULE)
        assert cls is not None

    def test_info_name(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        assert "CVE-2026-13385" in info["name"]

    def test_info_fields(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        for field in ("name", "description", "authors", "references"):
            assert field in info

    def test_default_port(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.port == 8443

    def test_has_check_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "check", None))

    def test_has_run_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "run", None))

    def test_has_exploit_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_exploit", None))

    def test_analyze_tls_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_analyze_tls", None))


# ============================================================================
# Cudy module
# ============================================================================

class TestCudyCmdiCVE2026_38713:
    MODULE = "wirelessxpl.modules.generic.access_points.cudy.cudy_cmdi_cve_2026_38713"

    def test_import(self):
        cls = _load_module(self.MODULE)
        assert cls is not None

    def test_info_name(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        assert "CVE-2026-38713" in info["name"]

    def test_info_fields(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        for field in ("name", "description", "authors", "references"):
            assert field in info

    def test_default_port(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.port == 80

    def test_ntp_path_constant(self):
        cls = _load_module(self.MODULE)
        assert hasattr(cls, "_NTP_PATH")
        assert "ntp" in cls._NTP_PATH.lower() or "time" in cls._NTP_PATH.lower()

    def test_has_check_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "check", None))

    def test_has_run_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "run", None))

    def test_has_exploit_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_exploit", None))


# ============================================================================
# D-Link FOTA module
# ============================================================================

class TestDlinkFotaCmdiCVE2026_1624:
    MODULE = "wirelessxpl.modules.generic.access_points.dlink.dlink_fota_cmdi_cve_2026_1624"

    def test_import(self):
        cls = _load_module(self.MODULE)
        assert cls is not None

    def test_info_name(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        assert "CVE-2026-1624" in info["name"]

    def test_info_fields(self):
        cls = _load_module(self.MODULE)
        info = cls._Exploit__info__
        for field in ("name", "description", "authors", "references"):
            assert field in info

    def test_default_port(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.port == 80

    def test_default_credentials(self):
        cls = _load_module(self.MODULE)
        obj = _make_exploit(cls)
        assert obj.username == "admin"
        assert obj.password == "admin"

    def test_fota_path_constant(self):
        cls = _load_module(self.MODULE)
        assert hasattr(cls, "_FOTA_PATH")
        assert "fota" in cls._FOTA_PATH.lower()

    def test_has_check_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "check", None))

    def test_has_run_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "run", None))

    def test_has_exploit_method(self):
        cls = _load_module(self.MODULE)
        assert callable(getattr(cls, "_exploit", None))
