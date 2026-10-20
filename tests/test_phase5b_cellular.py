"""Unit tests for Phase 5B Cellular/Baseband + RF HID exploit modules."""
import importlib
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Module paths
_PHASE5B_MODULES = [
    "wirelessxpl.modules.generic.cellular.samsung.exynos_nr_rrc_null_dos_cve_2026_33970",
    "wirelessxpl.modules.generic.cellular.samsung.exynos_nr_rrc_downlink_cve_2026_23792",
    "wirelessxpl.modules.generic.cellular.samsung.exynos_sms_tpud_oob_write_cve_2025_62818",
    "wirelessxpl.modules.generic.cellular.samsung.exynos_sms_rpdata_stack_overflow_cve_2025_54328",
    "wirelessxpl.modules.generic.cellular.samsung.exynos_modem_crash_cve_2025_26780",
    "wirelessxpl.modules.generic.cellular.gtp_u_tunnel_injection",
    "wirelessxpl.modules.generic.cellular.volte_ims_interception",
    "wirelessxpl.modules.generic.rf.mousejack_nrf24_hid",
]

_PHASE5B_CVES = [
    ("wirelessxpl.modules.generic.cellular.samsung.exynos_nr_rrc_null_dos_cve_2026_33970", "CVE-2026-33970"),
    ("wirelessxpl.modules.generic.cellular.samsung.exynos_nr_rrc_downlink_cve_2026_23792", "CVE-2026-23792"),
    ("wirelessxpl.modules.generic.cellular.samsung.exynos_sms_tpud_oob_write_cve_2025_62818", "CVE-2025-62818"),
    ("wirelessxpl.modules.generic.cellular.samsung.exynos_sms_rpdata_stack_overflow_cve_2025_54328", "CVE-2025-54328"),
    ("wirelessxpl.modules.generic.cellular.samsung.exynos_modem_crash_cve_2025_26780", "CVE-2025-26780"),
]


class TestModuleImports:
    """Verify all Phase 5B modules import without error."""

    @pytest.mark.parametrize("module_path", _PHASE5B_MODULES)
    def test_module_imports(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        assert hasattr(mod, "Exploit")

    @pytest.mark.parametrize("module_path", _PHASE5B_MODULES)
    def test_exploit_has_required_methods(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "check")
        assert hasattr(instance, "run")
        assert callable(instance.check)
        assert callable(instance.run)

    @pytest.mark.parametrize("module_path", _PHASE5B_MODULES)
    def test_exploit_has_timeout_option(self, module_path: str) -> None:
        mod = importlib.import_module(module_path)
        instance = mod.Exploit()
        assert hasattr(instance, "timeout")

    @pytest.mark.parametrize("module_path,expected_cve", _PHASE5B_CVES)
    def test_class_info_contains_cve(self, module_path: str, expected_cve: str) -> None:
        mod = importlib.import_module(module_path)
        cls = mod.Exploit
        info = getattr(cls, "_Exploit__info__", None) or getattr(cls, "__info__", {})
        assert expected_cve in info.get("name", ""), f"CVE not in __info__['name'] for {module_path}"


# ---------------------------------------------------------------------------
# Exynos NR RRC Null Pointer DoS (CVE-2026-33970)
# ---------------------------------------------------------------------------
class TestExynosNrRrcNullDos:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.cellular.samsung.exynos_nr_rrc_null_dos_cve_2026_33970"
        )
        e = mod.Exploit()
        e.timeout = 1.0
        return e

    def test_rrc_reconfiguration_normal(self, exploit) -> None:
        pkt = exploit._build_rrc_reconfiguration(include_mandatory_ie=True)
        assert isinstance(pkt, bytes)
        assert len(pkt) > 10
        # First byte is message type
        assert pkt[0] == exploit._RRC_RECONFIGURATION

    def test_rrc_reconfiguration_malformed(self, exploit) -> None:
        pkt = exploit._build_rrc_reconfiguration(include_mandatory_ie=False)
        assert isinstance(pkt, bytes)
        # Malformed should be shorter (missing CellGroupConfig IE)
        normal = exploit._build_rrc_reconfiguration(include_mandatory_ie=True)
        assert len(pkt) < len(normal)

    def test_pdcp_pdu_wrapping(self, exploit) -> None:
        payload = b"\x01\x02\x03"
        pdu = exploit._build_pdcp_pdu(payload, sn=5)
        assert isinstance(pdu, bytes)
        assert len(pdu) == 2 + len(payload)
        # Check SN encoding
        assert (pdu[0] & 0x0F) == 0  # SN high bits
        assert pdu[1] == 5  # SN low byte

    def test_rlc_pdu_wrapping(self, exploit) -> None:
        payload = b"\xAA\xBB"
        pdu = exploit._build_rlc_pdu(payload, sn=10)
        assert isinstance(pdu, bytes)
        assert len(pdu) == 2 + len(payload)

    def test_mac_pdu_short_header(self, exploit) -> None:
        payload = b"\x01" * 50
        pdu = exploit._build_mac_pdu(payload, lcid=1)
        assert isinstance(pdu, bytes)
        assert len(pdu) == 2 + len(payload)

    def test_mac_pdu_long_header(self, exploit) -> None:
        payload = b"\x01" * 300
        pdu = exploit._build_mac_pdu(payload, lcid=1)
        assert isinstance(pdu, bytes)
        # Long header: 3 bytes
        assert len(pdu) == 3 + len(payload)

    def test_trigger_packet_full_stack(self, exploit) -> None:
        pkt = exploit._build_trigger_packet()
        assert isinstance(pkt, bytes)
        assert len(pkt) > 6

    def test_normal_packet(self, exploit) -> None:
        pkt = exploit._build_normal_packet()
        assert isinstance(pkt, bytes)
        trigger = exploit._build_trigger_packet()
        assert len(pkt) > len(trigger)

    def test_check_no_target_no_sdr(self, exploit) -> None:
        exploit.target = ""
        exploit.sdr_device = ""
        assert exploit.check() is False

    def test_check_sdr_mode(self, exploit) -> None:
        exploit.sdr_device = "hackrf"
        assert exploit.check() is True

    def test_run_no_target(self, exploit) -> None:
        exploit.target = ""
        exploit.sdr_device = ""
        exploit.run()  # Should print error, not crash


# ---------------------------------------------------------------------------
# Exynos NR RRC Downlink Injection (CVE-2026-23792)
# ---------------------------------------------------------------------------
class TestExynosNrRrcDownlink:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.cellular.samsung.exynos_nr_rrc_downlink_cve_2026_23792"
        )
        e = mod.Exploit()
        e.timeout = 1.0
        e.redirect_arfcn = 500
        return e

    def test_sib1_redirect(self, exploit) -> None:
        sib = exploit._build_sib1_redirect()
        assert isinstance(sib, bytes)
        assert sib[0] == exploit._SIB1

    def test_rrc_reject(self, exploit) -> None:
        reject = exploit._build_rrc_reject()
        assert isinstance(reject, bytes)
        assert reject[0] == exploit._RRC_REJECT
        # Check redirect ARFCN is encoded
        arfcn_bytes = struct.pack(">I", 500)
        assert arfcn_bytes in reject

    def test_bcch_dl_sch_pdu(self, exploit) -> None:
        sib = exploit._build_sib1_redirect()
        pdu = exploit._build_bcch_dl_sch_pdu(sib)
        assert isinstance(pdu, bytes)
        assert pdu[0] == 0x00  # SIB1 indicator

    def test_check_sdr_mode(self, exploit) -> None:
        exploit.sdr_device = "usrp"
        assert exploit.check() is True

    def test_run_sdr_mode(self, exploit) -> None:
        exploit.sdr_device = "hackrf"
        exploit.target = ""
        exploit.run()  # SDR mode, prints info


# ---------------------------------------------------------------------------
# Exynos SMS TP-UD OOB Write (CVE-2025-62818)
# ---------------------------------------------------------------------------
class TestExynosSmsTPUD:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.cellular.samsung.exynos_sms_tpud_oob_write_cve_2025_62818"
        )
        e = mod.Exploit()
        e.timeout = 1.0
        e.overflow_size = 256
        return e

    def test_encode_phone_number(self, exploit) -> None:
        encoded = exploit._encode_phone_number("1234567890")
        assert isinstance(encoded, bytes)
        assert len(encoded) == 5  # 10 digits -> 5 bytes BCD

    def test_encode_phone_number_odd(self, exploit) -> None:
        encoded = exploit._encode_phone_number("12345")
        assert isinstance(encoded, bytes)
        assert len(encoded) == 3  # 5 digits + F padding -> 3 bytes

    def test_sms_deliver_normal(self, exploit) -> None:
        pdu = exploit._build_sms_deliver_pdu(oversized=False)
        assert isinstance(pdu, bytes)
        # First octet should have MTI=00 (SMS-DELIVER)
        assert (pdu[0] & 0x03) == exploit._MTI_SMS_DELIVER

    def test_sms_deliver_oversized(self, exploit) -> None:
        pdu = exploit._build_sms_deliver_pdu(oversized=True)
        assert isinstance(pdu, bytes)
        normal = exploit._build_sms_deliver_pdu(oversized=False)
        assert len(pdu) > len(normal)

    def test_smpp_submit(self, exploit) -> None:
        pdu = exploit._build_sms_deliver_pdu(oversized=True)
        smpp = exploit._build_smpp_submit(pdu)
        assert isinstance(smpp, bytes)
        # SMPP command_id for submit_sm = 0x00000004
        cmd_id = struct.unpack(">I", smpp[4:8])[0]
        assert cmd_id == 0x00000004

    def test_check_no_target(self, exploit) -> None:
        exploit.target = ""
        assert exploit.check() is False


# ---------------------------------------------------------------------------
# Exynos SMS RP-DATA Stack Overflow (CVE-2025-54328)
# ---------------------------------------------------------------------------
class TestExynosSmsRPDATA:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.cellular.samsung.exynos_sms_rpdata_stack_overflow_cve_2025_54328"
        )
        e = mod.Exploit()
        e.timeout = 1.0
        e.overflow_size = 512
        return e

    def test_encode_bcd(self, exploit) -> None:
        encoded = exploit._encode_bcd_number("1234567")
        assert isinstance(encoded, bytes)
        assert len(encoded) == 4  # 7 digits + F -> 4 bytes

    def test_rp_data_normal(self, exploit) -> None:
        pdu = exploit._build_rp_data(oversized=False)
        assert isinstance(pdu, bytes)
        assert pdu[0] == exploit._RP_DATA_MT

    def test_rp_data_overflow(self, exploit) -> None:
        pdu = exploit._build_rp_data(oversized=True)
        assert isinstance(pdu, bytes)
        normal = exploit._build_rp_data(oversized=False)
        assert len(pdu) > len(normal)

    def test_nas_sms_transport(self, exploit) -> None:
        rp = exploit._build_rp_data(oversized=True)
        nas = exploit._build_nas_sms_transport(rp)
        assert isinstance(nas, bytes)
        # Protocol discriminator: SMS (0x09)
        assert (nas[0] & 0x0F) == 0x09

    def test_check_no_target(self, exploit) -> None:
        exploit.target = ""
        assert exploit.check() is False


# ---------------------------------------------------------------------------
# Exynos Single-Packet Modem Crash (CVE-2025-26780)
# ---------------------------------------------------------------------------
class TestExynosModemCrash:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.cellular.samsung.exynos_modem_crash_cve_2025_26780"
        )
        e = mod.Exploit()
        e.timeout = 1.0
        return e

    def test_crash_pdu(self, exploit) -> None:
        pdu = exploit._build_nas_emm_crash()
        assert isinstance(pdu, bytes)
        # PD should be EMM (0x07)
        assert (pdu[0] & 0x0F) == exploit._PD_EMM

    def test_crash_pdu_contains_malformed_tai(self, exploit) -> None:
        pdu = exploit._build_nas_emm_crash()
        # Should contain 0xFF (the malformed TAI list length)
        assert b"\xFF" in pdu

    def test_normal_nas(self, exploit) -> None:
        pdu = exploit._build_normal_nas()
        assert isinstance(pdu, bytes)
        assert (pdu[0] & 0x0F) == exploit._PD_EMM

    def test_check_sdr_mode(self, exploit) -> None:
        exploit.sdr_device = "hackrf"
        assert exploit.check() is True

    def test_check_no_target_no_sdr(self, exploit) -> None:
        exploit.target = ""
        exploit.sdr_device = ""
        assert exploit.check() is False

    def test_run_sdr_mode(self, exploit) -> None:
        exploit.sdr_device = "hackrf"
        exploit.run()  # Should print info, not crash


# ---------------------------------------------------------------------------
# GTP-U Tunnel Injection
# ---------------------------------------------------------------------------
class TestGtpUTunnel:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.cellular.gtp_u_tunnel_injection"
        )
        e = mod.Exploit()
        e.timeout = 1.0
        e.teid = 0x12345678
        e.inject_dst = "10.0.0.1"
        e.inject_payload = "TEST"
        e.packet_count = 5
        return e

    def test_gtp_header(self, exploit) -> None:
        hdr = exploit._build_gtp_header(0xFF, 100, 0x12345678)
        assert isinstance(hdr, bytes)
        assert len(hdr) == 8
        # Version should be 1
        flags = hdr[0]
        version = (flags >> 5) & 0x07
        assert version == 1
        # TEID
        teid = struct.unpack(">I", hdr[4:8])[0]
        assert teid == 0x12345678

    def test_inner_ip_packet(self, exploit) -> None:
        inner = exploit._build_inner_ip_packet("8.8.8.8", b"hello")
        assert isinstance(inner, bytes)
        # IPv4 version+IHL
        assert (inner[0] >> 4) == 4
        # Protocol = UDP (17)
        assert inner[9] == 17

    def test_echo_request(self, exploit) -> None:
        echo = exploit._build_echo_request()
        assert isinstance(echo, bytes)
        assert len(echo) == 8
        # Message type = Echo Request (0x01)
        assert echo[1] == 0x01

    def test_inject_packet(self, exploit) -> None:
        pkt = exploit._build_inject_packet()
        assert isinstance(pkt, bytes)
        # First 8 bytes are GTP header
        assert len(pkt) > 8
        # Message type = G-PDU (0xFF)
        assert pkt[1] == 0xFF
        # TEID
        teid = struct.unpack(">I", pkt[4:8])[0]
        assert teid == 0x12345678

    def test_check_no_target(self, exploit) -> None:
        exploit.target = ""
        assert exploit.check() is False


# ---------------------------------------------------------------------------
# VoLTE / IMS Interception
# ---------------------------------------------------------------------------
class TestVoLTEIMS:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.cellular.volte_ims_interception"
        )
        e = mod.Exploit()
        e.timeout = 1.0
        e.caller_uri = "sip:attacker@test.local"
        e.callee_uri = "sip:target@test.local"
        e.target = "192.168.1.1"
        e.rtp_port = 8000
        return e

    def test_generate_call_id(self, exploit) -> None:
        cid = exploit._generate_call_id()
        assert isinstance(cid, str)
        assert "@" in cid

    def test_generate_branch(self, exploit) -> None:
        branch = exploit._generate_branch()
        assert isinstance(branch, str)
        assert branch.startswith("z9hG4bK")

    def test_sip_invite(self, exploit) -> None:
        invite = exploit._build_sip_invite()
        assert isinstance(invite, bytes)
        text = invite.decode()
        assert "INVITE" in text
        assert "SIP/2.0" in text
        assert "Content-Type: application/sdp" in text

    def test_sip_invite_redirect(self, exploit) -> None:
        exploit.redirect_uri = "sip:evil@attacker.local"
        invite = exploit._build_sip_invite()
        text = invite.decode()
        assert "sip:evil@attacker.local" in text

    def test_sip_options(self, exploit) -> None:
        options = exploit._build_sip_options()
        assert isinstance(options, bytes)
        text = options.decode()
        assert "OPTIONS" in text
        assert "SIP/2.0" in text

    def test_check_no_target(self, exploit) -> None:
        exploit.target = ""
        assert exploit.check() is False


# ---------------------------------------------------------------------------
# MouseJack nRF24 HID Injection
# ---------------------------------------------------------------------------
class TestMouseJack:
    @pytest.fixture()
    def exploit(self):
        mod = importlib.import_module(
            "wirelessxpl.modules.generic.rf.mousejack_nrf24_hid"
        )
        e = mod.Exploit()
        e.timeout = 1.0
        e.dongle_address = "AA:BB:CC:DD:EE"
        e.channel = 5
        e.keystrokes = "hello"
        e.payload_type = "unifying"
        e.dwell_time = 0.001
        return e

    def test_parse_address(self, exploit) -> None:
        addr = exploit._parse_address("AA:BB:CC:DD:EE")
        assert addr == bytes.fromhex("AABBCCDDEE")
        assert len(addr) == 5

    def test_parse_address_no_colons(self, exploit) -> None:
        addr = exploit._parse_address("AABBCCDDEE")
        assert addr == bytes.fromhex("AABBCCDDEE")

    def test_parse_address_invalid(self, exploit) -> None:
        addr = exploit._parse_address("short")
        assert addr == b"\x00" * 5

    def test_char_to_hid_lowercase(self, exploit) -> None:
        code, mod = exploit._char_to_hid("a")
        assert code == 0x04
        assert mod == exploit._HID_MOD_NONE

    def test_char_to_hid_uppercase(self, exploit) -> None:
        code, mod = exploit._char_to_hid("A")
        assert code == 0x04
        assert mod == exploit._HID_MOD_LSHIFT

    def test_char_to_hid_space(self, exploit) -> None:
        code, mod = exploit._char_to_hid(" ")
        assert code == 0x2C
        assert mod == exploit._HID_MOD_NONE

    def test_char_to_hid_enter(self, exploit) -> None:
        code, mod = exploit._char_to_hid("\n")
        assert code == 0x28

    def test_unifying_keystroke(self, exploit) -> None:
        frame = exploit._build_unifying_keystroke(0x04, 0x00)
        assert isinstance(frame, bytes)
        assert frame[0] == exploit._UNIFYING_KEYBOARD

    def test_unifying_key_release(self, exploit) -> None:
        frame = exploit._build_unifying_key_release()
        assert isinstance(frame, bytes)
        # Scan code should be 0
        assert frame[3] == 0x00

    def test_microsoft_keystroke(self, exploit) -> None:
        frame = exploit._build_microsoft_keystroke(0x04, 0x02)
        assert isinstance(frame, bytes)
        assert frame[0] == 0x08  # Keyboard device type

    def test_generic_keystroke(self, exploit) -> None:
        frame = exploit._build_generic_keystroke(0x04)
        assert isinstance(frame, bytes)
        assert len(frame) == 7

    def test_build_keystroke_unifying(self, exploit) -> None:
        exploit.payload_type = "unifying"
        frame = exploit._build_keystroke(0x04)
        assert frame[0] == exploit._UNIFYING_KEYBOARD

    def test_build_keystroke_microsoft(self, exploit) -> None:
        exploit.payload_type = "microsoft"
        frame = exploit._build_keystroke(0x04)
        assert frame[0] == 0x08

    def test_build_keystroke_generic(self, exploit) -> None:
        exploit.payload_type = "generic"
        frame = exploit._build_keystroke(0x04)
        assert len(frame) == 7

    def test_check_valid_address(self, exploit) -> None:
        assert exploit.check() is True

    def test_check_no_address(self, exploit) -> None:
        exploit.dongle_address = ""
        assert exploit.check() is False

    def test_run_no_keystrokes(self, exploit) -> None:
        exploit.keystrokes = ""
        exploit.run()  # Should print error, not crash

    def test_run_valid(self, exploit) -> None:
        exploit.run()  # Should complete without error

    def test_hid_keys_coverage(self, exploit) -> None:
        """Verify HID key table covers all common ASCII chars."""
        assert len(exploit._HID_KEYS) >= 40
        for char in "abcdefghijklmnopqrstuvwxyz0123456789":
            assert char in exploit._HID_KEYS
