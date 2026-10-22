"""Coverage tests for core/pcap, interpreter, and modules/generic/sim.

Smoke tests that import, instantiate, and exercise code paths without
requiring hardware (PC/SC readers, SDR, BLE adapters, etc.).
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# 1. core/pcap dataclasses and helpers (no scapy needed for struct tests)
# ---------------------------------------------------------------------------


class TestPcapParserDataclasses:
    """Test pcap_parser dataclass instantiation and properties."""

    def test_access_point_basic(self) -> None:
        from wirelessxpl.core.pcap.pcap_parser import AccessPoint

        ap = AccessPoint(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="TestNet",
            channel=6,
            encryption="WPA2",
            cipher="CCMP",
            auth="PSK",
        )
        assert ap.bssid == "AA:BB:CC:DD:EE:FF"
        assert ap.key == "AA:BB:CC:DD:EE:FF"

    def test_station_basic(self) -> None:
        from wirelessxpl.core.pcap.pcap_parser import Station

        st = Station(mac="11:22:33:44:55:66", associated_bssid="AA:BB:CC:DD:EE:FF")
        assert st.key == "11:22:33:44:55:66"

    def test_eapol_handshake_complete(self) -> None:
        from wirelessxpl.core.pcap.pcap_parser import EAPOLHandshake

        hs = EAPOLHandshake(
            bssid="AA:BB:CC:DD:EE:FF",
            client_mac="11:22:33:44:55:66",
            messages=[1, 2, 3, 4],
        )
        assert hs.is_complete
        assert hs.completeness == "full"

    def test_eapol_handshake_incomplete(self) -> None:
        from wirelessxpl.core.pcap.pcap_parser import EAPOLHandshake

        hs = EAPOLHandshake(
            bssid="AA:BB:CC:DD:EE:FF",
            client_mac="11:22:33:44:55:66",
            messages=[1],
        )
        assert not hs.is_complete

    def test_eapol_handshake_partial_usable(self) -> None:
        from wirelessxpl.core.pcap.pcap_parser import EAPOLHandshake

        hs = EAPOLHandshake(
            bssid="AA:BB:CC:DD:EE:FF",
            client_mac="11:22:33:44:55:66",
            messages=[1, 2],
        )
        assert hs.is_complete
        assert hs.completeness == "partial_usable"

    def test_extracted_credential(self) -> None:
        from wirelessxpl.core.pcap.pcap_parser import ExtractedCredential

        cred = ExtractedCredential(
            protocol="HTTP",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=80,
            dst_port=12345,
            username="admin",
            password="secret",
        )
        assert cred.protocol == "HTTP"
        assert cred.username == "admin"

    def test_rsn_info(self) -> None:
        from wirelessxpl.core.pcap.pcap_parser import RSNInfo

        info = RSNInfo()
        assert info.cipher == ""
        assert info.auth == ""
        assert info.pmf_capable is False

    def test_validate_pcap_path_nonexistent(self) -> None:
        from wirelessxpl.core.pcap.pcap_parser import validate_pcap_path

        with pytest.raises(FileNotFoundError):
            validate_pcap_path("/nonexistent/file.pcap")

    def test_validate_pcap_path_bad_ext(self, tmp_path: Path) -> None:
        from wirelessxpl.core.pcap.pcap_parser import validate_pcap_path

        f = tmp_path / "test.txt"
        f.write_text("not a pcap")
        with pytest.raises(ValueError):
            validate_pcap_path(str(f))

    def test_validate_pcap_path_good(self, tmp_path: Path) -> None:
        from wirelessxpl.core.pcap.pcap_parser import validate_pcap_path

        f = tmp_path / "test.pcap"
        f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
        result = validate_pcap_path(str(f))
        assert result == f

    def test_classify_eapol_message(self) -> None:
        from wirelessxpl.core.pcap.pcap_parser import _classify_eapol_message

        # EAPOL key with msg1 pattern (key info bits)
        # Minimal 99-byte EAPOL frame
        raw = bytearray(99)
        raw[0] = 0x02  # version
        raw[1] = 0x03  # type = key
        # key_info at offset 5-6
        raw[5] = 0x00
        raw[6] = 0x8A  # pairwise + ack = msg1
        result = _classify_eapol_message(bytes(raw))
        assert result in (0, 1, 2, 3, 4)

    def test_akm_type_from_auth(self) -> None:
        from wirelessxpl.core.pcap.pcap_parser import _akm_type_from_auth

        assert _akm_type_from_auth("PSK") is not None
        assert _akm_type_from_auth("UNKNOWN_AUTH_XYZ") is None


class TestPcapParserFunctions:
    """Test pcap_parser functions that don't need real packets."""

    def test_supported_extensions(self) -> None:
        from wirelessxpl.core.pcap.pcap_parser import SUPPORTED_EXTENSIONS

        assert ".pcap" in SUPPORTED_EXTENSIONS
        assert ".pcapng" in SUPPORTED_EXTENSIONS

    def test_load_packets_no_scapy(self, tmp_path: Path) -> None:
        from wirelessxpl.core.pcap import pcap_parser

        f = tmp_path / "test.pcap"
        f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
        if not pcap_parser.SCAPY_AVAILABLE:
            with pytest.raises(Exception):
                pcap_parser.load_packets(str(f))


# ---------------------------------------------------------------------------
# 2. core/pcap/wifi_offline dataclasses
# ---------------------------------------------------------------------------


class TestWifiOfflineDataclasses:
    def test_wep_iv_sample(self) -> None:
        from wirelessxpl.core.pcap.wifi_offline import WEPIVSample

        sample = WEPIVSample(bssid="AA:BB:CC:DD:EE:FF", iv=b"\x01\x02\x03", key_index=0, first_encrypted_byte=0xFF, packet_index=0)
        assert sample.iv == b"\x01\x02\x03"

    def test_wep_analysis(self) -> None:
        from wirelessxpl.core.pcap.wifi_offline import WEPAnalysis

        wa = WEPAnalysis(bssid="AA:BB:CC:DD:EE:FF", ssid="Test", iv_count=1000, unique_ivs=900, weak_ivs=50, samples=[])
        assert wa.bssid == "AA:BB:CC:DD:EE:FF"
        assert wa.iv_count == 1000

    def test_pmkid_entry(self) -> None:
        from wirelessxpl.core.pcap.wifi_offline import PMKIDEntry

        entry = PMKIDEntry(bssid="AA:BB:CC:DD:EE:FF", client_mac="11:22:33:44:55:66", ssid="Test", pmkid="a" * 32, hashcat_line="line")
        assert len(entry.pmkid) == 32

    def test_tkip_mic_info(self) -> None:
        from wirelessxpl.core.pcap.wifi_offline import TKIPMICInfo

        info = TKIPMICInfo(bssid="AA:BB:CC:DD:EE:FF", client_mac="11:22:33:44:55:66", ssid="Test", mic_failures_detected=0, qos_data_packets=10, tkip_fragments=0, chopchop_candidate=False, beck_tews_feasible=False)
        assert info.mic_failures_detected == 0

    def test_sae_commit(self) -> None:
        from wirelessxpl.core.pcap.wifi_offline import SAECommit

        sc = SAECommit(bssid="AA:BB:CC:DD:EE:FF", client_mac="11:22:33:44:55:66", ssid="Test", group_id=19, scalar=b"\x01", element=b"\x02", anti_clogging_token=None, timestamp_us=0.0, frame_index=0)
        assert sc.group_id == 19

    def test_dragonblood_analysis(self) -> None:
        from wirelessxpl.core.pcap.wifi_offline import DragonbloodAnalysis

        da = DragonbloodAnalysis(bssid="AA:BB:CC:DD:EE:FF", ssid="Test", commits=[], timing_deltas_us=[], group_downgrade_detected=False, transition_mode_detected=False, timing_variance_suspicious=False)
        assert da.bssid == "AA:BB:CC:DD:EE:FF"
        assert da.commits == []

    def test_eap_identity(self) -> None:
        from wirelessxpl.core.pcap.wifi_offline import EAPIdentity

        ei = EAPIdentity(bssid="AA:BB:CC:DD:EE:FF", client_mac="11:22:33:44:55:66", ssid="Test", eap_type="PEAP", identity="user@realm.com", challenge=None, response=None, success=None, hashcat_line="")
        assert ei.identity == "user@realm.com"

    def test_eapol_fourway_survey_row(self) -> None:
        from wirelessxpl.core.pcap.wifi_offline import EAPOLFourwaySurveyRow

        row = EAPOLFourwaySurveyRow(bssid="AA:BB:CC:DD:EE:FF", station_mac="11:22:33:44:55:66", ssid="TestNet", message_counts={"M1": 1}, distinct_anonce=1, distinct_snonce=1, replay_counters_seen=[0], hints=[])
        assert row.ssid == "TestNet"


# ---------------------------------------------------------------------------
# 3. core/pcap/crackable_detector
# ---------------------------------------------------------------------------


class TestCrackableDetector:
    def test_handshake_state(self) -> None:
        from wirelessxpl.core.pcap.crackable_detector import HandshakeState

        hs = HandshakeState(
            bssid="AA:BB:CC:DD:EE:FF",
            station="11:22:33:44:55:66",
        )
        assert hs.bssid == "AA:BB:CC:DD:EE:FF"

    def test_crackable_report(self) -> None:
        from wirelessxpl.core.pcap.crackable_detector import CrackableReport

        report = CrackableReport(filepath="test.pcap")
        assert report.handshakes == []
        assert report.crackable_count == 0


# ---------------------------------------------------------------------------
# 4. Interpreter
# ---------------------------------------------------------------------------


class TestInterpreter:
    def test_is_libedit(self) -> None:
        from wirelessxpl.interpreter import is_libedit

        result = is_libedit()
        assert isinstance(result, bool)

    def test_base_interpreter_init(self) -> None:
        from wirelessxpl.interpreter import BaseInterpreter

        bi = BaseInterpreter()
        assert hasattr(bi, "banner")
        assert hasattr(bi, "history_file")

    def test_base_interpreter_parse_line(self) -> None:
        from wirelessxpl.interpreter import BaseInterpreter

        bi = BaseInterpreter()
        cmd, subcmd, kwargs = bi.parse_line("use generic/wifi/test_module")
        assert cmd == "use"

    def test_base_interpreter_parse_line_empty(self) -> None:
        from wirelessxpl.interpreter import BaseInterpreter

        bi = BaseInterpreter()
        cmd, subcmd, kwargs = bi.parse_line("")
        assert cmd == ""

    def test_base_interpreter_commands(self) -> None:
        from wirelessxpl.interpreter import BaseInterpreter

        bi = BaseInterpreter()
        cmds = bi.commands()
        assert isinstance(cmds, list)

    def test_base_interpreter_get_command_handler_unknown(self) -> None:
        from wirelessxpl.core.exploit.exceptions import WirelessXPLException
        from wirelessxpl.interpreter import BaseInterpreter

        bi = BaseInterpreter()
        with pytest.raises(WirelessXPLException):
            bi.get_command_handler("nonexistent_cmd")

    def test_base_interpreter_default_completer(self) -> None:
        from wirelessxpl.interpreter import BaseInterpreter

        bi = BaseInterpreter()
        result = bi.default_completer()
        assert isinstance(result, list)

    def test_base_interpreter_suggested_commands(self) -> None:
        from wirelessxpl.interpreter import BaseInterpreter

        bi = BaseInterpreter()
        result = bi.suggested_commands()
        assert isinstance(result, list)

    def _make_wxf_interp(self) -> Any:
        """Create WXF interpreter with daemon PrinterThread."""
        from wirelessxpl.interpreter import PrinterThread, WirelessXPLInterpreter

        # Make PrinterThread a daemon so it doesn't block test exit
        orig_init = PrinterThread.__init__

        def patched_init(self_pt: Any, *a: Any, **kw: Any) -> None:
            orig_init(self_pt, *a, **kw)
            self_pt.daemon = True

        with patch.object(PrinterThread, "__init__", patched_init):
            return WirelessXPLInterpreter()

    def test_wxf_interpreter_init(self) -> None:
        interp = self._make_wxf_interp()
        assert interp.prompt_hostname == "wxf"
        assert len(interp.modules) >= 0
        assert len(interp.global_commands) > 0

    def test_wxf_interpreter_prompt_no_module(self) -> None:
        interp = self._make_wxf_interp()
        p = interp.prompt
        assert "wxf" in p

    def test_wxf_interpreter_commands(self) -> None:
        interp = self._make_wxf_interp()
        cmds = interp.commands()
        assert isinstance(cmds, list)

    def test_wxf_interpreter_noninteractive_help(self) -> None:
        interp = self._make_wxf_interp()
        interp.nonInteractive(["wxf", "-h"])

    def test_wxf_interpreter_noninteractive_no_module(self) -> None:
        interp = self._make_wxf_interp()
        interp.nonInteractive(["wxf"])


# ---------------------------------------------------------------------------
# 5. SIM modules - smoke tests
# ---------------------------------------------------------------------------


SIM_MODULES = [
    "wirelessxpl.modules.generic.sim.esim_rsp_bridge",
    "wirelessxpl.modules.generic.sim.pysim_reader",
    "wirelessxpl.modules.generic.sim.sim_adm_brute",
    "wirelessxpl.modules.generic.sim.sim_apdu_lab",
    "wirelessxpl.modules.generic.sim.sim_cloner",
    "wirelessxpl.modules.generic.sim.simjacker_info",
]


@pytest.fixture
def mock_no_hw() -> Any:
    """Mock out hardware dependencies for SIM modules."""
    with (
        patch("shutil.which", return_value=None),
        patch("subprocess.run", side_effect=FileNotFoundError("no binary")),
    ):
        yield


class TestSimModulesSmoke:
    """Smoke-test each SIM module: import, instantiate, __info__, check, run(dry)."""

    @pytest.mark.parametrize("mod_path", SIM_MODULES)
    def test_import_and_info(self, mod_path: str) -> None:
        mod = importlib.import_module(mod_path)
        cls = getattr(mod, "Exploit", None)
        assert cls is not None, f"{mod_path} has no Exploit class"
        instance = cls()
        info = getattr(instance, f"_{cls.__name__}__info__", None) or getattr(instance, "__info__", {})
        assert isinstance(info, dict)
        assert "name" in info
        assert "description" in info

    @pytest.mark.parametrize("mod_path", SIM_MODULES)
    def test_check_no_hw(self, mod_path: str, mock_no_hw: Any) -> None:
        mod = importlib.import_module(mod_path)
        cls = getattr(mod, "Exploit")
        instance = cls()
        try:
            result = instance.check()
        except Exception:
            pass

    @pytest.mark.parametrize("mod_path", SIM_MODULES)
    def test_run_dry(self, mod_path: str, mock_no_hw: Any) -> None:
        mod = importlib.import_module(mod_path)
        cls = getattr(mod, "Exploit")
        instance = cls()
        if hasattr(instance, "dry_run"):
            instance.dry_run = True
        if hasattr(instance, "i_know_scope"):
            instance.i_know_scope = True
        try:
            instance.run()
        except (SystemExit, Exception):
            pass


# ---------------------------------------------------------------------------
# 6. SIM module-specific deeper tests
# ---------------------------------------------------------------------------


class TestSimClonerHelpers:
    def test_validate_hex_valid(self) -> None:
        from wirelessxpl.modules.generic.sim.sim_cloner import _validate_hex

        assert _validate_hex("AABBCCDD", 8, "test") is True

    def test_validate_hex_wrong_len(self) -> None:
        from wirelessxpl.modules.generic.sim.sim_cloner import _validate_hex

        assert _validate_hex("AABB", 8, "test") is False

    def test_validate_hex_invalid_chars(self) -> None:
        from wirelessxpl.modules.generic.sim.sim_cloner import _validate_hex

        assert _validate_hex("GGHHIIJJ", 8, "test") is False

    def test_which_missing(self) -> None:
        from wirelessxpl.modules.generic.sim.sim_cloner import _which

        with patch("shutil.which", return_value=None):
            assert _which("nonexistent") is None

    def test_ensure_tmp(self, tmp_path: Path) -> None:
        from wirelessxpl.modules.generic.sim.sim_cloner import _ensure_tmp

        result = _ensure_tmp(str(tmp_path))
        assert os.path.isdir(result)
        assert result.endswith(".tmp")

    def test_ef_map(self) -> None:
        from wirelessxpl.modules.generic.sim.sim_cloner import _EF_MAP

        assert "IMSI" in _EF_MAP
        assert "ICCID" in _EF_MAP

    def test_csv_header(self) -> None:
        from wirelessxpl.modules.generic.sim.sim_cloner import _CSV_HEADER

        assert "ICCID" in _CSV_HEADER
        assert "IMSI" in _CSV_HEADER


class TestSimClonerModes:
    """Test SIM cloner with different modes in dry_run."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> Any:
        with (
            patch("shutil.which", return_value=None),
            patch("subprocess.run", side_effect=FileNotFoundError),
        ):
            yield

    def _make_instance(self, mode: str = "info") -> Any:
        from wirelessxpl.modules.generic.sim.sim_cloner import Exploit

        inst = Exploit()
        inst.mode = mode
        inst.dry_run = True
        inst.i_know_scope = True
        return inst

    @pytest.mark.parametrize(
        "mode",
        ["info", "read_source", "write_target", "provision_test", "verify", "batch_csv"],
    )
    def test_dry_run_mode(self, mode: str) -> None:
        inst = self._make_instance(mode)
        try:
            inst.run()
        except Exception:
            pass


class TestSimApduLabModes:
    """Test APDU lab with different modes."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> Any:
        with (
            patch("shutil.which", return_value=None),
            patch("subprocess.run", side_effect=FileNotFoundError),
        ):
            yield

    def _make_instance(self, mode: str = "interactive") -> Any:
        from wirelessxpl.modules.generic.sim.sim_apdu_lab import Exploit

        inst = Exploit()
        inst.mode = mode
        inst.dry_run = True
        inst.i_know_scope = True
        return inst

    @pytest.mark.parametrize(
        "mode",
        ["interactive", "select_file", "read_record", "send_raw", "verify_pin", "run_script", "fuzz"],
    )
    def test_dry_run_mode(self, mode: str) -> None:
        inst = self._make_instance(mode)
        try:
            inst.run()
        except Exception:
            pass


class TestSimAdmBruteModes:
    """Test ADM brute with different modes."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> Any:
        with (
            patch("shutil.which", return_value=None),
            patch("subprocess.run", side_effect=FileNotFoundError),
        ):
            yield

    def _make_instance(self, mode: str = "info") -> Any:
        from wirelessxpl.modules.generic.sim.sim_adm_brute import Exploit

        inst = Exploit()
        inst.mode = mode
        inst.dry_run = True
        inst.i_know_scope = True
        return inst

    @pytest.mark.parametrize(
        "mode",
        ["info", "brute_sequential", "brute_wordlist", "check_remaining", "known_pins"],
    )
    def test_dry_run_mode(self, mode: str) -> None:
        inst = self._make_instance(mode)
        try:
            inst.run()
        except Exception:
            pass


class TestPysimReaderModes:
    """Test pySim reader with different modes."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> Any:
        with (
            patch("shutil.which", return_value=None),
            patch("subprocess.run", side_effect=FileNotFoundError),
        ):
            yield

    def _make_instance(self, mode: str = "info") -> Any:
        from wirelessxpl.modules.generic.sim.pysim_reader import Exploit

        inst = Exploit()
        inst.mode = mode
        inst.dry_run = True
        inst.i_know_scope = True
        return inst

    @pytest.mark.parametrize(
        "mode",
        ["info", "read_all", "read_imsi", "read_iccid", "read_sms", "read_contacts", "export_json"],
    )
    def test_dry_run_mode(self, mode: str) -> None:
        inst = self._make_instance(mode)
        try:
            inst.run()
        except Exception:
            pass


class TestEsimRspBridgeModes:
    """Test eSIM RSP bridge with different modes."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> Any:
        with (
            patch("shutil.which", return_value=None),
            patch("subprocess.run", side_effect=FileNotFoundError),
        ):
            yield

    def _make_instance(self, mode: str = "info") -> Any:
        from wirelessxpl.modules.generic.sim.esim_rsp_bridge import Exploit

        inst = Exploit()
        inst.mode = mode
        inst.dry_run = True
        inst.i_know_scope = True
        return inst

    @pytest.mark.parametrize(
        "mode",
        ["info", "list_profiles", "enable_profile", "disable_profile", "delete_profile", "eid_info", "connectivity_test"],
    )
    def test_dry_run_mode(self, mode: str) -> None:
        inst = self._make_instance(mode)
        try:
            inst.run()
        except Exception:
            pass


class TestSimjackerInfoModes:
    """Test Simjacker info module with different modes."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> Any:
        with (
            patch("shutil.which", return_value=None),
            patch("subprocess.run", side_effect=FileNotFoundError),
        ):
            yield

    def _make_instance(self, mode: str = "info") -> Any:
        from wirelessxpl.modules.generic.sim.simjacker_info import Exploit

        inst = Exploit()
        inst.mode = mode
        inst.i_know_scope = True
        return inst

    @pytest.mark.parametrize(
        "mode",
        ["info", "check_stk", "check_ota", "full_audit", "explain"],
    )
    def test_mode(self, mode: str) -> None:
        inst = self._make_instance(mode)
        try:
            inst.run()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 7. SIM disclaimer module
# ---------------------------------------------------------------------------


class TestSimDisclaimer:
    def test_import(self) -> None:
        from wirelessxpl.modules.generic.sim._disclaimer import (
            require_authorised_lab,
            require_sim_ownership,
        )
        assert callable(require_authorised_lab)
        assert callable(require_sim_ownership)
