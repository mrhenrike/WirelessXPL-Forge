"""Unit tests for Phase 7: Integration modules (ML, GnuRadio, RemoteSensor, Zigbee)."""

import importlib
import os
import struct

import pytest

MODULES = {
    "ml_signal_classifier": "wirelessxpl.modules.generic.integration.ml_signal_classifier",
    "gnuradio_sdr_integration": "wirelessxpl.modules.generic.integration.gnuradio_sdr_integration",
    "remote_sensor_node": "wirelessxpl.modules.generic.integration.remote_sensor_node",
    "zigbee_ecosystem_expansion": "wirelessxpl.modules.generic.zigbee.zigbee_ecosystem_expansion",
}


def _load(name: str):
    mod = importlib.import_module(MODULES[name])
    return mod.Exploit


# ====================================================================
# ML Signal Classifier
# ====================================================================

class TestMLSignalClassifier:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.Exploit = _load("ml_signal_classifier")
        self.exp = self.Exploit()

    def test_instantiation(self):
        assert self.exp is not None

    def test_info_name(self):
        info = self.exp._Exploit__info__
        assert "ML" in info["name"]
        assert "Signal" in info["name"] or "Classifier" in info["name"]

    def test_info_description(self):
        info = self.exp._Exploit__info__
        assert "classify" in info["description"].lower() or "signal" in info["description"].lower()

    def test_info_authors(self):
        info = self.exp._Exploit__info__
        assert any("mrhenrike" in a for a in info["authors"])

    def test_info_references(self):
        info = self.exp._Exploit__info__
        assert len(info["references"]) >= 1

    def test_info_platform(self):
        info = self.exp._Exploit__info__
        assert info["platform"] == "linux"

    def test_info_targets(self):
        info = self.exp._Exploit__info__
        assert len(info["targets"]) >= 1

    def test_option_sdr_device(self):
        assert str(self.exp.sdr_device) == "rtlsdr"

    def test_option_center_freq(self):
        assert float(self.exp.center_freq) == pytest.approx(2.437e9)

    def test_option_sample_rate(self):
        assert float(self.exp.sample_rate) == pytest.approx(2.4e6)

    def test_option_fft_size(self):
        assert int(self.exp.fft_size) == 1024

    def test_option_model_path(self):
        assert str(self.exp.model_path) == ""

    def test_known_protocols(self):
        assert "wifi_24" in self.Exploit._KNOWN_PROTOCOLS
        assert "ble" in self.Exploit._KNOWN_PROTOCOLS
        assert "zigbee" in self.Exploit._KNOWN_PROTOCOLS
        assert "tetra" in self.Exploit._KNOWN_PROTOCOLS
        assert "lora" in self.Exploit._KNOWN_PROTOCOLS

    def test_default_features(self):
        assert "peak_freq_offset" in self.Exploit._DEFAULT_FEATURES
        assert "bandwidth_3db" in self.Exploit._DEFAULT_FEATURES
        assert "duty_cycle" in self.Exploit._DEFAULT_FEATURES

    def test_check_sdr_not_available(self):
        assert self.exp._check_sdr_available() is False

    def test_check_fissure_not_installed(self):
        self.exp.fissure_path = "/nonexistent/path"
        assert self.exp._check_fissure() is False

    def test_extract_features_empty(self):
        result = self.exp._extract_features(b"")
        assert result == {}

    def test_extract_features_too_short(self):
        result = self.exp._extract_features(b"\x00" * 10)
        assert result == {}

    def test_classify_signal_wifi_24(self):
        self.exp.center_freq = 2.437e9
        features = {"bandwidth_3db": 20e6, "duty_cycle": 0.5}
        protocol, confidence = self.exp._classify_signal(features)
        assert protocol == "wifi_24"
        assert confidence > 0

    def test_classify_signal_wifi_5(self):
        self.exp.center_freq = 5.5e9
        features = {"bandwidth_3db": 40e6}
        protocol, confidence = self.exp._classify_signal(features)
        assert protocol == "wifi_5"

    def test_classify_signal_ble(self):
        self.exp.center_freq = 2.44e9
        features = {"bandwidth_3db": 2e6}
        protocol, confidence = self.exp._classify_signal(features)
        assert protocol == "ble"

    def test_classify_signal_zigbee(self):
        self.exp.center_freq = 2.44e9
        features = {"bandwidth_3db": 800e3}
        protocol, confidence = self.exp._classify_signal(features)
        assert protocol == "zigbee"

    def test_classify_signal_lora_868(self):
        self.exp.center_freq = 868e6
        features = {"bandwidth_3db": 200e3}
        protocol, confidence = self.exp._classify_signal(features)
        assert protocol == "lora"

    def test_classify_signal_zwave(self):
        self.exp.center_freq = 868e6
        features = {"bandwidth_3db": 50e3}
        protocol, confidence = self.exp._classify_signal(features)
        assert protocol == "zwave"

    def test_classify_signal_dect(self):
        self.exp.center_freq = 1890e6
        features = {}
        protocol, confidence = self.exp._classify_signal(features)
        assert protocol == "dect"

    def test_classify_signal_tetra(self):
        self.exp.center_freq = 390e6
        features = {}
        protocol, confidence = self.exp._classify_signal(features)
        assert protocol == "tetra"

    def test_classify_signal_unknown(self):
        self.exp.center_freq = 50e6
        features = {}
        protocol, confidence = self.exp._classify_signal(features)
        assert protocol == "unknown"
        assert confidence <= 0.5

    def test_classify_no_model(self):
        self.exp.model_path = ""
        self.exp.center_freq = 2.437e9
        features = {"bandwidth_3db": 20e6}
        protocol, confidence = self.exp._classify_signal(features)
        assert isinstance(protocol, str)
        assert isinstance(confidence, float)

    def test_query_fissure_not_installed(self):
        self.exp.fissure_path = "/nonexistent"
        result = self.exp._query_fissure("wifi")
        assert result == []

    def test_check_returns_bool(self):
        result = self.exp.check()
        assert isinstance(result, bool)

    def test_has_run_method(self):
        assert hasattr(self.exp, "run")
        assert callable(self.exp.run)

    def test_has_exploit_method(self):
        assert hasattr(self.exp, "_exploit")
        assert callable(self.exp._exploit)


# ====================================================================
# GnuRadio SDR Integration
# ====================================================================

class TestGnuRadioSDRIntegration:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.Exploit = _load("gnuradio_sdr_integration")
        self.exp = self.Exploit()

    def test_instantiation(self):
        assert self.exp is not None

    def test_info_name(self):
        info = self.exp._Exploit__info__
        assert "GnuRadio" in info["name"]

    def test_info_description(self):
        info = self.exp._Exploit__info__
        assert "gnuradio" in info["description"].lower() or "sdr" in info["description"].lower()

    def test_info_authors(self):
        info = self.exp._Exploit__info__
        assert any("mrhenrike" in a for a in info["authors"])

    def test_info_references(self):
        info = self.exp._Exploit__info__
        assert any("gnuradio" in r for r in info["references"])

    def test_info_platform(self):
        info = self.exp._Exploit__info__
        assert info["platform"] == "linux"

    def test_option_flowgraph(self):
        assert str(self.exp.flowgraph) == ""

    def test_option_sdr_device(self):
        assert str(self.exp.sdr_device) == "rtlsdr"

    def test_option_mode(self):
        assert str(self.exp.mode) == "capture"

    def test_option_center_freq(self):
        assert float(self.exp.center_freq) == pytest.approx(2.437e9)

    def test_option_sample_rate(self):
        assert float(self.exp.sample_rate) == pytest.approx(2.4e6)

    def test_builtin_flowgraphs(self):
        assert "capture" in self.Exploit._BUILTIN_FLOWGRAPHS
        assert "jam" in self.Exploit._BUILTIN_FLOWGRAPHS
        assert "replay" in self.Exploit._BUILTIN_FLOWGRAPHS
        assert "inject" in self.Exploit._BUILTIN_FLOWGRAPHS

    def test_sdr_sources(self):
        assert "rtlsdr" in self.Exploit._SDR_SOURCES
        assert "hackrf" in self.Exploit._SDR_SOURCES
        assert "usrp" in self.Exploit._SDR_SOURCES

    def test_check_gnuradio_not_installed(self):
        assert self.exp._check_gnuradio() is False

    def test_get_gnuradio_version_not_installed(self):
        assert self.exp._get_gnuradio_version() == "unknown"

    def test_generate_capture_flowgraph(self):
        path = self.exp._generate_capture_flowgraph()
        assert os.path.isfile(path)
        with open(path) as f:
            content = f.read()
        assert "RFCapture" in content
        assert "set_center_freq" in content
        os.unlink(path)

    def test_generate_jammer_flowgraph(self):
        path = self.exp._generate_jammer_flowgraph()
        assert os.path.isfile(path)
        with open(path) as f:
            content = f.read()
        assert "RFJammer" in content
        assert "noise_source" in content
        os.unlink(path)

    def test_run_flowgraph_missing_script(self):
        success, output = self.exp._run_flowgraph("/nonexistent/script.py")
        assert success is False

    def test_check_returns_bool(self):
        assert isinstance(self.exp.check(), bool)

    def test_has_run_method(self):
        assert callable(self.exp.run)

    def test_has_exploit_method(self):
        assert callable(self.exp._exploit)

    def test_compile_grc_nonexistent(self):
        result = self.exp._compile_grc("/nonexistent/file.grc")
        assert result == ""


# ====================================================================
# Remote Sensor Node
# ====================================================================

class TestRemoteSensorNode:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.Exploit = _load("remote_sensor_node")
        self.exp = self.Exploit()

    def test_instantiation(self):
        assert self.exp is not None

    def test_info_name(self):
        info = self.exp._Exploit__info__
        assert "Remote" in info["name"] or "Sensor" in info["name"]

    def test_info_description(self):
        info = self.exp._Exploit__info__
        assert "sensor" in info["description"].lower() or "distributed" in info["description"].lower()

    def test_info_authors(self):
        info = self.exp._Exploit__info__
        assert any("mrhenrike" in a for a in info["authors"])

    def test_info_platform(self):
        info = self.exp._Exploit__info__
        assert info["platform"] == "linux"

    def test_option_port(self):
        assert int(self.exp.port) == 9090

    def test_option_nodes(self):
        assert str(self.exp.nodes) == ""

    def test_option_operation(self):
        assert str(self.exp.operation) == "monitor"

    def test_option_output_dir(self):
        assert str(self.exp.output_dir) == "/tmp/sensor_data"

    def test_proto_version(self):
        assert self.Exploit._PROTO_VERSION == 1

    def test_command_constants(self):
        assert self.Exploit._CMD_PING == 0x01
        assert self.Exploit._CMD_CONFIGURE == 0x02
        assert self.Exploit._CMD_START_CAPTURE == 0x03
        assert self.Exploit._CMD_GET_DATA == 0x06

    def test_build_command_ping(self):
        cmd = self.exp._build_command(self.Exploit._CMD_PING)
        assert len(cmd) == 4
        ver, cmd_type, payload_len = struct.unpack("<BBH", cmd)
        assert ver == 1
        assert cmd_type == 0x01
        assert payload_len == 0

    def test_build_command_with_payload(self):
        payload = b"\x01\x02\x03"
        cmd = self.exp._build_command(self.Exploit._CMD_CONFIGURE, payload)
        assert len(cmd) == 7
        ver, cmd_type, payload_len = struct.unpack("<BBH", cmd[:4])
        assert payload_len == 3
        assert cmd[4:] == payload

    def test_parse_response_ok(self):
        data = struct.pack("<BBH", 1, 0x00, 4) + b"\x01\x02\x03\x04"
        status, payload = self.exp._parse_response(data)
        assert status == self.Exploit._RSP_OK
        assert payload == b"\x01\x02\x03\x04"

    def test_parse_response_error(self):
        data = struct.pack("<BBH", 1, 0xFF, 0)
        status, payload = self.exp._parse_response(data)
        assert status == self.Exploit._RSP_ERROR
        assert payload == b""

    def test_parse_response_too_short(self):
        status, payload = self.exp._parse_response(b"\x01\x02")
        assert status == self.Exploit._RSP_ERROR

    def test_get_node_list_empty(self):
        self.exp.nodes = ""
        assert self.exp._get_node_list() == []

    def test_get_node_list_single(self):
        self.exp.nodes = "192.168.1.10:9090"
        result = self.exp._get_node_list()
        assert result == ["192.168.1.10:9090"]

    def test_get_node_list_multiple(self):
        self.exp.nodes = "192.168.1.10:9090,192.168.1.11:9090,192.168.1.12:9090"
        result = self.exp._get_node_list()
        assert len(result) == 3

    def test_ping_node_unreachable(self):
        result = self.exp._ping_node("192.0.2.1:9999")
        assert result is False

    def test_send_to_node_invalid_address(self):
        status, _ = self.exp._send_to_node("invalid", b"\x00")
        assert status == self.Exploit._RSP_ERROR

    def test_send_to_node_unreachable(self):
        self.exp.timeout = 1.0
        status, _ = self.exp._send_to_node("192.0.2.1:9999", b"\x00")
        assert status == self.Exploit._RSP_ERROR

    def test_triangulate_insufficient_nodes(self):
        result = self.exp._triangulate(["node1:9090", "node2:9090"])
        assert "error" in result
        assert "3 nodes" in result["error"]

    def test_check_no_nodes(self):
        self.exp.nodes = ""
        assert self.exp.check() is False

    def test_has_run_method(self):
        assert callable(self.exp.run)

    def test_has_exploit_method(self):
        assert callable(self.exp._exploit)


# ====================================================================
# Zigbee Ecosystem Expansion
# ====================================================================

class TestZigbeeEcosystemExpansion:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.Exploit = _load("zigbee_ecosystem_expansion")
        self.exp = self.Exploit()

    def test_instantiation(self):
        assert self.exp is not None

    def test_info_name(self):
        info = self.exp._Exploit__info__
        assert "Zigbee" in info["name"]

    def test_info_description(self):
        info = self.exp._Exploit__info__
        assert "zigbee" in info["description"].lower()
        assert "802.15.4" in info["description"]

    def test_info_authors(self):
        info = self.exp._Exploit__info__
        assert any("mrhenrike" in a for a in info["authors"])

    def test_info_references(self):
        info = self.exp._Exploit__info__
        assert any("killerbee" in r for r in info["references"])

    def test_info_platform(self):
        info = self.exp._Exploit__info__
        assert info["platform"] == "linux"

    def test_info_privileged(self):
        info = self.exp._Exploit__info__
        assert info["privileged"] is True

    def test_info_targets(self):
        info = self.exp._Exploit__info__
        assert len(info["targets"]) >= 2

    def test_option_interface(self):
        assert str(self.exp.interface) == "/dev/ttyACM0"

    def test_option_adapter_type(self):
        assert str(self.exp.adapter_type) == "cc2531"

    def test_option_channel(self):
        assert int(self.exp.channel) == 11

    def test_option_mode(self):
        assert str(self.exp.mode) == "discover"

    def test_option_pan_id(self):
        assert int(self.exp.pan_id) == 0

    def test_option_scan_duration(self):
        assert float(self.exp.scan_duration) == 5.0

    def test_zha_default_key(self):
        assert len(self.Exploit._ZHA_DEFAULT_TC_LINK_KEY) == 16
        assert bytes.fromhex(
            "5A6967426565416C6C69616E63653039"
        ) == self.Exploit._ZHA_DEFAULT_TC_LINK_KEY

    def test_zll_master_key(self):
        assert len(self.Exploit._ZLL_MASTER_KEY) == 16

    def test_frame_type_constants(self):
        assert self.Exploit._FRAME_TYPE_BEACON == 0x00
        assert self.Exploit._FRAME_TYPE_DATA == 0x01
        assert self.Exploit._FRAME_TYPE_CMD == 0x03

    def test_nwk_cmd_constants(self):
        assert self.Exploit._NWK_CMD_LEAVE == 0x04
        assert self.Exploit._NWK_CMD_REJOIN_REQ == 0x06

    def test_build_beacon_request(self):
        frame = self.exp._build_beacon_request()
        assert len(frame) >= 7
        fc = struct.unpack("<H", frame[:2])[0]
        frame_type = fc & 0x07
        assert frame_type == 0x03  # MAC command

    def test_build_beacon_request_broadcast_dst(self):
        frame = self.exp._build_beacon_request()
        dst_pan = struct.unpack("<H", frame[3:5])[0]
        dst_addr = struct.unpack("<H", frame[5:7])[0]
        assert dst_pan == 0xFFFF
        assert dst_addr == 0xFFFF

    def test_build_data_request(self):
        frame = self.exp._build_data_request(0x1234, 0x0001, 0x0002)
        assert len(frame) >= 9
        pan_id = struct.unpack("<H", frame[3:5])[0]
        assert pan_id == 0x1234

    def test_build_touchlink_scan(self):
        frame = self.exp._build_touchlink_scan()
        assert len(frame) >= 10
        # Verify broadcast PAN
        dst_pan = struct.unpack("<H", frame[3:5])[0]
        assert dst_pan == 0xFFFF

    def test_open_adapter_no_device(self):
        self.exp.interface = "/dev/nonexistent_device"
        self.exp.adapter_type = "cc2531"
        result = self.exp._open_adapter()
        assert result is None

    def test_send_frame_none_adapter(self):
        result = self.exp._send_frame(None, b"\x00")
        assert result is False

    def test_receive_frames_none_adapter(self):
        # Should handle gracefully
        class FakeAdapter:
            pass
        result = self.exp._receive_frames(FakeAdapter(), 0.01)
        assert result == []

    def test_replay_missing_pcap(self):
        self.exp.replay_pcap = "/nonexistent/file.pcap"
        # _replay_frames requires an adapter, but should handle missing file
        class FakeAdapter:
            def write(self, data): return len(data)
            def close(self): pass
        count = self.exp._replay_frames(FakeAdapter())
        assert count == 0

    def test_inject_empty_payload(self):
        self.exp.inject_payload = ""
        class FakeAdapter:
            def write(self, data): return len(data)
        result = self.exp._inject_frame_payload(FakeAdapter())
        assert result is False

    def test_inject_invalid_hex(self):
        self.exp.inject_payload = "ZZZZ"
        class FakeAdapter:
            def write(self, data): return len(data)
        result = self.exp._inject_frame_payload(FakeAdapter())
        assert result is False

    def test_check_no_adapter(self):
        self.exp.interface = "/dev/nonexistent"
        assert self.exp.check() is False

    def test_has_run_method(self):
        assert callable(self.exp.run)

    def test_has_exploit_method(self):
        assert callable(self.exp._exploit)

    def test_discover_networks_returns_list(self):
        class FakeAdapter:
            def write(self, data): pass
            def read(self, size): raise TimeoutError
        result = self.exp._discover_networks(FakeAdapter())
        assert isinstance(result, list)

    def test_sniff_keys_returns_list(self):
        class FakeAdapter:
            def read(self, size): raise TimeoutError
        self.exp.timeout = 0.01
        result = self.exp._sniff_keys(FakeAdapter())
        assert isinstance(result, list)
