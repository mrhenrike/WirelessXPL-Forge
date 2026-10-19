"""Tests for wirelessxpl.core.sdr."""

from __future__ import annotations

from pathlib import Path

import pytest

from wirelessxpl.core.sdr import (
    CapturedSignal,
    ModulationType,
    SDRBackend,
    SDRConfig,
    SDRDevice,
    SignalAnalyzer,
)


class TestSDRConfig:
    def test_defaults(self) -> None:
        cfg = SDRConfig()
        assert cfg.backend == SDRBackend.HACKRF
        assert cfg.center_freq == 433.92e6
        assert cfg.sample_rate == 2e6
        assert cfg.gain == 40.0


class TestCapturedSignal:
    def test_empty(self) -> None:
        sig = CapturedSignal()
        assert sig.sample_count == 0

    def test_with_samples(self) -> None:
        sig = CapturedSignal(samples=b"\x00" * 80)
        assert sig.sample_count == 10  # 80 / 8


class TestSDRDevice:
    def test_init(self) -> None:
        dev = SDRDevice()
        assert dev.config.backend == SDRBackend.HACKRF
        assert dev.connected is False

    def test_file_backend_connect(self) -> None:
        cfg = SDRConfig(backend=SDRBackend.FILE)
        dev = SDRDevice(cfg)
        assert dev.connect() is True
        assert dev.connected is True
        dev.disconnect()
        assert dev.connected is False

    def test_capture_not_connected(self) -> None:
        dev = SDRDevice()
        with pytest.raises(RuntimeError, match="not connected"):
            dev.capture()

    def test_capture_connected(self) -> None:
        cfg = SDRConfig(backend=SDRBackend.FILE)
        dev = SDRDevice(cfg)
        dev.connect()
        sig = dev.capture(duration=2.0)
        assert sig.duration == 2.0
        assert sig.frequency == 433.92e6

    def test_transmit_not_connected(self) -> None:
        dev = SDRDevice()
        with pytest.raises(RuntimeError, match="not connected"):
            dev.transmit(CapturedSignal())

    def test_transmit_rtlsdr_no_tx(self) -> None:
        cfg = SDRConfig(backend=SDRBackend.RTLSDR)
        dev = SDRDevice(cfg)
        dev._connected = True
        with pytest.raises(RuntimeError, match="does not support TX"):
            dev.transmit(CapturedSignal())


class TestSignalAnalyzer:
    def test_estimate_empty(self) -> None:
        sig = CapturedSignal()
        assert SignalAnalyzer.estimate_modulation(sig) == ModulationType.OOK

    def test_extract_bitstream_empty(self) -> None:
        sig = CapturedSignal()
        assert SignalAnalyzer.extract_bitstream(sig) == []

    def test_save_and_load(self, tmp_path: Path) -> None:
        sig = CapturedSignal(
            samples=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            frequency=868e6,
            sample_rate=1e6,
        )
        path = tmp_path / "capture.iq"
        SignalAnalyzer.save_to_file(sig, path)
        loaded = SignalAnalyzer.load_from_file(path, freq=868e6, sample_rate=1e6)
        assert loaded.samples == sig.samples
        assert loaded.frequency == 868e6
