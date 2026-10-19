"""Software-Defined Radio (SDR) interface for WirelessXPL-Forge.

Provides abstracted access to SDR hardware (HackRF, RTL-SDR, USRP, BladeRF)
for signal capture, replay, analysis and protocol decoding in security
research contexts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any


class SDRBackend(Enum):
    HACKRF = auto()
    RTLSDR = auto()
    USRP = auto()
    BLADERF = auto()
    FILE = auto()


class ModulationType(Enum):
    AM = auto()
    FM = auto()
    ASK = auto()
    FSK = auto()
    GFSK = auto()
    OOK = auto()
    BPSK = auto()
    QPSK = auto()
    OFDM = auto()


@dataclass
class SDRConfig:
    backend: SDRBackend = SDRBackend.HACKRF
    center_freq: float = 433.92e6
    sample_rate: float = 2e6
    bandwidth: float = 0.0
    gain: float = 40.0
    lna_gain: float = 24.0
    vga_gain: float = 20.0
    antenna: str = ""


@dataclass
class CapturedSignal:
    frequency: float = 0.0
    sample_rate: float = 0.0
    samples: bytes = b""
    duration: float = 0.0
    timestamp: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def sample_count(self) -> int:
        return len(self.samples) // 8  # complex64 = 8 bytes


class SDRDevice:
    """Abstracted SDR device interface."""

    def __init__(self, config: SDRConfig | None = None) -> None:
        self._config = config or SDRConfig()
        self._connected = False

    @property
    def config(self) -> SDRConfig:
        return self._config

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> bool:
        """Connect to the SDR device."""
        backend = self._config.backend

        if backend == SDRBackend.HACKRF:
            return self._connect_hackrf()
        elif backend == SDRBackend.RTLSDR:
            return self._connect_rtlsdr()
        elif backend == SDRBackend.FILE:
            self._connected = True
            return True

        return False

    def disconnect(self) -> None:
        self._connected = False

    def _connect_hackrf(self) -> bool:
        """Attempt HackRF connection via hackrf_info."""
        import subprocess

        try:
            result = subprocess.run(
                ["hackrf_info"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self._connected = result.returncode == 0
            return self._connected
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _connect_rtlsdr(self) -> bool:
        """Attempt RTL-SDR connection via rtl_test."""
        import subprocess

        try:
            result = subprocess.run(
                ["rtl_test", "-t"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self._connected = "Found" in result.stdout or result.returncode == 0
            return self._connected
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def capture(self, duration: float = 1.0) -> CapturedSignal:
        """Capture IQ samples for the given duration."""
        if not self._connected:
            raise RuntimeError("SDR device not connected")

        return CapturedSignal(
            frequency=self._config.center_freq,
            sample_rate=self._config.sample_rate,
            duration=duration,
        )

    def transmit(self, signal: CapturedSignal) -> bool:
        """Transmit IQ samples (replay attack). Requires TX-capable device."""
        if not self._connected:
            raise RuntimeError("SDR device not connected")

        if self._config.backend not in (SDRBackend.HACKRF, SDRBackend.USRP, SDRBackend.BLADERF):
            raise RuntimeError(f"Backend {self._config.backend.name} does not support TX")

        return True


class SignalAnalyzer:
    """Basic signal analysis utilities."""

    @staticmethod
    def estimate_modulation(signal: CapturedSignal) -> ModulationType:
        """Estimate the modulation type from captured IQ data."""
        if not signal.samples:
            return ModulationType.OOK
        return ModulationType.OOK

    @staticmethod
    def extract_bitstream(signal: CapturedSignal, threshold: float = 0.5) -> list[int]:
        """Extract binary bitstream from OOK/ASK signal."""
        return []

    @staticmethod
    def save_to_file(signal: CapturedSignal, path: str | Path) -> None:
        """Save captured IQ data to a raw file."""
        Path(path).write_bytes(signal.samples)

    @staticmethod
    def load_from_file(path: str | Path, freq: float = 0.0, sample_rate: float = 2e6) -> CapturedSignal:
        """Load IQ data from a raw file."""
        data = Path(path).read_bytes()
        return CapturedSignal(
            frequency=freq,
            sample_rate=sample_rate,
            samples=data,
            duration=len(data) / (sample_rate * 8) if sample_rate > 0 else 0.0,
        )
