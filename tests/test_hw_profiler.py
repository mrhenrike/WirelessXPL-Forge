"""Tests for wirelessxpl.core.hw_profiler — GPUDevice, HWProfile, HWProfiler."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wirelessxpl.core.hw_profiler import GPUDevice, HWProfile, HWProfiler

# ---------------------------------------------------------------------------
# GPUDevice
# ---------------------------------------------------------------------------

def test_gpu_device_summary_with_vram() -> None:
    gpu = GPUDevice(name="RTX 4090", vendor="nvidia", vram_mb=24576,
                    driver="535.183.01", compute_cap="8.9", backend="cuda")
    s = gpu.summary()
    assert "RTX 4090" in s
    assert "cuda" in s
    assert "24576 MB" in s
    assert "8.9" in s


def test_gpu_device_summary_no_vram() -> None:
    gpu = GPUDevice(name="AMD GPU", vendor="amd", backend="rocm")
    s = gpu.summary()
    assert "unknown VRAM" in s
    assert "rocm" in s


def test_gpu_device_defaults() -> None:
    gpu = GPUDevice(name="Test", vendor="test")
    assert gpu.vram_mb == 0
    assert gpu.driver == ""
    assert gpu.compute_cap == ""
    assert gpu.backend == ""
    assert gpu.index == 0


# ---------------------------------------------------------------------------
# HWProfile
# ---------------------------------------------------------------------------

def test_hwprofile_defaults() -> None:
    p = HWProfile()
    assert p.cpu_model == "Unknown"
    assert p.cpu_cores == 1
    assert p.ram_total_mb == 0
    assert p.gpus == []
    assert p.best_backend == "cpu"
    assert p.compute_mode == "auto"


def test_hwprofile_has_gpu_false() -> None:
    p = HWProfile()
    assert p.has_gpu() is False


def test_hwprofile_has_gpu_true() -> None:
    p = HWProfile(gpus=[GPUDevice("Test", "nvidia", vram_mb=8192)])
    assert p.has_gpu() is True


def test_hwprofile_gpu_summary_no_gpu() -> None:
    p = HWProfile()
    assert p.gpu_summary() == "No GPU detected"


def test_hwprofile_gpu_summary_with_gpus() -> None:
    p = HWProfile(gpus=[
        GPUDevice("RTX 4090", "nvidia", vram_mb=24576),
        GPUDevice("AMD RX 7900", "amd", vram_mb=20480),
    ])
    s = p.gpu_summary()
    assert "RTX 4090" in s
    assert "24576MB" in s
    assert "AMD RX 7900" in s


def test_hwprofile_one_liner() -> None:
    p = HWProfile(cpu_model="i9-14900K", cpu_threads=32,
                  ram_total_mb=65536, compute_mode="auto")
    s = p.one_liner()
    assert "i9-14900K" in s
    assert "32T" in s
    assert "65536MB RAM" in s
    assert "auto->cpu" in s


def test_hwprofile_one_liner_with_gpu() -> None:
    p = HWProfile(cpu_model="i9", cpu_threads=8,
                  gpus=[GPUDevice("RTX", "nvidia", vram_mb=8192)],
                  compute_mode="auto")
    s = p.one_liner()
    assert "auto->hybrid" in s


def test_hwprofile_one_liner_explicit_mode() -> None:
    p = HWProfile(cpu_model="ARM", cpu_threads=4, compute_mode="cuda")
    s = p.one_liner()
    assert "compute: cuda" in s


# ---------------------------------------------------------------------------
# HWProfiler._select_backend
# ---------------------------------------------------------------------------

def test_select_backend_cuda_first() -> None:
    p = HWProfile(gpus=[
        GPUDevice("AMD", "amd", backend="rocm"),
        GPUDevice("NV", "nvidia", backend="cuda"),
    ])
    HWProfiler._select_backend(p)
    assert p.best_backend == "cuda"


def test_select_backend_rocm() -> None:
    p = HWProfile(gpus=[GPUDevice("AMD", "amd", backend="rocm")])
    HWProfiler._select_backend(p)
    assert p.best_backend == "rocm"


def test_select_backend_opencl() -> None:
    p = HWProfile(gpus=[GPUDevice("Intel", "intel", backend="opencl")])
    HWProfiler._select_backend(p)
    assert p.best_backend == "opencl"


def test_select_backend_cpu_fallback() -> None:
    p = HWProfile(gpus=[])
    HWProfiler._select_backend(p)
    assert p.best_backend == "cpu"


# ---------------------------------------------------------------------------
# HWProfiler.detect (mocked)
# ---------------------------------------------------------------------------

def test_detect_returns_profile() -> None:
    with mock.patch.object(HWProfiler, "_detect_cpu"), \
         mock.patch.object(HWProfiler, "_detect_ram"), \
         mock.patch.object(HWProfiler, "_detect_gpus"), \
         mock.patch.object(HWProfiler, "_select_backend"):
        p = HWProfiler.detect()
        assert isinstance(p, HWProfile)
        assert p.compute_mode == "auto"


def test_detect_custom_compute_mode() -> None:
    with mock.patch.object(HWProfiler, "_detect_cpu"), \
         mock.patch.object(HWProfiler, "_detect_ram"), \
         mock.patch.object(HWProfiler, "_detect_gpus"), \
         mock.patch.object(HWProfiler, "_select_backend"):
        p = HWProfiler.detect(compute_mode="gpu-only")
        assert p.compute_mode == "gpu-only"
