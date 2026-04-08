#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""System Hardware Profiler — CPU, RAM, and GPU discovery for WirelessXPL-Forge.

Detects available compute resources on the host and provides a unified
``HWProfile`` for backend selection, module scheduling, and user reporting.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class GPUDevice:
    """Single GPU device detected on the host."""

    name: str
    vendor: str
    vram_mb: int = 0
    driver: str = ""
    compute_cap: str = ""
    backend: str = ""
    index: int = 0

    def summary(self) -> str:
        """One-line summary."""
        vram = "{} MB".format(self.vram_mb) if self.vram_mb else "unknown VRAM"
        cc = " ({})".format(self.compute_cap) if self.compute_cap else ""
        return "{} [{}] {} {}{}".format(self.name, self.backend, vram, self.driver, cc)


@dataclass
class HWProfile:
    """Aggregated hardware profile of the host machine."""

    cpu_model: str = "Unknown"
    cpu_arch: str = ""
    cpu_cores: int = 1
    cpu_threads: int = 1
    cpu_freq_mhz: int = 0
    ram_total_mb: int = 0
    ram_available_mb: int = 0
    gpus: List[GPUDevice] = field(default_factory=list)
    best_backend: str = "cpu"
    compute_mode: str = "auto"

    def has_gpu(self) -> bool:
        """True if at least one GPU was detected."""
        return len(self.gpus) > 0

    def gpu_summary(self) -> str:
        """Compact GPU summary."""
        if not self.gpus:
            return "No GPU detected"
        parts = []
        for g in self.gpus:
            vram = " {}MB".format(g.vram_mb) if g.vram_mb else ""
            parts.append("{}{}".format(g.name, vram))
        return " | ".join(parts)

    def one_liner(self) -> str:
        """Single-line system summary for startup display."""
        cpu = "{} ({}T)".format(self.cpu_model, self.cpu_threads)
        ram = "{}MB RAM".format(self.ram_total_mb) if self.ram_total_mb else "? RAM"
        gpu = self.gpu_summary()
        mode = self.compute_mode
        if mode == "auto":
            mode = "auto->{}".format("hybrid" if self.has_gpu() else "cpu")
        return "{} | {} | {} | compute: {}".format(cpu, ram, gpu, mode)


class HWProfiler:
    """Discovers CPU, RAM, and GPU hardware."""

    @staticmethod
    def detect(compute_mode: str = "auto") -> HWProfile:
        """Run full hardware detection and return an ``HWProfile``."""
        profile = HWProfile(compute_mode=compute_mode)
        HWProfiler._detect_cpu(profile)
        HWProfiler._detect_ram(profile)
        HWProfiler._detect_gpus(profile)
        HWProfiler._select_backend(profile)
        return profile

    @staticmethod
    def _detect_cpu(profile: HWProfile) -> None:
        """Detect CPU info."""
        profile.cpu_arch = platform.machine()
        profile.cpu_cores = os.cpu_count() or 1
        profile.cpu_threads = profile.cpu_cores

        try:
            if platform.system() == "Linux":
                out = subprocess.check_output(
                    ["lscpu"], text=True, timeout=5, stderr=subprocess.DEVNULL,
                )
                for line in out.splitlines():
                    if line.startswith("Model name:"):
                        profile.cpu_model = line.split(":", 1)[1].strip()
                    elif line.startswith("CPU(s):"):
                        profile.cpu_threads = int(line.split(":", 1)[1].strip())
                    elif line.startswith("Core(s) per socket:"):
                        cores_per = int(line.split(":", 1)[1].strip())
                    elif "CPU max MHz" in line or "CPU MHz" in line:
                        try:
                            profile.cpu_freq_mhz = int(float(line.split(":", 1)[1].strip()))
                        except ValueError:
                            pass
            elif platform.system() == "Windows":
                out = subprocess.check_output(
                    ["wmic", "cpu", "get", "Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed",
                     "/format:csv"],
                    text=True, timeout=5, stderr=subprocess.DEVNULL,
                )
                for line in out.strip().splitlines()[1:]:
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 5:
                        profile.cpu_freq_mhz = int(parts[1]) if parts[1].isdigit() else 0
                        profile.cpu_model = parts[2]
                        profile.cpu_cores = int(parts[3]) if parts[3].isdigit() else 1
                        profile.cpu_threads = int(parts[4]) if parts[4].isdigit() else 1
        except Exception as exc:
            logger.debug("CPU detection partial: %s", exc)
            profile.cpu_model = platform.processor() or "Unknown"

    @staticmethod
    def _detect_ram(profile: HWProfile) -> None:
        """Detect RAM info."""
        try:
            if platform.system() == "Linux":
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            profile.ram_total_mb = int(line.split()[1]) // 1024
                        elif line.startswith("MemAvailable:"):
                            profile.ram_available_mb = int(line.split()[1]) // 1024
            elif platform.system() == "Windows":
                out = subprocess.check_output(
                    ["wmic", "OS", "get", "TotalVisibleMemorySize,FreePhysicalMemory", "/format:csv"],
                    text=True, timeout=5, stderr=subprocess.DEVNULL,
                )
                for line in out.strip().splitlines()[1:]:
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 3:
                        profile.ram_available_mb = int(parts[1]) // 1024 if parts[1].isdigit() else 0
                        profile.ram_total_mb = int(parts[2]) // 1024 if parts[2].isdigit() else 0
        except Exception as exc:
            logger.debug("RAM detection failed: %s", exc)

    @staticmethod
    def _detect_gpus(profile: HWProfile) -> None:
        """Detect GPUs via nvidia-smi, rocm-smi, and PyTorch fallback."""
        HWProfiler._detect_nvidia(profile)
        HWProfiler._detect_amd(profile)
        HWProfiler._detect_opencl(profile)
        if not profile.gpus:
            HWProfiler._detect_pytorch_fallback(profile)

    @staticmethod
    def _detect_nvidia(profile: HWProfile) -> None:
        """Detect NVIDIA GPUs via nvidia-smi."""
        if not shutil.which("nvidia-smi"):
            return
        try:
            out = subprocess.check_output(
                ["nvidia-smi", "--query-gpu=index,name,memory.total,driver_version,compute_cap",
                 "--format=csv,noheader,nounits"],
                text=True, timeout=10, stderr=subprocess.DEVNULL,
            )
            for line in out.strip().splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 5:
                    profile.gpus.append(GPUDevice(
                        name=parts[1],
                        vendor="nvidia",
                        vram_mb=int(parts[2]) if parts[2].isdigit() else 0,
                        driver=parts[3],
                        compute_cap=parts[4],
                        backend="cuda",
                        index=int(parts[0]) if parts[0].isdigit() else 0,
                    ))
        except Exception as exc:
            logger.debug("nvidia-smi detection failed: %s", exc)

    @staticmethod
    def _detect_amd(profile: HWProfile) -> None:
        """Detect AMD GPUs via rocm-smi."""
        if not shutil.which("rocm-smi"):
            return
        try:
            out = subprocess.check_output(
                ["rocm-smi", "--showproductname", "--csv"],
                text=True, timeout=10, stderr=subprocess.DEVNULL,
            )
            for i, line in enumerate(out.strip().splitlines()[1:]):
                parts = [p.strip() for p in line.split(",")]
                if parts:
                    profile.gpus.append(GPUDevice(
                        name=parts[0] if parts[0] else "AMD GPU",
                        vendor="amd",
                        backend="rocm",
                        index=i,
                    ))
            vram_out = subprocess.check_output(
                ["rocm-smi", "--showmeminfo", "vram", "--csv"],
                text=True, timeout=10, stderr=subprocess.DEVNULL,
            )
            for line in vram_out.strip().splitlines()[1:]:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 2:
                    idx = int(parts[0]) if parts[0].isdigit() else 0
                    for g in profile.gpus:
                        if g.index == idx and g.vendor == "amd":
                            g.vram_mb = int(parts[1]) // (1024 * 1024) if parts[1].isdigit() else 0
        except Exception as exc:
            logger.debug("rocm-smi detection failed: %s", exc)

    @staticmethod
    def _detect_opencl(profile: HWProfile) -> None:
        """Detect GPUs via PyOpenCL."""
        try:
            import pyopencl as cl
            for plat in cl.get_platforms():
                for dev in plat.get_devices(device_type=cl.device_type.GPU):
                    already = any(
                        g.name == dev.name and g.vendor in ("nvidia", "amd")
                        for g in profile.gpus
                    )
                    if not already:
                        profile.gpus.append(GPUDevice(
                            name=dev.name.strip(),
                            vendor="intel" if "intel" in dev.vendor.lower() else "other",
                            vram_mb=dev.global_mem_size // (1024 * 1024),
                            backend="opencl",
                            index=len(profile.gpus),
                        ))
        except ImportError:
            pass
        except Exception as exc:
            logger.debug("OpenCL detection failed: %s", exc)

    @staticmethod
    def _detect_pytorch_fallback(profile: HWProfile) -> None:
        """Fallback GPU detection via PyTorch."""
        try:
            import torch
            if torch.cuda.is_available():
                for i in range(torch.cuda.device_count()):
                    props = torch.cuda.get_device_properties(i)
                    vendor = "amd" if hasattr(torch.version, "hip") and torch.version.hip else "nvidia"
                    profile.gpus.append(GPUDevice(
                        name=props.name,
                        vendor=vendor,
                        vram_mb=props.total_mem // (1024 * 1024),
                        backend="rocm" if vendor == "amd" else "cuda",
                        index=i,
                    ))
        except ImportError:
            pass
        except Exception as exc:
            logger.debug("PyTorch GPU fallback failed: %s", exc)

    @staticmethod
    def _select_backend(profile: HWProfile) -> None:
        """Set best_backend based on detected GPUs."""
        for g in profile.gpus:
            if g.backend == "cuda":
                profile.best_backend = "cuda"
                return
        for g in profile.gpus:
            if g.backend == "rocm":
                profile.best_backend = "rocm"
                return
        for g in profile.gpus:
            if g.backend == "opencl":
                profile.best_backend = "opencl"
                return
        profile.best_backend = "cpu"
