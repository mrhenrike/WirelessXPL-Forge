# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Backends de computação GPU/CPU para WirelessXPL-Forge (Wi‑Fi, BLE, RF)."""

from wirelessxpl.core.gpu.backend import ComputeBackend, auto_select_backend

__all__ = ["ComputeBackend", "auto_select_backend"]
