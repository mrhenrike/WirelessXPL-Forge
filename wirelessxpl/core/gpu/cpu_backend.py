# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Backend de computação somente CPU (NumPy) para WirelessXPL-Forge.

Sempre disponível; adequado a análise offline de PCAP, wordlists e
prototipagem sem dependências GPU.

Version: 1.0.0
"""

from __future__ import annotations

import os

import numpy as np

from wirelessxpl.core.gpu.backend import ComputeBackend


class CPUBackend(ComputeBackend):
    """Backend CPU puro com NumPy."""

    name = "cpu"

    def is_available(self) -> bool:
        return True

    def device_info(self) -> str:
        return "CPU ({} threads, NumPy)".format(os.cpu_count() or 1)

    def array_from_numpy(self, arr: np.ndarray):
        return arr

    def to_numpy(self, arr) -> np.ndarray:
        return np.asarray(arr)

    def matmul(self, a, b):
        return np.matmul(np.asarray(a), np.asarray(b))

    def cosine_similarity_batch(self, queries, corpus) -> np.ndarray:
        q = np.asarray(queries, dtype=np.float32)
        c = np.asarray(corpus, dtype=np.float32)
        q_norm = q / (np.linalg.norm(q, axis=1, keepdims=True) + 1e-10)
        c_norm = c / (np.linalg.norm(c, axis=1, keepdims=True) + 1e-10)
        return q_norm @ c_norm.T
