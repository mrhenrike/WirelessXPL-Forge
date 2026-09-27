# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Backend NVIDIA CUDA via PyTorch para WirelessXPL-Forge.

Usa apenas ``torch.Tensor`` no dispositivo CUDA. Builds PyTorch ROCm (HIP)
não são tratados aqui — use ``ROCmBackend`` em ``backend.py``.

Version: 1.0.0
"""

from __future__ import annotations

import logging

import numpy as np

from wirelessxpl.core.gpu.backend import ComputeBackend

logger = logging.getLogger(__name__)

_torch = None


def _get_torch_cuda():
    """Carrega PyTorch com CUDA NVIDIA disponível (não HIP/ROCm).

    Returns:
        Módulo ``torch`` ou ``None`` se indisponível.
    """
    global _torch
    if _torch is not None:
        return _torch
    try:
        import torch

        hip = getattr(torch.version, "hip", None)
        if hip is not None:
            return None
        if torch.cuda.is_available():
            _torch = torch
            return _torch
    except ImportError:
        logger.debug("PyTorch não instalado")
    return None


class CUDABackend(ComputeBackend):
    """Backend CUDA com tensores PyTorch no dispositivo ``cuda``."""

    name = "cuda"

    def is_available(self) -> bool:
        return _get_torch_cuda() is not None

    def device_info(self) -> str:
        torch = _get_torch_cuda()
        if not torch:
            return "CUDA (indisponível)"
        dev = torch.cuda.get_device_name(0)
        props = torch.cuda.get_device_properties(0)
        raw_mem = getattr(props, "total_memory", None) or getattr(props, "total_mem", 0)
        vram = raw_mem // (1024 * 1024)
        return "CUDA [PyTorch] {} ({}MB)".format(dev, vram)

    def array_from_numpy(self, arr: np.ndarray):
        torch = _get_torch_cuda()
        if torch:
            return torch.tensor(arr, device="cuda", dtype=torch.float32)
        return np.asarray(arr, dtype=np.float32)

    def to_numpy(self, arr) -> np.ndarray:
        torch = _get_torch_cuda()
        if torch and hasattr(arr, "detach"):
            return arr.detach().cpu().numpy()
        return np.asarray(arr)

    def matmul(self, a, b):
        torch = _get_torch_cuda()
        if torch:
            return torch.matmul(a, b)
        return np.matmul(np.asarray(a), np.asarray(b))

    def cosine_similarity_batch(self, queries, corpus) -> np.ndarray:
        torch = _get_torch_cuda()
        if not torch:
            q = np.asarray(queries, dtype=np.float32)
            c = np.asarray(corpus, dtype=np.float32)
            q_norm = q / (np.linalg.norm(q, axis=1, keepdims=True) + 1e-10)
            c_norm = c / (np.linalg.norm(c, axis=1, keepdims=True) + 1e-10)
            return q_norm @ c_norm.T

        q = self.array_from_numpy(np.asarray(queries, dtype=np.float32))
        c = self.array_from_numpy(np.asarray(corpus, dtype=np.float32))
        q_n = q / (q.norm(dim=1, keepdim=True) + 1e-10)
        c_n = c / (c.norm(dim=1, keepdim=True) + 1e-10)
        sim = torch.mm(q_n, c_n.t())
        return self.to_numpy(sim)
