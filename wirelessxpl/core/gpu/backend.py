# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Classe abstrata ``ComputeBackend`` e seleção automática de backend.

Backends cobrem casos de uso wireless: similaridade de fingerprints RF/PCAP,
mutação de payloads, cracking auxiliar e lotes de hashes. A ordem de
``auto_select_backend`` é CUDA (NVIDIA) → ROCm (AMD/HIP) → OpenCL → CPU.

Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List, Optional

import numpy as np

if TYPE_CHECKING:
    from wirelessxpl.core.hw_profiler import HWProfile

logger = logging.getLogger(__name__)


class ComputeBackend(ABC):
    """Backend abstrato de computação (CUDA, ROCm, OpenCL, CPU).

    Operações uniformes para módulos que processam vetores de features
    (ex.: anomalias em PCAP, correlação de beacons, wordlists).
    """

    name: str = "abstract"

    @abstractmethod
    def is_available(self) -> bool:
        """Verifica se o backend pode ser usado neste host."""

    @abstractmethod
    def device_info(self) -> str:
        """Retorna descrição legível do dispositivo."""

    @abstractmethod
    def array_from_numpy(self, arr: np.ndarray):
        """Converte ``np.ndarray`` para o tipo nativo do backend."""

    @abstractmethod
    def to_numpy(self, arr) -> np.ndarray:
        """Converte array do backend de volta para NumPy."""

    @abstractmethod
    def matmul(self, a, b):
        """Multiplicação de matrizes no backend."""

    @abstractmethod
    def cosine_similarity_batch(self, queries, corpus) -> np.ndarray:
        """Similaridade de cosseno entre vetores de consulta e corpus.

        Args:
            queries: Array (N, D) de vetores de consulta.
            corpus: Array (M, D) de vetores do corpus.

        Returns:
            Array NumPy (N, M) com scores de similaridade.
        """

    def hash_batch(self, data_list: List[bytes], algorithm: str = "md5") -> List[str]:
        """Calcula hash de um lote de blobs; implementação CPU padrão.

        Backends GPU podem sobrescrever com hashing paralelo.

        Args:
            data_list: Lista de bytes a hashear.
            algorithm: Nome do algoritmo (md5, sha1, sha256, ...).

        Returns:
            Lista de digests hexadecimais.
        """
        return [hashlib.new(algorithm, d).hexdigest() for d in data_list]


class ROCmBackend(ComputeBackend):
    """Backend AMD ROCm via PyTorch compilado com HIP.

    Mantido neste módulo para evitar import circular com ``cuda_backend``
    e para preservar a ordem CUDA → ROCm na seleção automática.
    """

    name = "rocm"

    def __init__(self) -> None:
        self._torch = None

    def is_available(self) -> bool:
        try:
            import torch

            hip = getattr(torch.version, "hip", None)
            if hip is not None and torch.cuda.is_available():
                self._torch = torch
                return True
        except ImportError:
            pass
        return False

    def device_info(self) -> str:
        if self._torch:
            dev = self._torch.cuda.get_device_name(0)
            return "ROCm [PyTorch-HIP] {}".format(dev)
        return "ROCm (indisponível)"

    def array_from_numpy(self, arr: np.ndarray):
        if self._torch:
            return self._torch.tensor(arr, device="cuda", dtype=self._torch.float32)
        return arr

    def to_numpy(self, arr) -> np.ndarray:
        if self._torch:
            return arr.detach().cpu().numpy()
        return np.asarray(arr)

    def matmul(self, a, b):
        if self._torch:
            return self._torch.matmul(a, b)
        return np.matmul(np.asarray(a), np.asarray(b))

    def cosine_similarity_batch(self, queries, corpus) -> np.ndarray:
        q = self.array_from_numpy(np.asarray(queries, dtype=np.float32))
        c = self.array_from_numpy(np.asarray(corpus, dtype=np.float32))
        if self._torch:
            q_n = q / (q.norm(dim=1, keepdim=True) + 1e-10)
            c_n = c / (c.norm(dim=1, keepdim=True) + 1e-10)
            sim = self._torch.mm(q_n, c_n.t())
            return self.to_numpy(sim)
        return np.zeros((len(queries), len(corpus)), dtype=np.float32)


def auto_select_backend(
    hw_profile: Optional[HWProfile] = None,
    compute_mode: str = "auto",
) -> ComputeBackend:
    """Escolhe o melhor backend disponível (CUDA → ROCm → OpenCL → CPU).

    Args:
        hw_profile: Perfil opcional de hardware (registro / telemetria).
        compute_mode: Preferência: ``cpu``, ``gpu``, ``hybrid`` ou ``auto``.

    Returns:
        Instância concreta de ``ComputeBackend``.
    """
    if hw_profile is not None:
        logger.debug("hw_profile recebido (reservado p/ roteamento futuro): %s", hw_profile)

    if compute_mode == "cpu":
        from wirelessxpl.core.gpu.cpu_backend import CPUBackend

        return CPUBackend()

    from wirelessxpl.core.gpu.cuda_backend import CUDABackend
    from wirelessxpl.core.gpu.opencl_backend import OpenCLBackend
    from wirelessxpl.core.gpu.cpu_backend import CPUBackend

    candidates = [CUDABackend(), ROCmBackend(), OpenCLBackend()]

    for backend in candidates:
        if backend.is_available():
            logger.info("Backend de computação selecionado: %s", backend.name)
            return backend

    if compute_mode == "gpu":
        logger.warning(
            "compute_mode=gpu sem GPU utilizável; instale PyTorch (CUDA/ROCm) "
            "ou PyOpenCL. Usando CPU."
        )

    return CPUBackend()
