# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Priorização de PINs WPS com algoritmos determinísticos e camada ML opcional."""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import numpy as np

logger = logging.getLogger(__name__)

_SKLEARN: Any = None
try:
    from sklearn.ensemble import RandomForestClassifier  # type: ignore

    _SKLEARN = True
except ImportError:
    RandomForestClassifier = None  # type: ignore


def _sklearn_available() -> bool:
    return bool(_SKLEARN)


def _wps_checksum_digit_int(pin7_int: int) -> int:
    """8º dígito WPS (mesma convenção de reaver/hostapd sobre o PIN×10)."""
    accum = 0
    pin = (int(pin7_int) % 10000000) * 10
    for i in range(8):
        digit = (pin // (10**i)) % 10
        if i % 2:
            digit *= 2
            accum += digit // 10 + digit % 10
        else:
            accum += digit
    return (10 - (accum % 10)) % 10


def format_wps_pin(pin7: str) -> str:
    """Formata 7 dígitos base + checksum oficial WPS."""
    if len(pin7) != 7 or not pin7.isdigit():
        raise ValueError("base PIN inválido")
    body = int(pin7, 10)
    check = _wps_checksum_digit_int(body)
    return "{}{}".format(pin7, check)


def wps_pin_checksum(pin7: str) -> str:
    """Alias de :func:`format_wps_pin` para compatibilidade."""
    return format_wps_pin(pin7)


def _mac_ints(bssid: str) -> Tuple[int, int, int, int, int, int]:
    m = re.sub(r"[^0-9a-fA-F]", "", bssid)
    if len(m) != 12:
        raise ValueError("BSSID deve ter 6 octetos hex")
    vals = tuple(int(m[i : i + 2], 16) for i in range(0, 12, 2))
    return vals  # type: ignore[return-value]


def algo_compute_pin(bssid: str) -> Optional[str]:
    """Heurística estilo ComputePIN (derivada de octetos NIC, chipset comum)."""
    try:
        b = _mac_ints(bssid)
    except ValueError:
        return None
    nic = (b[3] << 16) | (b[4] << 8) | b[5]
    pin_int = nic % 10000000
    pin7 = "{:07d}".format(pin_int)
    try:
        return format_wps_pin(pin7)
    except ValueError:
        return None


def algo_easybox(bssid: str) -> Optional[str]:
    """Padrão easybox / Arcor: combinação dos últimos octetos."""
    try:
        b = _mac_ints(bssid)
    except ValueError:
        return None
    mix = ((b[3] ^ b[4]) << 8) | b[5]
    pin_int = mix % 10000000
    pin7 = "{:07d}".format(pin_int)
    return format_wps_pin(pin7)


def algo_arcadyan(bssid: str) -> Optional[str]:
    """Heurística Arcadyan/ISP CPE (rotação XOR sobre OUI+NIC)."""
    try:
        b = _mac_ints(bssid)
    except ValueError:
        return None
    x = (b[0] + b[1] + b[2]) & 0xFF
    nic = ((b[3] ^ x) << 16) | ((b[4] ^ x) << 8) | (b[5] ^ x)
    pin_int = nic % 10000000
    pin7 = "{:07d}".format(pin_int)
    return format_wps_pin(pin7)


def algo_hash_fallback(bssid: str, salt: str = "wirelessxpl") -> str:
    """Gera PIN determinístico válido quando não há algoritmo de fornecedor."""
    raw = (re.sub(r"[^0-9a-fA-F]", "", bssid) + salt).encode("utf-8")
    h = hashlib.sha256(raw).hexdigest()
    pin_int = int(h[:8], 16) % 10000000
    pin7 = "{:07d}".format(pin_int)
    return format_wps_pin(pin7)


@dataclass(frozen=True)
class PINPrediction:
    """Um candidato a PIN ordenado por confiança decrescente."""

    pin: str
    confidence: float
    source: str
    detail: str = ""


class WPSPINPredictor:
    """Combina geradores determinísticos conhecidos com RandomForest opcional.

    A camada ML reordena candidatos quando há dados em ``fine_tune``; sem
    sklearn ou sem treino, a ordenação segue prioridade heurística de fonte.
    """

    def __init__(self) -> None:
        self._generators: Dict[str, Callable[[str], Optional[str]]] = {
            "compute_pin": algo_compute_pin,
            "easybox": algo_easybox,
            "arcadyan": algo_arcadyan,
        }
        self._clf: Any = None
        self._train_X: List[List[float]] = []
        self._train_y: List[int] = []

    def _bssid_features(self, bssid: str) -> List[float]:
        try:
            b = _mac_ints(bssid)
        except ValueError:
            return [0.0] * 14
        feats = [x / 255.0 for x in b]
        oui = (b[0] << 16) | (b[1] << 8) | b[2]
        nic = (b[3] << 16) | (b[4] << 8) | b[5]
        feats.extend([oui / 0xFFFFFF, nic / 0xFFFFFF])
        return feats

    def _vendor_bonus(self, vendor: Optional[str], source: str) -> float:
        if not vendor:
            return 0.0
        v = vendor.lower()
        if "arcadyan" in v and source == "arcadyan":
            return 0.12
        if "vodafone" in v or "easy" in v or "arcor" in v:
            if source == "easybox":
                return 0.12
        if "broadcom" in v or "netgear" in v:
            if source == "compute_pin":
                return 0.08
        return 0.0

    def _pin_vector(self, pin: str) -> List[float]:
        digits = [int(c) for c in pin if c.isdigit()]
        if len(digits) != 8:
            return [0.0] * 8
        return [d / 9.0 for d in digits]

    def _build_X(self, bssid: str, pin: str, vendor: Optional[str]) -> List[float]:
        vhash = float(int(hashlib.md5((vendor or "").encode()).hexdigest()[:4], 16) / 65535.0)
        return [*self._bssid_features(bssid), *self._pin_vector(pin), vhash]

    def fine_tune(self, labeled_samples: Sequence[Tuple[str, str, int]]) -> None:
        """Atualiza o classificador com tentativas (PIN funcionou ou não).

        Args:
            labeled_samples: Tuplas ``(bssid, pin_tentado, sucesso)`` com
                sucesso 1 ou 0.
        """
        for bssid, pin, ok in labeled_samples:
            if len(pin) != 8 or not pin.isdigit():
                continue
            self._train_X.append(self._build_X(bssid, pin, None))
            self._train_y.append(int(ok))

        if not _sklearn_available() or len(self._train_X) < 4:
            self._clf = None
            if not _sklearn_available():
                logger.info("WPSPINPredictor.fine_tune: sklearn ausente.")
            return

        y_arr = np.asarray(self._train_y, dtype=np.int32)
        if len(np.unique(y_arr)) < 2:
            logger.info("WPSPINPredictor: rótulo único; RF desativado até haver sucesso e falha.")
            self._clf = None
            return
        self._clf = RandomForestClassifier(
            n_estimators=120,
            max_depth=10,
            class_weight="balanced",
            random_state=7,
        )
        self._clf.fit(np.asarray(self._train_X, dtype=np.float64), y_arr)

    def predict(
        self,
        bssid: str,
        vendor: Optional[str] = None,
        model: Optional[str] = None,
    ) -> List[PINPrediction]:
        """Lista ordenada de PINs a tentar (maior confiança primeiro).

        Args:
            bssid: Endereço MAC do AP (formato livre).
            vendor: Fabricante opcional (ajusta pesos de algoritmo).
            model: Modelo textual opcional (reservado para extensões).

        Returns:
            Lista de ``PINPrediction`` sem duplicatas de PIN.
        """
        _ = model
        candidates: Dict[str, PINPrediction] = {}
        for name, gen in self._generators.items():
            pin = gen(bssid)
            if pin and pin not in candidates:
                conf = 0.55 + self._vendor_bonus(vendor, name)
                candidates[pin] = PINPrediction(
                    pin=pin,
                    confidence=min(0.95, conf),
                    source=name,
                    detail="deterministic",
                )
        fb = algo_hash_fallback(bssid)
        if fb not in candidates:
            candidates[fb] = PINPrediction(
                pin=fb,
                confidence=0.25,
                source="hash_fallback",
                detail="sem algoritmo de fornecedor",
            )

        ordered = list(candidates.values())

        if self._clf is not None and _sklearn_available():
            try:
                refined: List[PINPrediction] = []
                classes = list(self._clf.classes_)
                idx_ok = classes.index(1) if 1 in classes else None
                for cand in ordered:
                    X = np.asarray([self._build_X(bssid, cand.pin, vendor)], dtype=np.float64)
                    proba = self._clf.predict_proba(X)[0]
                    if idx_ok is not None:
                        p = float(proba[idx_ok])
                        conf = min(0.99, cand.confidence * 0.45 + 0.55 * p)
                    else:
                        conf = cand.confidence
                    refined.append(
                        PINPrediction(
                            pin=cand.pin,
                            confidence=conf,
                            source=cand.source + "+ml",
                            detail=cand.detail,
                        ),
                    )
                ordered = refined
            except Exception as exc:  # pylint: disable=broad-except
                logger.debug("Refinamento ML falhou: %s", exc)

        ordered.sort(key=lambda p: p.confidence, reverse=True)
        return ordered
