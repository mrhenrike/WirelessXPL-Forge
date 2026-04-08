# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Pontuação de qualidade de handshakes WPA e detecção de anomalias em features."""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

import numpy as np

logger = logging.getLogger(__name__)

_SKLEARN: Any = None
_JOBLIB: Any = None

try:
    import joblib as _joblib_mod  # type: ignore

    from sklearn.ensemble import (  # type: ignore
        IsolationForest,
        RandomForestClassifier,
    )

    _SKLEARN = True
    _JOBLIB = _joblib_mod
except ImportError:
    IsolationForest = None  # type: ignore
    RandomForestClassifier = None  # type: ignore


def _sklearn_available() -> bool:
    """Retorna True se scikit-learn e joblib estão importáveis."""
    return bool(_SKLEARN and _JOBLIB)


def _default_writable_ml_dir() -> Path:
    """Diretório gravável para modelos joblib (submódulo WirelessXPL-Forge/.tmp/ml)."""
    # wirelessxpl/core/ml/<this> -> parents[3] = raiz do submódulo Forge
    root = Path(__file__).resolve().parents[3]
    d = root / ".tmp" / "ml"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _bundle_ml_dir() -> Any:
    """Traversable do pacote ``wirelessxpl.resources.ml`` (somente leitura)."""
    return resources.files("wirelessxpl.resources.ml")


@dataclass(frozen=True)
class HandshakeScore:
    """Resultado agregado da análise de um handshake WPA."""

    quality: float
    """Pontuação geral 0–100 (maior = melhor para pós-processamento/crack)."""

    completeness: float
    """Grau de completude do four-way handshake (0–1)."""

    crack_probability: float
    """Probabilidade estimada de sucesso de quebra (0–1)."""

    anomaly_score: float
    """Score de anomalia (quanto maior, mais típico / menos anômalo em IF)."""

    details: Dict[str, Any]
    """Metadados (ex.: uso de heurística, versão do modelo)."""


class HandshakeScorer:
    """Modelo híbrido: IsolationForest + RandomForest para handshakes WPA.

    Com scikit-learn: detecta outliers nas features e estima probabilidade de
    crack. Sem sklearn: aplica heurísticas interpretáveis coerentes com as
    mesmas dimensões de entrada.
    """

    _FEATURE_ORDER: Tuple[str, ...] = (
        "eapol_count",
        "m1_present",
        "m2_present",
        "m3_present",
        "m4_present",
        "replay_consistency",
        "nonce_uniqueness",
        "signal_dbm",
        "capture_duration_sec",
    )

    def __init__(self, model_basename: str = "handshake_scorer") -> None:
        self._model_basename = model_basename
        self._iforest: Any = None
        self._clf: Any = None
        self._load_or_init_models()

    def _load_or_init_models(self) -> None:
        if not _sklearn_available():
            logger.info("HandshakeScorer: sklearn indisponível; modo heurístico.")
            return
        path = _default_writable_ml_dir() / f"{self._model_basename}.joblib"
        bundle = _bundle_ml_dir()
        if path.is_file():
            try:
                data = _JOBLIB.load(path)
                self._iforest = data.get("iforest")
                self._clf = data.get("clf")
                return
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning("Falha ao carregar %s: %s", path, exc)
        bundle_name = f"{self._model_basename}.joblib"
        try:
            if hasattr(bundle, "joinpath"):
                bp = bundle.joinpath(bundle_name)
                if bp.is_file():
                    raw = bp.read_bytes() if hasattr(bp, "read_bytes") else bp.open("rb").read()
                    import io

                    data = _JOBLIB.load(io.BytesIO(raw))
                    self._iforest = data.get("iforest")
                    self._clf = data.get("clf")
                    return
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("Sem modelo empacotado %s: %s", bundle_name, exc)

        self._iforest = IsolationForest(
            n_estimators=120,
            contamination=0.08,
            random_state=42,
        )
        self._clf = RandomForestClassifier(
            n_estimators=80,
            max_depth=8,
            random_state=42,
        )
        rng = np.random.RandomState(42)
        warm = rng.normal(size=(48, len(self._FEATURE_ORDER)))
        warm_y = (rng.uniform(size=48) > 0.55).astype(np.int32)
        self._iforest.fit(warm)
        self._clf.fit(warm, warm_y)

    def _vector_from_dict(self, pcap_features: Mapping[str, Any]) -> np.ndarray:
        def _f(key: str, default: float = 0.0) -> float:
            v = pcap_features.get(key, default)
            try:
                return float(v)
            except (TypeError, ValueError):
                return float(default)

        mtypes = pcap_features.get("message_types") or {}
        vec = [
            _f("eapol_count"),
            float(bool(mtypes.get("m1", pcap_features.get("m1_present", False)))),
            float(bool(mtypes.get("m2", pcap_features.get("m2_present", False)))),
            float(bool(mtypes.get("m3", pcap_features.get("m3_present", False)))),
            float(bool(mtypes.get("m4", pcap_features.get("m4_present", False)))),
            _f("replay_counter_consistency", pcap_features.get("replay_consistency", 0.0)),
            _f("nonce_uniqueness", 1.0),
            _f("ap_signal_strength_dbm", pcap_features.get("signal_dbm", -90.0)),
            _f("capture_duration_sec", 1.0),
        ]
        return np.asarray(vec, dtype=np.float64).reshape(1, -1)

    def _heuristic_score(self, pcap_features: Mapping[str, Any]) -> HandshakeScore:
        x = self._vector_from_dict(pcap_features).ravel()
        eapol = int(max(0, min(x[0], 20)))
        present = int(sum(x[1:5]))
        completeness = present / 4.0
        replay = float(x[5])
        nonce_u = float(x[6])
        sig = float(x[7])
        duration = max(0.1, float(x[8]))

        quality = (
            15.0 * min(eapol / 4.0, 1.0)
            + 55.0 * completeness
            + 15.0 * max(0.0, min(replay, 1.0))
            + 10.0 * max(0.0, min(nonce_u, 1.0))
            + 5.0 * max(0.0, min((sig + 100.0) / 40.0, 1.0))
        )
        quality = float(max(0.0, min(quality, 100.0)))

        crack = 0.15 + 0.55 * completeness + 0.15 * min(eapol / 6.0, 1.0)
        crack += 0.1 * max(0.0, min((sig + 95.0) / 35.0, 1.0))
        crack += 0.05 * max(0.0, min(2.0 / duration, 1.0))
        crack = float(max(0.0, min(crack, 0.99)))

        return HandshakeScore(
            quality=quality,
            completeness=completeness,
            crack_probability=crack,
            anomaly_score=0.5,
            details={"mode": "heuristic", "eapol_frames": eapol},
        )

    def score(self, pcap_features: Dict[str, Any]) -> HandshakeScore:
        """Calcula ``HandshakeScore`` a partir de features agregadas de PCAP/EAPOL.

        Args:
            pcap_features: Dicionário com contagens EAPOL, presença M1–M4,
                consistência de replay counter, unicidade de nonces, RSSI e
                duração da captura.

        Returns:
            Instância imutável ``HandshakeScore``.
        """
        if not _sklearn_available() or self._iforest is None or self._clf is None:
            return self._heuristic_score(pcap_features)

        X = self._vector_from_dict(pcap_features)
        if_dec = 0.0
        try:
            if_dec = float(self._iforest.decision_function(X)[0])
            anomaly_score = float(1.0 / (1.0 + math.exp(-if_dec)))
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("IF decision_function falhou: %s", exc)
            anomaly_score = 0.5

        try:
            proba = self._clf.predict_proba(X)[0, 1]
            crack_probability = float(max(0.0, min(proba, 0.999)))
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("RF predict_proba falhou: %s", exc)
            crack_probability = self._heuristic_score(pcap_features).crack_probability

        heur = self._heuristic_score(pcap_features)
        quality = heur.quality * (0.65 + 0.35 * anomaly_score)
        quality = float(max(0.0, min(quality, 100.0)))

        return HandshakeScore(
            quality=quality,
            completeness=heur.completeness,
            crack_probability=crack_probability,
            anomaly_score=anomaly_score,
            details={"mode": "sklearn", "if_decision_raw": if_dec},
        )

    def save(self, path: Optional[Path] = None) -> Path:
        """Persiste iforest + RandomForest via joblib.

        Args:
            path: Arquivo destino; padrão ``.tmp/ml/<basename>.joblib``.

        Returns:
            Caminho do arquivo gravado.
        """
        if not _sklearn_available():
            raise RuntimeError("sklearn/joblib não instalados; nada a salvar.")
        dest = path or (_default_writable_ml_dir() / f"{self._model_basename}.joblib")
        dest.parent.mkdir(parents=True, exist_ok=True)
        _JOBLIB.dump({"iforest": self._iforest, "clf": self._clf}, dest)
        return dest

    def load(self, path: Optional[Path] = None) -> None:
        """Carrega modelo joblib do disco ou do bundle em ``resources/ml/``."""
        if not _sklearn_available():
            return
        if path and path.is_file():
            data = _JOBLIB.load(path)
            self._iforest = data.get("iforest")
            self._clf = data.get("clf")
            return
        self._load_or_init_models()

    def fine_tune(self, labeled_samples: Sequence[Tuple[Mapping[str, Any], int]]) -> None:
        """Atualiza IsolationForest e RandomForest com novos exemplos rotulados.

        Args:
            labeled_samples: Lista de pares (features_dict, crack_success) com
                ``crack_success`` em {0, 1}.
        """
        if not labeled_samples:
            return
        if not _sklearn_available():
            logger.info("fine_tune ignorado: sklearn indisponível.")
            return

        X_list = [self._vector_from_dict(f).ravel() for f, _ in labeled_samples]
        y = np.asarray([int(lbl) for _, lbl in labeled_samples], dtype=np.int32)
        X = np.vstack(X_list)

        self._iforest = IsolationForest(
            n_estimators=160,
            contamination="auto",
            random_state=42,
        )
        self._iforest.fit(X)

        self._clf = RandomForestClassifier(
            n_estimators=120,
            max_depth=12,
            random_state=42,
        )
        self._clf.fit(X, y)


class AnomalyDetector:
    """Detecção de anomalias genérica em vetores numéricos (IsolationForest).

    Fallback: distância euclidiana ao centróide amostral com z-score grosseiro.
    """

    def __init__(self, contamination: float = 0.1) -> None:
        self._contamination = contamination
        self._model: Any = None
        self._centroid: Optional[np.ndarray] = None
        self._scale: Optional[np.ndarray] = None

    def fit(self, X: Union[np.ndarray, Sequence[Sequence[float]]]) -> None:
        """Ajusta o detector a uma matriz de features (N, D)."""
        arr = np.asarray(X, dtype=np.float64)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if _sklearn_available():
            self._model = IsolationForest(
                n_estimators=150,
                contamination=self._contamination,
                random_state=0,
            )
            self._model.fit(arr)
        else:
            self._centroid = np.mean(arr, axis=0)
            self._scale = np.std(arr, axis=0) + 1e-9

    def decision_function(self, X: Union[np.ndarray, Sequence[Sequence[float]]]) -> np.ndarray:
        """Scores de decisão (maiores = mais inliers, alinhado ao sklearn)."""
        arr = np.asarray(X, dtype=np.float64)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if self._model is not None:
            return np.asarray(self._model.decision_function(arr), dtype=np.float64)
        if self._centroid is None or self._scale is None:
            return np.zeros(arr.shape[0], dtype=np.float64)
        d = np.linalg.norm((arr - self._centroid) / self._scale, axis=1)
        return -d

    def predict(self, X: Union[np.ndarray, Sequence[Sequence[float]]]) -> np.ndarray:
        """Rótulos 1=inlier, -1=outlier."""
        arr = np.asarray(X, dtype=np.float64)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if self._model is not None:
            return np.asarray(self._model.predict(arr), dtype=np.int32)
        df = self.decision_function(arr)
        thresh = np.median(df)
        return np.where(df >= thresh, 1, -1).astype(np.int32)
