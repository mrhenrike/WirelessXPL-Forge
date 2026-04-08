# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Otimização de canal e janelas temporais para ataques wireless."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import numpy as np

logger = logging.getLogger(__name__)

_SKLEARN: Any = None
try:
    from sklearn.ensemble import GradientBoostingRegressor  # type: ignore

    _SKLEARN = True
except ImportError:
    GradientBoostingRegressor = None  # type: ignore


def _sklearn_available() -> bool:
    return bool(_SKLEARN)


@dataclass(frozen=True)
class ChannelPlan:
    """Plano de canal recomendado e janelas de tempo para deauth / evil twin."""

    recommended_channel: int
    evil_twin_channel: int
    timing_windows: List[Tuple[float, float]]
    """Janelas em horas locais [0,24) como (início, fim) para picos de reconexão."""

    confidence: float
    congestion_prediction: Dict[int, float]
    details: Dict[str, Any] = field(default_factory=dict)


class ChannelOptimizer:
    """Prevê congestão por canal e sugere timing de ataque.

    Com ``sklearn``, usa ``GradientBoostingRegressor``. Observações são
    acumuladas e o modelo é reajustado periodicamente. Sem sklearn, usa
    heurísticas sobre utilização e contagem de APs/clientes.
    """

    def __init__(self, refit_every: int = 32) -> None:
        self._refit_every = max(4, refit_every)
        self._model: Any = None
        self._obs_buffer: List[Tuple[np.ndarray, float]] = []
        self._train_X: List[List[float]] = []
        self._train_y: List[float] = []

    @staticmethod
    def _row_from_channel_entry(
        ch: Mapping[str, Any],
        hour: float,
        dow: float,
    ) -> Tuple[int, List[float]]:
        cid = int(ch.get("channel", ch.get("id", 0)))
        util = float(ch.get("utilization", ch.get("busy_ratio", 0.3)))
        apc = float(ch.get("ap_count", ch.get("aps", 0)))
        clc = float(ch.get("client_count", ch.get("clients", 0)))
        noise = float(ch.get("noise_floor_dbm", ch.get("noise_dbm", -95.0)))
        hist = float(ch.get("historical_success_rate", ch.get("hist_success", 0.35)))
        feats = [
            float(cid),
            util,
            apc,
            clc,
            noise / 100.0,
            hour / 24.0,
            dow / 7.0,
            hist,
        ]
        return cid, feats

    def _predict_congestion(
        self,
        channels: Sequence[Mapping[str, Any]],
        hour: float,
        dow: float,
    ) -> Dict[int, float]:
        preds: Dict[int, float] = {}
        rows: List[Tuple[int, List[float]]] = []
        for ch in channels:
            cid, feats = self._row_from_channel_entry(ch, hour, dow)
            rows.append((cid, feats))

        if self._model is not None and _sklearn_available() and len(self._train_X) >= 6:
            try:
                X = np.asarray([r[1] for r in rows], dtype=np.float64)
                raw = self._model.predict(X)
                for (cid, _), p in zip(rows, raw):
                    preds[cid] = float(max(0.0, min(1.0, p)))
                return preds
            except Exception as exc:  # pylint: disable=broad-except
                logger.debug("GBRT predict falhou: %s", exc)

        for cid, feats in rows:
            util, apc, clc = feats[1], feats[2], feats[3]
            preds[cid] = float(max(0.0, min(1.0, 0.45 * util + 0.25 * min(apc / 10.0, 1.0) + 0.2 * min(clc / 40.0, 1.0))))
        return preds

    def optimize(self, scan_data: Dict[str, Any]) -> ChannelPlan:
        """Gera um :class:`ChannelPlan` a partir de um scan agregado.

        Args:
            scan_data: Deve incluir ``channels`` (lista de dicts com métricas por
                canal) e opcionalmente ``timestamp`` (datetime ou ISO) para
                hora/dia da semana.

        Returns:
            Plano com canal alvo, canal evil twin e janelas sugeridas.
        """
        channels: List[Mapping[str, Any]] = list(scan_data.get("channels") or [])
        ts = scan_data.get("timestamp")
        if isinstance(ts, datetime):
            hour = float(ts.hour) + ts.minute / 60.0
            dow = float(ts.weekday())
        elif isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                hour = float(dt.hour) + dt.minute / 60.0
                dow = float(dt.weekday())
            except ValueError:
                hour = float(scan_data.get("hour", 12))
                dow = float(scan_data.get("day_of_week", 3))
        else:
            hour = float(scan_data.get("hour", 12))
            dow = float(scan_data.get("day_of_week", 3))

        congestion = self._predict_congestion(channels, hour, dow)
        if not congestion:
            return ChannelPlan(
                recommended_channel=int(scan_data.get("default_channel", 6)),
                evil_twin_channel=int(scan_data.get("default_channel", 6)),
                timing_windows=[(18.0, 23.0)],
                confidence=0.35,
                congestion_prediction={},
                details={"mode": "empty_scan"},
            )

        # Menor congestão para evil twin próximo ao alvo (mesma banda)
        sorted_ch = sorted(congestion.items(), key=lambda kv: kv[1])
        best_cid, _ = sorted_ch[0]
        target_hist = next(
            (
                float(c.get("historical_success_rate", c.get("hist_success", 0.35)))
                for c in channels
                if int(c.get("channel", c.get("id", -1))) == best_cid
            ),
            0.35,
        )
        # Canal alvo: equilíbrio entre histórico de sucesso e congestão moderada (clientes ativos)
        scored: List[Tuple[int, float]] = []
        for cid, cong in congestion.items():
            hist = next(
                (
                    float(c.get("historical_success_rate", c.get("hist_success", 0.35)))
                    for c in channels
                    if int(c.get("channel", c.get("id", -1))) == cid
                ),
                0.35,
            )
            clients = next(
                (
                    float(c.get("client_count", c.get("clients", 0)))
                    for c in channels
                    if int(c.get("channel", c.get("id", -1))) == cid
                ),
                0.0,
            )
            utility = 0.55 * hist + 0.25 * min(clients / 30.0, 1.0) - 0.35 * cong
            scored.append((cid, utility))
        scored.sort(key=lambda x: x[1], reverse=True)
        target_cid = scored[0][0]

        evil_cid = best_cid if best_cid != target_cid else (sorted_ch[1][0] if len(sorted_ch) > 1 else best_cid)

        # Janelas: horários com maior rotatividade de clientes (heurística + hora atual)
        windows = [(7.5, 9.5), (12.0, 14.0), (18.0, 23.0)]
        if 8 <= hour <= 10 or 17 <= hour <= 22:
            conf = 0.78 if self._model is not None else 0.62
        else:
            conf = 0.55 if self._model is not None else 0.48
        conf = float(min(0.95, conf + 0.1 * target_hist))

        return ChannelPlan(
            recommended_channel=int(target_cid),
            evil_twin_channel=int(evil_cid),
            timing_windows=windows,
            confidence=conf,
            congestion_prediction=congestion,
            details={
                "mode": "sklearn" if self._model is not None else "heuristic",
                "hour": hour,
                "dow": dow,
            },
        )

    def _maybe_refit(self) -> None:
        if not _sklearn_available():
            return
        if len(self._train_X) < 6:
            return
        self._model = GradientBoostingRegressor(
            n_estimators=80,
            max_depth=4,
            learning_rate=0.08,
            random_state=11,
        )
        try:
            self._model.fit(np.asarray(self._train_X, dtype=np.float64), np.asarray(self._train_y, dtype=np.float64))
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("ChannelOptimizer refit falhou: %s", exc)
            self._model = None

    def update(self, observation: Mapping[str, Any]) -> None:
        """Aprendizado online: uma linha de medição de canal + congestão observada.

        Args:
            observation: Campos alinhados a ``_row_from_channel_entry`` mais
                ``congestion_observed`` em [0,1].
        """
        hour = float(observation.get("hour", 12))
        dow = float(observation.get("day_of_week", 3))
        ch = {k: v for k, v in observation.items() if k not in ("hour", "day_of_week", "congestion_observed")}
        _, feats = self._row_from_channel_entry(ch, hour, dow)
        y = float(observation.get("congestion_observed", observation.get("utilization", 0.5)))
        y = max(0.0, min(1.0, y))
        self._train_X.append(feats)
        self._train_y.append(y)
        self._obs_buffer.append((np.asarray(feats, dtype=np.float64), y))
        if len(self._train_X) % self._refit_every == 0:
            self._maybe_refit()
