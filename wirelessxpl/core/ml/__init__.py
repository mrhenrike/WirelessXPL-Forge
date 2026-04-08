"""Machine learning para otimização de ataques wireless (WirelessXPL-Forge).

Componentes opcionais: quando ``scikit-learn``, ``joblib`` ou ``torch`` não
estão instalados, cada módulo degrada para heurísticas ou CPU pura sem
falhar na importação.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from wirelessxpl.core.ml.advisor import (
    AdvisorContext,
    AttackAdvisor,
    advisor_context_from_autopwn,
)
from wirelessxpl.core.ml.ap_fingerprinter import APFingerprint, APFingerprinter
from wirelessxpl.core.ml.channel_optimizer import ChannelOptimizer, ChannelPlan
from wirelessxpl.core.ml.gpu import gpu_capability_summary
from wirelessxpl.core.ml.handshake_scorer import (
    AnomalyDetector,
    HandshakeScore,
    HandshakeScorer,
)
from wirelessxpl.core.ml.portal_optimizer import PortalOptimizer, PortalRecommendation
from wirelessxpl.core.ml.wps_pin_predictor import PINPrediction, WPSPINPredictor

__all__ = (
    "AdvisorContext",
    "AnomalyDetector",
    "APFingerprint",
    "APFingerprinter",
    "AttackAdvisor",
    "ChannelOptimizer",
    "ChannelPlan",
    "HandshakeScore",
    "HandshakeScorer",
    "PINPrediction",
    "PortalOptimizer",
    "PortalRecommendation",
    "WPSPINPredictor",
    "advisor_context_from_autopwn",
    "gpu_capability_summary",
)
