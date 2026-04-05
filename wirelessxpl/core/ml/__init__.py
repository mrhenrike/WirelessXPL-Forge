"""Optional attack advisor (lightweight ML/heuristics + GPU hints).

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from wirelessxpl.core.ml.advisor import AttackAdvisor, AdvisorContext
from wirelessxpl.core.ml.gpu import gpu_capability_summary

__all__ = (
    "AttackAdvisor",
    "AdvisorContext",
    "gpu_capability_summary",
)
