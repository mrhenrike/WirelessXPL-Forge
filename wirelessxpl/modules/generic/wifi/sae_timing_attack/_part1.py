#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""SAE Timing Side-Channel Analysis - native WPA3 timing attack module.

Measures SAE handshake timing to detect group-dependent variations that
reveal password partition information (CVE-2019-9494). Instead of relying
on external Dragonblood binaries, this module uses Scapy to sniff SAE
Authentication frames directly, collecting inter-frame timing deltas
between SAE commit and confirm exchanges.

Workflow:
  1. capture  : sniff SAE Authentication frames on a monitor interface
  2. analyze  : perform statistical analysis on captured timing data
  3. full_pipeline : capture then analyze in one step
  4. info     : display module reference and CVE details

Research references:
  - Dragonblood (Vanhoef/Ronen, 2019) - timing side-channel on SAE MODP groups
  - CVE-2019-9494: SAE timing side-channel leaks password partition info
  - CVE-2019-13377: Brainpool group timing side-channel

Version: 1.0.0
"""


import json
import logging
import math
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

HAS_SCAPY = False
try:
    from scapy.all import (
        Dot11,
        Dot11Auth,
        RadioTap,
        rdpcap,
    )
    from scapy.all import (
        sniff as scapy_sniff,
    )
    HAS_SCAPY = True
except ImportError:
    pass

HAS_NUMPY = False
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    pass

_project_tmp = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".tmp")
os.makedirs(_project_tmp, exist_ok=True)


def _mean(values: list[float]) -> float:
    """Arithmetic mean (fallback when numpy is unavailable)."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def _stddev(values: list[float]) -> float:
    """Population standard deviation (fallback when numpy is unavailable)."""
    if len(values) < 2:
        return 0.0
    avg = _mean(values)
    variance = sum((x - avg) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def _ttest_ind(a: list[float], b: list[float]) -> tuple[float, float]:
    """Welch's t-test (fallback when numpy/scipy unavailable).

    Returns (t_statistic, approximate_p_value).
    The p-value uses a rough normal approximation; for precise results
    use scipy.stats.ttest_ind.
    """
    if len(a) < 2 or len(b) < 2:
        return (0.0, 1.0)

    mean_a, mean_b = _mean(a), _mean(b)
    var_a = sum((x - mean_a) ** 2 for x in a) / (len(a) - 1)
    var_b = sum((x - mean_b) ** 2 for x in b) / (len(b) - 1)

    se = math.sqrt(var_a / len(a) + var_b / len(b))
    if se == 0:
        return (0.0, 1.0)

    t_stat = (mean_a - mean_b) / se
    # rough two-tailed p from normal CDF approximation
    p_approx = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(abs(t_stat) / math.sqrt(2.0))))
    return (t_stat, p_approx)


@requires_os(OSRequirement.LINUX_ONLY)
