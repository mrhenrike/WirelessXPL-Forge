#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""SS7/Diameter/GTP protocol attack bridge using SiGploit framework.

Bridge the SiGploit framework for comprehensive testing of SS7, Diameter,
and GTP protocol vulnerabilities. Covers the most critical cellular signaling
attacks used in real-world surveillance and interception operations (2020-2026).

Protocols:
  SS7 (MAP/CAP/TCAP/SCCP): legacy signaling for 2G/3G, still widely interconnected
  Diameter (S6a/S6d): 4G/5G signaling replacement for SS7 HLR/AuC queries
  GTP (C-plane/U-plane): GPRS Tunnelling Protocol for data plane and control

Attack categories:
  - Location tracking: SendRoutingInfo, AnyTimeInterrogation, ProvideSubscriberInfo
  - SMS interception: UpdateLocation to redirect SMS to attacker MSC/VLR
  - Call redirection: InsertSubscriberData, RegisterSS for unconditional forwarding
  - DoS: CancelLocation, PurgeMS to de-register subscribers
  - IMSI enumeration: SendRoutingInfoForSM to map MSISDN to IMSI
  - GTP tunnel hijack: modify GTP tunnels for traffic interception
  - Diameter equivalents of SS7 attacks for 4G/5G networks

Requires: SS7 connectivity (SIGTRAN/M3UA over IP) or Osmocom lab core,
SiGploit framework, SCTP stack.

References:
  - https://github.com/SigPloiter/SigPloit
  - P1 Security SS7 research
  - GSMA IR.82 SS7 Security Guidelines
  - Positive Technologies SS7 reports (2020-2024)

Version: 1.0.0
"""


import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.core.hw_validator import HWValidator, Requirement
from wirelessxpl.core.phase_gateway import PhaseGateway
from wirelessxpl.modules.generic.sim._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


def _which(binary: str) -> str | None:
    return shutil.which(binary)


def _ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def _find_sigploit(custom_path: str) -> Path | None:
    """Locate SiGploit installation."""
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return p

    candidates = [
        Path.home() / "SigPloit",
        Path.home() / "tools" / "SigPloit",
        Path("/opt/SigPloit"),
        Path("/opt/sigploit"),
    ]
    for c in candidates:
        if c.exists():
            return c

    sigploit_bin = _which("sigploit")
    if sigploit_bin:
        return Path(sigploit_bin).parent

    return None


