#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""UERANSIM 5G UE/gNB simulator bridge for 5G NR security research.

Bridge UERANSIM for 5G New Radio security testing, including UE simulation,
gNB simulation, protocol analysis, and vulnerability assessment.

5G NR architecture components:
  gNB (gNodeB): 5G base station (radio access network)
  AMF (Access and Mobility Management Function): core network entry point
  UPF (User Plane Function): data forwarding
  SMF (Session Management Function): PDU session control
  AUSF/UDM: authentication and subscriber data

UERANSIM capabilities:
  - Full 5G UE simulation (registration, PDU session, data transfer)
  - Full gNB simulation (RRC, NGAP, NAS relay)
  - CLI for runtime control (nr-cli)
  - Config-driven: YAML templates for gNB and UE parameters

5G security areas:
  - SUCI/SUPI: subscription identifier concealment (privacy)
  - 5G-AKA: authentication and key agreement
  - NAS security: integrity and ciphering of NAS messages
  - RRC security: Radio Resource Control layer procedures

Requires: UERANSIM binaries (nr-gnb, nr-ue, nr-cli), 5G core (Open5GS or free5GC).

References:
  - https://github.com/aligungr/UERANSIM
  - 3GPP TS 33.501 (5G Security)
  - 5GReasoner: https://relentless-warrior.github.io/5greasoner/
  - DoLTEst: https://github.com/SysSec-KAIST/DoLTEst

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


def _find_ueransim(custom_path: str) -> Path | None:
    """Locate UERANSIM installation directory."""
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return p

    candidates = [
        Path.home() / "UERANSIM",
        Path.home() / "tools" / "UERANSIM",
        Path("/opt/UERANSIM"),
        Path("/opt/ueransim"),
        Path.home() / "UERANSIM" / "build",
    ]
    for c in candidates:
        if c.exists():
            return c

    nr_gnb = _which("nr-gnb")
    if nr_gnb:
        return Path(nr_gnb).parent

    return None


_GNB_CONFIG_TEMPLATE = """\
mcc: '{mcc}'
mnc: '{mnc}'
nci: '0x000000010'
idLength: 32
tac: {tac}

linkIp: 127.0.0.1
ngapIp: 127.0.0.1
gtpIp: 127.0.0.1

amfConfigs:
  - address: {amf_host}
    port: {amf_port}

slices:
  - sst: 1

ignoreStreamIds: true
"""

_UE_CONFIG_TEMPLATE = """\
supi: 'imsi-{supi}'
mcc: '{mcc}'
mnc: '{mnc}'

key: '{key_k}'
op: '{key_opc}'
opType: 'OPC'
amf: '8000'

imei: '356938035643803'

gnbSearchList:
  - 127.0.0.1

sessions:
  - type: 'IPv4'
    apn: '{dnn}'
    slice:
      sst: 1

configured-nssai:
  - sst: 1

integrity:
  IA1: true
  IA2: true
  IA3: true

ciphering:
  EA1: true
  EA2: true
  EA3: true
"""


