"""WiFi target filtering, scoring and prioritization.

Filters and ranks discovered APs by signal strength, encryption
type, WPS state and attack feasibility. Used by autopwn and
manual engagement workflows.

Conceptual reference: wifite2 model/target.py (GPL-2.0, derv82)
Recode: full Python rewrite, no code copied.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional, Sequence

logger = logging.getLogger(__name__)


class EncryptionType(Enum):
    OPEN = auto()
    WEP = auto()
    WPA = auto()
    WPA2 = auto()
    WPA3 = auto()
    WPA2_ENTERPRISE = auto()
    WPA3_ENTERPRISE = auto()
    UNKNOWN = auto()


class WPSState(Enum):
    DISABLED = auto()
    ENABLED = auto()
    LOCKED = auto()
    UNKNOWN = auto()


@dataclass
class WiFiTarget:
    bssid: str
    ssid: str = ""
    channel: int = 0
    power: int = -100
    encryption: EncryptionType = EncryptionType.UNKNOWN
    wps: WPSState = WPSState.UNKNOWN
    clients: int = 0
    pmf_required: bool = False
    is_hidden: bool = False
    beacon_count: int = 0

    @property
    def is_enterprise(self) -> bool:
        return self.encryption in (
            EncryptionType.WPA2_ENTERPRISE,
            EncryptionType.WPA3_ENTERPRISE,
        )

    @property
    def is_broadcast(self) -> bool:
        return self.bssid.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")


@dataclass
class FilterCriteria:
    min_power: int = -80
    max_power: int = 0
    channels: Optional[List[int]] = None
    exclude_enterprise: bool = True
    exclude_hidden: bool = False
    exclude_open: bool = False
    exclude_wep: bool = False
    ssid_pattern: Optional[str] = None
    bssid_pattern: Optional[str] = None
    wps_only: bool = False
    min_clients: int = 0


def filter_targets(
    targets: Sequence[WiFiTarget],
    criteria: FilterCriteria,
) -> List[WiFiTarget]:
    """Filter WiFi targets by criteria.

    Args:
        targets: List of discovered targets.
        criteria: Filtering criteria.

    Returns:
        Filtered list of targets.
    """
    result = []

    for t in targets:
        if t.is_broadcast:
            continue

        if t.power < criteria.min_power or t.power > criteria.max_power:
            continue

        if criteria.channels and t.channel not in criteria.channels:
            continue

        if criteria.exclude_enterprise and t.is_enterprise:
            continue

        if criteria.exclude_hidden and t.is_hidden:
            continue

        if criteria.exclude_open and t.encryption == EncryptionType.OPEN:
            continue

        if criteria.exclude_wep and t.encryption == EncryptionType.WEP:
            continue

        if criteria.wps_only and t.wps != WPSState.ENABLED:
            continue

        if criteria.min_clients > 0 and t.clients < criteria.min_clients:
            continue

        if criteria.ssid_pattern:
            try:
                if not re.search(criteria.ssid_pattern, t.ssid, re.IGNORECASE):
                    continue
            except re.error:
                pass

        if criteria.bssid_pattern:
            try:
                if not re.search(criteria.bssid_pattern, t.bssid, re.IGNORECASE):
                    continue
            except re.error:
                pass

        result.append(t)

    return result


def rank_targets(
    targets: Sequence[WiFiTarget],
    prefer_wps: bool = True,
    prefer_clients: bool = True,
) -> List[WiFiTarget]:
    """Rank targets by attack feasibility score (higher = better).

    Score factors:
    - Signal strength (power)
    - WPS state (enabled = bonus)
    - Connected clients (more clients = easier handshake)
    - Encryption simplicity (WEP > WPA > WPA2 > WPA3)

    Args:
        targets: Filtered target list.
        prefer_wps: Bonus for WPS-enabled targets.
        prefer_clients: Bonus for targets with clients.

    Returns:
        Targets sorted by score descending.
    """

    def _score(t: WiFiTarget) -> float:
        score = 0.0

        power_norm = max(0, (t.power + 100)) / 100.0
        score += power_norm * 40

        enc_scores = {
            EncryptionType.OPEN: 50,
            EncryptionType.WEP: 45,
            EncryptionType.WPA: 30,
            EncryptionType.WPA2: 20,
            EncryptionType.WPA3: 10,
            EncryptionType.WPA2_ENTERPRISE: 5,
            EncryptionType.WPA3_ENTERPRISE: 2,
            EncryptionType.UNKNOWN: 0,
        }
        score += enc_scores.get(t.encryption, 0)

        if prefer_wps and t.wps == WPSState.ENABLED:
            score += 25

        if prefer_clients and t.clients > 0:
            score += min(t.clients * 5, 20)

        if t.pmf_required:
            score -= 10

        return score

    return sorted(targets, key=_score, reverse=True)


def suggest_attacks(target: WiFiTarget) -> List[str]:
    """Suggest attack chain order for a target.

    Prioritizes faster attacks first (PMKID, WPS PixieDust)
    then falls back to slower ones (handshake capture + crack).

    Args:
        target: Single WiFi target.

    Returns:
        Ordered list of attack method names.
    """
    attacks: List[str] = []

    if target.encryption == EncryptionType.OPEN:
        attacks.append("evil-twin-captive")
        return attacks

    if target.encryption == EncryptionType.WEP:
        attacks.append("wep-chop-chop")
        attacks.append("wep-arp-replay")
        return attacks

    if target.wps == WPSState.ENABLED:
        attacks.append("wps-pixie-dust")
        attacks.append("wps-pin-brute")

    if target.encryption in (EncryptionType.WPA, EncryptionType.WPA2, EncryptionType.WPA3):
        attacks.append("pmkid-solicitation")
        if target.clients > 0:
            attacks.append("deauth-handshake-capture")
        else:
            attacks.append("passive-handshake-wait")

    if target.encryption == EncryptionType.WPA3 and not target.pmf_required:
        attacks.append("wpa3-sae-downgrade")

    return attacks
