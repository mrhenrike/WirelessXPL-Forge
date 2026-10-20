"""Wireless Intrusion Detection System (WIDS) - native Python implementation.

Passive monitor-mode packet analysis using Scapy. Detects common 802.11
attacks and anomalies, emitting structured alerts via callback or MQTT.

Detected threat classes:
  - DEAUTH_FLOOD: excessive deauthentication frames targeting client/AP
  - BEACON_FLOOD: beacon frame flood (SSID flood attack)
  - PROBE_FLOOD: probe request/response flood
  - EVIL_TWIN: SSID seen with a different BSSID than previously observed
  - ROGUE_AP: new AP on monitored SSID with mismatched parameters
  - CHANNEL_HOP: AP BSSID hopping across multiple channels rapidly
  - SSID_CHANGE: known BSSID advertising different SSID
  - DISASSOC_FLOOD: excessive disassociation frames

Requires: scapy (graceful import error with clear message)
MQTT alerting: requires paho-mqtt (optional, graceful fallback)

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""


import logging
import threading
import time
import uuid
from collections import defaultdict, deque
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone, UTC
from enum import StrEnum
from typing import Any, Optional
from collections.abc import Callable

logger = logging.getLogger(__name__)

try:
    from scapy.all import AsyncSniffer  # type: ignore
    from scapy.layers.dot11 import (  # type: ignore
        Dot11,
        Dot11Beacon,
        Dot11Deauth,
        Dot11Disas,
        Dot11Elt,
        Dot11ProbeReq,
        Dot11ProbeResp,
        RadioTap,
    )
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False
    logger.warning("[WIDS] scapy not installed - install with: pip install scapy")

try:
    import paho.mqtt.client as mqtt  # type: ignore
    _MQTT_AVAILABLE = True
except ImportError:
    _MQTT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Alert types and structure
# ---------------------------------------------------------------------------

class AlertType(StrEnum):
    DEAUTH_FLOOD = "DEAUTH_FLOOD"
    BEACON_FLOOD = "BEACON_FLOOD"
    PROBE_FLOOD = "PROBE_FLOOD"
    EVIL_TWIN = "EVIL_TWIN"
    ROGUE_AP = "ROGUE_AP"
    CHANNEL_HOP = "CHANNEL_HOP"
    SSID_CHANGE = "SSID_CHANGE"
    DISASSOC_FLOOD = "DISASSOC_FLOOD"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_SEVERITY_MAP: dict[AlertType, Severity] = {
    AlertType.DEAUTH_FLOOD: Severity.CRITICAL,
    AlertType.BEACON_FLOOD: Severity.HIGH,
    AlertType.PROBE_FLOOD: Severity.MEDIUM,
    AlertType.EVIL_TWIN: Severity.CRITICAL,
    AlertType.ROGUE_AP: Severity.HIGH,
    AlertType.CHANNEL_HOP: Severity.MEDIUM,
    AlertType.SSID_CHANGE: Severity.HIGH,
    AlertType.DISASSOC_FLOOD: Severity.HIGH,
}


@dataclass
class WIDSAlert:
    """A WIDS detection event."""
    alert_id: str
    alert_type: AlertType
    severity: Severity
    timestamp: str
    bssid: str | None
    ssid: str | None
    details: dict[str, Any] = field(default_factory=dict)
    simulated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-safe dict."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "details": self.details,
            "simulated": self.simulated,
        }


# ---------------------------------------------------------------------------
# Thresholds configuration
# ---------------------------------------------------------------------------

@dataclass
class WIDSThresholds:
    """Configurable detection thresholds.

    Args:
        deauth_per_second: Deauth frames per second before triggering alert.
        beacon_flood_per_second: Distinct beaconing SSIDs per second.
        probe_per_second: Probe frames per second per source MAC.
        disassoc_per_second: Disassoc frames per second before alert.
        channel_hop_window_seconds: Time window for channel-hop detection.
        channel_hop_count: Min channel changes in window to trigger alert.
        rate_window_seconds: Sliding window duration for rate calculations.
    """
    deauth_per_second: float = 5.0
    beacon_flood_per_second: float = 20.0
    probe_per_second: float = 10.0
    disassoc_per_second: float = 5.0
    channel_hop_window_seconds: float = 30.0
    channel_hop_count: int = 5
    rate_window_seconds: float = 5.0


# ---------------------------------------------------------------------------
# Rate tracker using sliding time window
# ---------------------------------------------------------------------------

class _RateCounter:
    """Sliding-window event rate tracker."""

    def __init__(self, window: float = 5.0) -> None:
        self._window = window
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def record(self) -> float:
        """Record an event and return the current rate (events/sec)."""
        now = time.monotonic()
        with self._lock:
            self._events.append(now)
            cutoff = now - self._window
            while self._events and self._events[0] < cutoff:
                self._events.popleft()
            return len(self._events) / self._window


# ---------------------------------------------------------------------------
# Wireless IDS main class
# ---------------------------------------------------------------------------

