"""Intelligent WiFi channel hopper with park-on-channel support.

Provides hot-swappable channel plan, intelligent hopping during
scanning, and the ability to park on a specific channel during
active attacks (deauth, handshake capture).

Conceptual reference: airgorah scan.rs (MIT, martin-olivier)
Recode: full Python rewrite, no code copied.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import logging
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Sequence

logger = logging.getLogger(__name__)

CHANNELS_2GHZ = list(range(1, 15))
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
CHANNELS_6GHZ = [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93]


@dataclass
class HopperState:
    current_channel: int = 0
    is_parked: bool = False
    parked_channel: int = 0
    hop_count: int = 0
    errors: int = 0
    is_running: bool = False


class ChannelHopper:
    """Channel hopper with hot-swap and park capabilities."""

    def __init__(
        self,
        interface: str,
        channels: Optional[Sequence[int]] = None,
        dwell_time: float = 0.3,
    ) -> None:
        self.interface = interface
        self.channels = list(channels or CHANNELS_2GHZ + CHANNELS_5GHZ)
        self.dwell_time = dwell_time
        self._state = HopperState()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._on_hop: Optional[Callable[[int], None]] = None

    @property
    def state(self) -> HopperState:
        return self._state

    def set_channel(self, channel: int) -> bool:
        """Set the interface to a specific channel using iw or sysfs."""
        success = self._try_sysfs(channel) or self._try_iw(channel)
        if success:
            self._state.current_channel = channel
        else:
            self._state.errors += 1
        return success

    def _try_sysfs(self, channel: int) -> bool:
        freq = _channel_to_freq(channel)
        if not freq:
            return False
        phy_path = Path(f"/sys/class/net/{self.interface}/phy80211/name")
        if not phy_path.exists():
            return False
        try:
            phy = phy_path.read_text().strip()
            proc = subprocess.run(
                ["iw", "phy", phy, "set", "freq", str(freq)],
                capture_output=True,
                timeout=5,
            )
            return proc.returncode == 0
        except Exception:
            return False

    def _try_iw(self, channel: int) -> bool:
        try:
            proc = subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                capture_output=True,
                timeout=5,
            )
            return proc.returncode == 0
        except Exception:
            return False

    def start(self, on_hop: Optional[Callable[[int], None]] = None) -> None:
        """Start channel hopping in a background thread."""
        if self._state.is_running:
            return

        self._on_hop = on_hop
        self._stop_event.clear()
        self._state.is_running = True
        self._thread = threading.Thread(target=self._hop_loop, daemon=True)
        self._thread.start()
        logger.info("Channel hopper started on %s (%d channels)", self.interface, len(self.channels))

    def stop(self) -> None:
        """Stop channel hopping."""
        self._stop_event.set()
        self._state.is_running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Channel hopper stopped (hops: %d)", self._state.hop_count)

    def park(self, channel: int) -> bool:
        """Park on a specific channel (stop hopping, stay on channel)."""
        with self._lock:
            if self.set_channel(channel):
                self._state.is_parked = True
                self._state.parked_channel = channel
                logger.info("Parked on channel %d", channel)
                return True
            return False

    def unpark(self) -> None:
        """Resume channel hopping."""
        with self._lock:
            self._state.is_parked = False
            self._state.parked_channel = 0
            logger.info("Unparked, resuming hop cycle")

    def update_channels(self, channels: Sequence[int]) -> None:
        """Hot-swap the channel plan without stopping."""
        with self._lock:
            self.channels = list(channels)
            logger.info("Channel plan updated: %d channels", len(self.channels))

    def _hop_loop(self) -> None:
        idx = 0
        while not self._stop_event.is_set():
            with self._lock:
                if self._state.is_parked:
                    self._stop_event.wait(self.dwell_time)
                    continue

                if not self.channels:
                    self._stop_event.wait(1.0)
                    continue

                channel = self.channels[idx % len(self.channels)]
                idx += 1

            if self.set_channel(channel):
                self._state.hop_count += 1
                if self._on_hop:
                    try:
                        self._on_hop(channel)
                    except Exception:
                        pass

            self._stop_event.wait(self.dwell_time)


def _channel_to_freq(channel: int) -> Optional[int]:
    if 1 <= channel <= 14:
        if channel == 14:
            return 2484
        return 2407 + channel * 5
    if 36 <= channel <= 165:
        return 5000 + channel * 5
    return None


def get_supported_channels(interface: str) -> List[int]:
    """Query supported channels from iw."""
    channels = []
    try:
        proc = subprocess.run(
            ["iw", "phy"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        import re
        for match in re.finditer(r"\*\s+(\d+)\s+MHz\s+\[(\d+)\]", proc.stdout):
            ch = int(match.group(2))
            channels.append(ch)
    except Exception as exc:
        logger.debug("Failed to query channels: %s", exc)
    return channels or CHANNELS_2GHZ
