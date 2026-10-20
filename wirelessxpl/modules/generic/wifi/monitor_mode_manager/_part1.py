#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Native wireless interface monitor mode manager.

Manages switching between managed and monitor modes without depending
on airmon-ng. Uses iw/ip link/rfkill via subprocess.

Features:
  - Enable/disable monitor mode via 'iw dev <iface> set type monitor'
  - Kill conflicting processes (NetworkManager, wpa_supplicant, dhclient)
  - rfkill check and unblock
  - Channel hopping in background thread
  - Injection capability detection via test frame
  - Context manager support (with MonitorModeManager(...) as iface:)

Note: Some APs advertise a channel in their beacon frames but operate at a
slightly different frequency (channel drift/mismatch). If scan reports ch3 but
capture or injection fails, try adjacent channels (ch4, ch2). Use
`iw dev <iface> scan` to confirm the actual operating frequency of the AP.

OS requirement: Linux only.

Version: 1.0.0
"""


import logging
import re
import shutil
import subprocess
import threading
import time
from typing import Dict, List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

# Legacy: processes that conflict with monitor mode (only used as fallback
# when nmcli is unavailable). Killing these globally drops ALL wifi connections;
# prefer _unmanage_interface() which targets only the specific interface.
_CONFLICTING_PROCESSES = (
    "wpa_supplicant",
    "dhclient",
    "dhcpcd",
)

# Channels grouped by regulatory band (2.4 GHz and 5 GHz common set).
CHANNELS_2GHZ: list[int] = list(range(1, 14))
CHANNELS_5GHZ: list[int] = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 149, 153, 157, 161]
CHANNELS_ALL: list[int] = CHANNELS_2GHZ + CHANNELS_5GHZ


def _run(
    cmd: list[str],
    capture: bool = False,
    timeout: int = 10,
) -> str | None:
    """Execute a shell command safely without shell=True.

    Args:
        cmd: Command and arguments as a list of strings.
        capture: If True, return stdout; otherwise return None.
        timeout: Maximum seconds to wait for the process.

    Returns:
        Decoded stdout string when capture is True, else None.
    """
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        if capture:
            return result.stdout.decode("utf-8", errors="replace")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("Command %s failed: %s", cmd[0], exc)
    return None


# ---------------------------------------------------------------------------
# MonitorModeManager
# ---------------------------------------------------------------------------


class MonitorModeManager:
    """Manage 802.11 interface monitor mode without airmon-ng.

    Provides enable/disable of monitor mode, channel control, channel
    hopping in a daemon thread, injection testing, and context manager
    support for use in with-statements.

    Example:
        with MonitorModeManager("wlan0") as mon_iface:
            # mon_iface is "wlan0" in monitor mode
            do_injection(mon_iface)
        # managed mode restored on exit
    """

    def __init__(
        self,
        interface: str,
        kill_processes: bool = True,
    ) -> None:
        """Initialize with the target wireless interface.

        Args:
            interface: Wireless interface name (e.g. "wlan0").
            kill_processes: If True, kill conflicting processes before
                enabling monitor mode.
        """
        self._interface = interface
        self._kill_processes = kill_processes
        self._monitor_iface: str | None = None
        self._hop_thread: threading.Thread | None = None
        self._hop_stop = threading.Event()
        self._enabled: bool = False

    # ------------------------------------------------------------------
    # rfkill helpers
    # ------------------------------------------------------------------

    def _rfkill_unblock(self) -> None:
        """Attempt to unblock wifi via rfkill if the tool is available."""
        if shutil.which("rfkill"):
            _run(["rfkill", "unblock", "wifi"])
            logger.debug("rfkill unblock wifi executed")

    # ------------------------------------------------------------------
    # Process management
    # ------------------------------------------------------------------

    def _unmanage_interface(self) -> None:
        """Remove this interface from NetworkManager control only.

        Preferred over killing NM/wpa_supplicant globally because it
        leaves all other interfaces (including the internet connection)
        intact. Falls back to killing wpa_supplicant/dhclient for this
        interface only when nmcli is unavailable.
        """
        if shutil.which("nmcli"):
            _run(["nmcli", "device", "set", self._interface, "managed", "no"])
            logger.info("nmcli: %s set to unmanaged (NM still running)", self._interface)
            time.sleep(0.3)
            return
        # Fallback: kill only dhclient/wpa_supplicant bound to this iface.
        for proc in _CONFLICTING_PROCESSES:
            if shutil.which("pkill"):
                _run(["pkill", "-f", f"{proc}.*{self._interface}"])
        time.sleep(0.3)

    def _remanage_interface(self) -> None:
        """Return this interface to NetworkManager management after disable()."""
        if shutil.which("nmcli"):
            _run(["nmcli", "device", "set", self._interface, "managed", "yes"])
            logger.info("nmcli: %s returned to managed", self._interface)

    def _kill_conflicting(self) -> None:
        """Compatibility shim: delegate to _unmanage_interface."""
        self._unmanage_interface()

    # ------------------------------------------------------------------
    # Mode switching
    # ------------------------------------------------------------------

    def enable(self) -> str:
        """Enable monitor mode on the interface.

        Attempts 'iw dev <iface> set type monitor' first, then falls back
        to 'iwconfig <iface> mode monitor'. Brings the interface down
        before the mode change and back up afterward.

        Returns:
            Monitor interface name (same as the input interface name when
            using iw; may vary with legacy iwconfig).

        Raises:
            RuntimeError: If neither iw nor iwconfig can switch the mode.
        """
        if self._enabled:
            logger.debug("Monitor mode already enabled on %s", self._monitor_iface)
            return self._monitor_iface or self._interface

        self._rfkill_unblock()

        if self._kill_processes:
            self._unmanage_interface()

        _run(["ip", "link", "set", self._interface, "down"])

        switched = False

        if shutil.which("iw"):
            out = _run(
                ["iw", "dev", self._interface, "set", "type", "monitor"],
                capture=True,
            )
            if out is not None:
                switched = True
                logger.info("iw: interface %s set to monitor mode", self._interface)

        if not switched and shutil.which("iwconfig"):
            _run(["iwconfig", self._interface, "mode", "monitor"])
            switched = True
            logger.info("iwconfig fallback: interface %s set to monitor mode", self._interface)

        if not switched:
            raise RuntimeError(
                "Neither iw nor iwconfig found. "
                "Install iw (apt install iw) or wireless-tools."
            )

        _run(["ip", "link", "set", self._interface, "up"])

        self._monitor_iface = self._interface
        self._enabled = True
        logger.info("Monitor mode enabled on %s", self._monitor_iface)
        return self._monitor_iface

    def disable(self) -> None:
        """Restore managed mode on the interface.

        Uses 'iw dev <iface> set type managed' or 'iwconfig managed'
        as fallback.
        """
        if not self._enabled:
            return

        self.stop_hop()

        iface = self._monitor_iface or self._interface
        _run(["ip", "link", "set", iface, "down"])

        if shutil.which("iw"):
            _run(["iw", "dev", iface, "set", "type", "managed"])
        elif shutil.which("iwconfig"):
            _run(["iwconfig", iface, "mode", "managed"])

        _run(["ip", "link", "set", iface, "up"])

        self._enabled = False
        self._monitor_iface = None
        self._remanage_interface()
        logger.info("Interface %s restored to managed mode", iface)

    # ------------------------------------------------------------------
    # Channel control
    # ------------------------------------------------------------------

    def set_channel(self, channel: int) -> None:
        """Set the operating channel on the monitor interface.

        Args:
            channel: 802.11 channel number (1-14 for 2.4 GHz, UNII
                channels for 5 GHz).
        """
        iface = self._monitor_iface or self._interface
        if shutil.which("iw"):
            _run(["iw", "dev", iface, "set", "channel", str(channel)])
        elif shutil.which("iwconfig"):
            _run(["iwconfig", iface, "channel", str(channel)])
        logger.debug("Channel set to %d on %s", channel, iface)

    def start_hop(
        self,
        channels: list[int],
        interval_s: float = 0.5,
    ) -> None:
        """Start cycling through channels in a daemon thread.

        Args:
            channels: Ordered list of channel numbers to cycle through.
            interval_s: Dwell time per channel in seconds.
        """
        if not channels:
            raise ValueError("channels list must not be empty")

        if self._hop_thread and self._hop_thread.is_alive():
            logger.debug("Channel hopper already running; ignoring start_hop call")
            return

        self._hop_stop.clear()

        def _hop_loop() -> None:
            idx = 0
            while not self._hop_stop.is_set():
                self.set_channel(channels[idx % len(channels)])
                idx += 1
                self._hop_stop.wait(timeout=interval_s)

        self._hop_thread = threading.Thread(
            target=_hop_loop,
            daemon=True,
            name="ChanHop",
        )
        self._hop_thread.start()
        logger.info(
            "Channel hopper started (%d channels, %.1fs interval)",
            len(channels),
            interval_s,
        )

    def stop_hop(self) -> None:
        """Stop the channel hopping thread if active."""
        self._hop_stop.set()
        if self._hop_thread and self._hop_thread.is_alive():
            self._hop_thread.join(timeout=3.0)
        self._hop_thread = None
        logger.debug("Channel hopper stopped")

    # ------------------------------------------------------------------
    # Injection capability detection
    # ------------------------------------------------------------------

    def check_injection(self) -> bool:
        """Attempt to inject a test frame and verify it was sent.

        Sends a single RadioTap/Dot11 probe-request frame via Scapy
        and treats a clean return (no exception) as confirmation that
        the driver supports frame injection.

        Returns:
            True if a test frame was injected without error, False otherwise.
        """
        iface = self._monitor_iface or self._interface

        try:
            from scapy.all import Dot11, Dot11Elt, Dot11ProbeReq, RadioTap, sendp  # type: ignore[import-untyped]
        except ImportError:
            logger.warning("Scapy not available; cannot verify injection capability")
            return False

        try:
            test_frame = (
                RadioTap()
                / Dot11(
                    type=0,
                    subtype=4,
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2="00:11:22:33:44:55",
                    addr3="ff:ff:ff:ff:ff:ff",
                )
                / Dot11ProbeReq()
                / Dot11Elt(ID=0, info=b"wxf-inject-test")
            )
            sendp(
                test_frame,
                iface=iface,
                count=1,
                verbose=False,
            )
            logger.info("Injection test succeeded on %s", iface)
            return True
        except Exception as exc:
            logger.debug("Injection test failed on %s: %s", iface, exc)
            return False

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> str:
        """Enable monitor mode and return the monitor interface name.

        Returns:
            Monitor interface name for use inside the with-block.
        """
        return self.enable()

    def __exit__(self, *args: object) -> None:
        """Restore managed mode on context exit."""
        self.disable()

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def get_interfaces() -> list[dict[str, str]]:
        """List available wireless interfaces and their current mode.

        Parses the output of 'iw dev' to discover phy/interface tuples
        and the current type (managed, monitor, etc.).

        Returns:
            List of dicts, each with keys: interface, phy, type, addr.
            Returns an empty list when iw is not available or fails.
        """
        iw = shutil.which("iw")
        if not iw:
            return []

        raw = _run([iw, "dev"], capture=True)
        if not raw:
            return []

        results: list[dict[str, str]] = []
        current_phy = ""
        current: dict[str, str] = {}

        for line in raw.splitlines():
            stripped = line.strip()

            phy_match = re.match(r"^(phy#\d+)$", stripped)
            if phy_match:
                if current.get("interface"):
                    results.append(current)
                current_phy = phy_match.group(1)
                current = {"phy": current_phy, "interface": "", "type": "", "addr": ""}
                continue

            iface_match = re.match(r"^Interface\s+(\S+)$", stripped)
            if iface_match:
                if current.get("interface"):
                    results.append(current)
                current = {"phy": current_phy, "interface": iface_match.group(1), "type": "", "addr": ""}
                continue

            type_match = re.match(r"^type\s+(\S+)$", stripped)
            if type_match:
                current["type"] = type_match.group(1)
                continue

            addr_match = re.match(r"^addr\s+([0-9a-f:]{17})$", stripped)
            if addr_match:
                current["addr"] = addr_match.group(1)

        if current.get("interface"):
            results.append(current)

        return results


# ---------------------------------------------------------------------------
# Exploit class
# ---------------------------------------------------------------------------


@requires_os(OSRequirement.LINUX_ONLY)
