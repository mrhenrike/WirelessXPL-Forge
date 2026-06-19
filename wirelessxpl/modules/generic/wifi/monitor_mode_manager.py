#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Native wireless interface monitor mode manager.

Manages switching between managed and monitor modes without depending
on airmon-ng. Implements process cleanup, rfkill management, channel
hopping, and injection capability detection.

OS requirement: Linux only (iw, ip link, /sys/class/net/).

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from types import TracebackType
from typing import Dict, List, Optional, Tuple, Type

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

# Processes known to conflict with monitor mode or raw socket capture
_CONFLICTING_PROCS: Tuple[str, ...] = (
    "NetworkManager",
    "wpa_supplicant",
    "wpa_cli",
    "dhclient",
    "dhcpcd",
    "avahi-daemon",
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run_cmd(
    cmd: List[str],
    check: bool = False,
    timeout: int = 10,
) -> "subprocess.CompletedProcess[str]":
    """Execute a command safely without shell interpolation.

    Args:
        cmd: Command and arguments (no shell=True).
        check: If True, raise CalledProcessError on non-zero exit.
        timeout: Maximum execution time in seconds.

    Returns:
        CompletedProcess with stdout, stderr, and returncode attributes.

    Raises:
        subprocess.CalledProcessError: When check=True and exit code is nonzero.
        FileNotFoundError: When the command binary is not found.
        subprocess.TimeoutExpired: When the command exceeds timeout.
    """
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def _iface_exists(iface: str) -> bool:
    """Check whether a network interface exists in /sys/class/net/.

    Args:
        iface: Interface name to check.

    Returns:
        True if the interface directory exists.
    """
    return os.path.exists(f"/sys/class/net/{iface}")


def _iface_mode(iface: str) -> Optional[str]:
    """Return the current wireless mode for an interface.

    Args:
        iface: Interface name.

    Returns:
        Mode string (e.g. "managed", "monitor") or None if not determinable.
    """
    try:
        result = _run_cmd(["iw", "dev", iface, "info"], timeout=5)
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("type "):
                return stripped.split(None, 1)[1].strip()
    except Exception as exc:
        logger.debug("iface_mode: iw failed for %s: %s", iface, exc)
    return None


def _parse_iw_dev_interfaces() -> List[Tuple[str, str]]:
    """Parse 'iw dev' output and return (interface_name, type) pairs.

    Returns:
        List of (name, type) tuples for all interfaces reported by iw dev.
    """
    pairs: List[Tuple[str, str]] = []
    try:
        result = _run_cmd(["iw", "dev"], timeout=5)
        current_iface: Optional[str] = None
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Interface "):
                current_iface = stripped.split(None, 1)[1].strip()
            elif stripped.startswith("type ") and current_iface:
                iface_type = stripped.split(None, 1)[1].strip()
                pairs.append((current_iface, iface_type))
                current_iface = None
    except Exception as exc:
        logger.debug("_parse_iw_dev_interfaces failed: %s", exc)
    return pairs


# ---------------------------------------------------------------------------
# MonitorModeManager
# ---------------------------------------------------------------------------


class MonitorModeManager:
    """Context manager for enabling and restoring wireless monitor mode.

    Enables monitor mode on the specified interface, yields the monitor
    interface name, and restores managed mode on exit - even if an
    exception occurred.

    Usage as context manager::

        with MonitorModeManager("wlan0") as mon_iface:
            # mon_iface is e.g. "wlan0mon" or "wlan0"
            do_capture(mon_iface)

    Usage as standalone object::

        mgr = MonitorModeManager("wlan0")
        mon_iface = mgr.enable()
        mgr.start_hop([1, 6, 11], interval=0.5)
        time.sleep(30)
        mgr.disable()

    Args:
        interface: Wireless interface name (e.g. "wlan0").
        kill_processes: If True, send SIGTERM+SIGKILL to processes that
            conflict with monitor mode before switching.
        rfkill_unblock: If True, check rfkill and unblock wifi if
            soft-blocked.
        restore_on_exit: If True, restore managed mode in __exit__ or
            disable(). Set to False to keep monitor mode after the
            context block ends.
    """

    def __init__(
        self,
        interface: str,
        kill_processes: bool = True,
        rfkill_unblock: bool = True,
        restore_on_exit: bool = True,
    ) -> None:
        self._interface = interface
        self._kill_processes = kill_processes
        self._rfkill_unblock = rfkill_unblock
        self._restore_on_exit = restore_on_exit
        self._monitor_iface: Optional[str] = None
        self._hop_thread: Optional[threading.Thread] = None
        self._hop_stop = threading.Event()

    # ------------------------------------------------------------------
    # Context manager protocol
    # ------------------------------------------------------------------

    def __enter__(self) -> str:
        """Enable monitor mode and return the monitor interface name.

        Returns:
            Monitor interface name (e.g. "wlan0mon" or "wlan0").

        Raises:
            RuntimeError: If monitor mode could not be enabled.
        """
        self._monitor_iface = self.enable()
        return self._monitor_iface

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> bool:
        """Restore managed mode unconditionally.

        Returns:
            False - exceptions from the body are not suppressed.
        """
        if self._restore_on_exit:
            try:
                self.disable()
            except Exception as exc:
                logger.warning(
                    "Failed to restore managed mode on %s: %s",
                    self._interface,
                    exc,
                )
        return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enable(self) -> str:
        """Enable monitor mode on the configured interface.

        The method follows this sequence:
          1. Optionally kill conflicting processes.
          2. Optionally unblock via rfkill.
          3. Bring the interface down.
          4. Switch mode with iw (falls back to iwconfig).
          5. Bring the interface up.
          6. Detect the resulting monitor interface name.
          7. Verify monitor mode is active.

        Returns:
            Monitor interface name.

        Raises:
            RuntimeError: If monitor mode could not be confirmed.
        """
        if self._kill_processes:
            self._kill_conflicting_processes()

        if self._rfkill_unblock:
            self._rfkill_check_unblock()

        monitor_iface = self._set_monitor_mode()
        self._monitor_iface = monitor_iface
        logger.info(
            "Monitor mode enabled: %s -> %s", self._interface, monitor_iface
        )
        return monitor_iface

    def disable(self) -> None:
        """Restore managed mode and stop channel hopping.

        Safe to call multiple times; subsequent calls after the interface
        has already been restored are no-ops.
        """
        self.stop_hop()
        iface = self._monitor_iface or self._interface
        self._restore_managed_mode(iface)
        self._monitor_iface = None

    def set_channel(self, channel: int) -> bool:
        """Set the wireless channel on the monitor interface.

        Args:
            channel: 802.11 channel number (e.g. 1-14 for 2.4 GHz).

        Returns:
            True if the channel was set successfully.
        """
        mon = self._monitor_iface
        if not mon:
            logger.warning("set_channel called but monitor mode is not active")
            return False
        result = _run_cmd(
            ["iw", "dev", mon, "set", "channel", str(channel)],
            timeout=5,
        )
        if result.returncode == 0:
            logger.debug("Channel set to %d on %s", channel, mon)
            return True
        logger.debug(
            "set_channel %d on %s failed: %s", channel, mon, result.stderr.strip()
        )
        return False

    def start_hop(
        self, channels: List[int], interval: float = 0.5
    ) -> None:
        """Start background channel hopping across the given list.

        Any existing hop thread is stopped before starting a new one.

        Args:
            channels: Ordered list of channel numbers to cycle through.
            interval: Dwell time on each channel in seconds.
        """
        if not channels:
            logger.warning("start_hop called with empty channel list")
            return

        self.stop_hop()
        self._hop_stop.clear()
        self._hop_thread = threading.Thread(
            target=self._hop_loop,
            args=(list(channels), float(interval)),
            daemon=True,
            name="channel-hop",
        )
        self._hop_thread.start()
        logger.info(
            "Channel hopping started: %s (%.2fs interval)", channels, interval
        )

    def stop_hop(self) -> None:
        """Stop channel hopping and wait for the hop thread to exit."""
        if self._hop_thread and self._hop_thread.is_alive():
            self._hop_stop.set()
            self._hop_thread.join(timeout=3.0)
        self._hop_thread = None
        self._hop_stop.clear()

    def detect_injection(self) -> bool:
        """Test whether the monitor interface supports packet injection.

        Sends a single crafted Dot11 frame using Scapy. Success means the
        driver accepted the frame for transmission (injection-capable).
        This does not guarantee frames are visible on the air.

        Returns:
            True if injection was accepted by the driver, False otherwise.
        """
        mon = self._monitor_iface
        if not mon:
            logger.warning("detect_injection called but monitor mode is not active")
            return False

        try:
            from scapy.all import Dot11, Dot11ProbeReq, RadioTap, sendp  # noqa: PLC0415

            test_frame = (
                RadioTap()
                / Dot11(
                    type=0,
                    subtype=4,
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2="02:00:00:00:00:01",
                    addr3="ff:ff:ff:ff:ff:ff",
                )
                / Dot11ProbeReq()
            )
            sendp(
                test_frame,
                iface=mon,
                count=1,
                verbose=False,
                timeout=3,
            )
            logger.info("Injection test passed on %s", mon)
            return True
        except Exception as exc:
            logger.info("Injection test failed on %s: %s", mon, exc)
            return False

    def status(self) -> Dict[str, object]:
        """Return the current state as a dict.

        Returns:
            Dict with keys: interface, monitor_iface, mode, hopping.
        """
        mode = _iface_mode(self._monitor_iface or self._interface)
        return {
            "interface": self._interface,
            "monitor_iface": self._monitor_iface,
            "mode": mode or "unknown",
            "hopping": bool(
                self._hop_thread and self._hop_thread.is_alive()
            ),
        }

    # ------------------------------------------------------------------
    # Internal implementation
    # ------------------------------------------------------------------

    def _kill_conflicting_processes(self) -> None:
        """Send SIGTERM then SIGKILL to processes that block monitor mode."""
        for proc_name in _CONFLICTING_PROCS:
            _run_cmd(["pkill", "-TERM", proc_name], timeout=5)

        # Give processes a moment to exit gracefully
        time.sleep(0.5)

        for proc_name in _CONFLICTING_PROCS:
            _run_cmd(["pkill", "-KILL", proc_name], timeout=5)

        logger.info("Killed conflicting wireless management processes")

    def _rfkill_check_unblock(self) -> None:
        """Unblock the wifi radio via rfkill if it is soft-blocked."""
        try:
            result = _run_cmd(["rfkill", "list", "wifi"], timeout=5)
            if "Soft blocked: yes" in result.stdout:
                _run_cmd(["rfkill", "unblock", "wifi"], timeout=5)
                time.sleep(0.3)
                logger.info("rfkill: unblocked wifi")
            else:
                logger.debug("rfkill: wifi not soft-blocked")
        except FileNotFoundError:
            logger.debug("rfkill not found; skipping")
        except Exception as exc:
            logger.debug("rfkill check error: %s", exc)

    def _set_monitor_mode(self) -> str:
        """Perform the actual monitor mode transition.

        Attempts in order:
          1. iw dev <iface> set type monitor
          2. iwconfig <iface> mode monitor (legacy fallback)

        Returns:
            Detected monitor interface name.

        Raises:
            RuntimeError: If monitor mode cannot be confirmed.
        """
        iface = self._interface

        # Bring interface down before changing mode
        _run_cmd(["ip", "link", "set", iface, "down"], timeout=5)

        # Primary method: iw
        result = _run_cmd(
            ["iw", "dev", iface, "set", "type", "monitor"], timeout=10
        )
        if result.returncode != 0:
            logger.debug(
                "iw set type monitor failed (rc=%d): %s",
                result.returncode,
                result.stderr.strip(),
            )
            # Fallback: iwconfig
            r2 = _run_cmd(
                ["iwconfig", iface, "mode", "monitor"], timeout=10
            )
            if r2.returncode != 0:
                logger.debug(
                    "iwconfig mode monitor also failed (rc=%d): %s",
                    r2.returncode,
                    r2.stderr.strip(),
                )

        # Bring interface back up
        _run_cmd(["ip", "link", "set", iface, "up"], timeout=5)

        # Brief wait for the kernel to update the interface state
        time.sleep(0.5)

        monitor_iface = self._detect_monitor_iface(iface)

        if not self._verify_monitor_mode(monitor_iface):
            raise RuntimeError(
                f"Monitor mode not active on {monitor_iface} after switch attempt. "
                "Ensure the adapter supports monitor mode and run as root."
            )

        return monitor_iface

    def _detect_monitor_iface(self, base_iface: str) -> str:
        """Discover the monitor-mode interface name after mode switch.

        Some drivers rename the interface (e.g. wlan0 -> wlan0mon).
        This method parses 'iw dev' to find any interface now in monitor
        mode that is associated with the same physical radio.

        Args:
            base_iface: Original interface name before mode switch.

        Returns:
            Monitor interface name, falling back to base_iface if
            detection fails.
        """
        pairs = _parse_iw_dev_interfaces()
        monitor_ifaces = [name for name, t in pairs if t == "monitor"]

        if not monitor_ifaces:
            # iw found nothing in monitor; try common naming patterns
            for candidate in (base_iface + "mon", base_iface):
                if _iface_exists(candidate):
                    return candidate
            return base_iface

        # Prefer exact match or <base>mon, then any monitor iface
        for name in monitor_ifaces:
            if name == base_iface or name == base_iface + "mon":
                return name
            if name.startswith(base_iface):
                return name

        # Return the first monitor interface found
        return monitor_ifaces[0]

    def _verify_monitor_mode(self, iface: str) -> bool:
        """Confirm that an interface is currently in monitor mode.

        Args:
            iface: Interface name to check.

        Returns:
            True if the interface is confirmed in monitor mode.
        """
        mode = _iface_mode(iface)
        if mode == "monitor":
            return True

        # Secondary check via iwconfig output
        try:
            result = _run_cmd(["iwconfig", iface], timeout=5)
            return "Mode:Monitor" in result.stdout
        except Exception:
            return False

    def _restore_managed_mode(self, iface: str) -> None:
        """Restore an interface to managed mode.

        Args:
            iface: Interface name to restore (may be the monitor name).
        """
        if not _iface_exists(iface):
            logger.debug("restore_managed_mode: %s does not exist, skipping", iface)
            return

        _run_cmd(["ip", "link", "set", iface, "down"], timeout=5)

        result = _run_cmd(
            ["iw", "dev", iface, "set", "type", "managed"], timeout=10
        )
        if result.returncode != 0:
            logger.debug(
                "iw set type managed failed; trying iwconfig: %s",
                result.stderr.strip(),
            )
            _run_cmd(["iwconfig", iface, "mode", "managed"], timeout=10)

        _run_cmd(["ip", "link", "set", iface, "up"], timeout=5)
        logger.info("Interface %s restored to managed mode", iface)

    def _hop_loop(self, channels: List[int], interval: float) -> None:
        """Background loop for channel hopping.

        Args:
            channels: List of channel numbers to cycle through.
            interval: Dwell time per channel in seconds.
        """
        idx = 0
        while not self._hop_stop.is_set():
            ch = channels[idx % len(channels)]
            self.set_channel(ch)
            idx += 1
            self._hop_stop.wait(timeout=interval)


# ---------------------------------------------------------------------------
# WXF Exploit class
# ---------------------------------------------------------------------------


class Exploit(Exploit):
    """Native wireless monitor mode management without airmon-ng."""

    __info__ = {
        "name": "Monitor Mode Manager",
        "description": (
            "Native wireless monitor mode management without airmon-ng. "
            "Handles interface mode transitions, conflicting process cleanup, "
            "rfkill management, channel hopping, and packet injection "
            "capability detection. Works with any nl80211 driver."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://wireless.wiki.kernel.org/en/users/Documentation/iw",
            "https://www.kernel.org/doc/html/latest/driver-api/rfkill.html",
        ),
        "devices": ("wifi", "802.11"),
    }

    mode = OptString(
        "status",
        "Mode: enable | disable | status | channel | hop | inject_test",
    )
    interface = OptString("wlan0", "Wireless interface name (e.g. wlan0)")
    channel = OptInteger(6, "Channel to set (mode=channel)")
    hop_channels = OptString(
        "1,6,11",
        "Comma-separated channel list for mode=hop",
    )
    hop_interval = OptFloat(0.5, "Dwell time per channel in seconds")
    kill_procs = OptBool(
        True,
        "Kill NetworkManager/wpa_supplicant/dhclient before enabling",
    )
    rfkill_unblock = OptBool(
        True,
        "Unblock wifi via rfkill if soft-blocked",
    )
    restore_on_exit = OptBool(
        True,
        "Restore managed mode after disable or CLI exit",
    )
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    def _get_manager(self) -> MonitorModeManager:
        """Build a MonitorModeManager from current option values.

        Returns:
            Configured MonitorModeManager instance.
        """
        return MonitorModeManager(
            interface=str(self.interface).strip(),
            kill_processes=bool(self.kill_procs),
            rfkill_unblock=bool(self.rfkill_unblock),
            restore_on_exit=bool(self.restore_on_exit),
        )

    def check(self) -> str:
        """Check interface existence and current wireless mode."""
        iface = str(self.interface).strip()
        if not _iface_exists(iface):
            return f"Interface {iface} not found in /sys/class/net/"
        mode = _iface_mode(iface)
        pairs = _parse_iw_dev_interfaces()
        monitor_count = sum(1 for _, t in pairs if t == "monitor")
        return (
            f"Interface {iface}: mode={mode or 'unknown'} | "
            f"monitor interfaces detected={monitor_count}"
        )

    def run(self) -> None:
        """Entry point dispatched by the WXF CLI."""
        op = str(self.mode).strip().lower()
        iface = str(self.interface).strip()

        if op == "status":
            print_info(self.check())
            pairs = _parse_iw_dev_interfaces()
            for name, iface_type in pairs:
                print_info(f"  {name:20s} type={iface_type}")
            return

        if op == "info":
            self._info()
            return

        if not bool(self.i_know_scope):
            print_error("Set i_know_scope = true to confirm authorized lab.")
            return
        require_authorised_lab()

        if not iface:
            print_error("Set interface (e.g. set interface wlan0).")
            return

        if op == "enable":
            self._do_enable(iface)
        elif op == "disable":
            self._do_disable(iface)
        elif op == "channel":
            self._do_channel(iface)
        elif op == "hop":
            self._do_hop(iface)
        elif op == "inject_test":
            self._do_inject_test(iface)
        else:
            print_error(
                f"Unknown mode: {op}. "
                "Valid: info, status, enable, disable, channel, hop, inject_test"
            )

    # ------------------------------------------------------------------
    # Mode handlers
    # ------------------------------------------------------------------

    def _info(self) -> None:
        """Print usage information."""
        print_info("Monitor Mode Manager")
        print_info("=" * 50)
        print_info("")
        print_info("Manages 802.11 monitor mode without airmon-ng.")
        print_info("")
        print_info("Modes:")
        print_info("  status       Show current interface modes")
        print_info("  enable       Switch interface to monitor mode")
        print_info("  disable      Restore managed mode")
        print_info("  channel      Set a fixed channel")
        print_info("  hop          Start channel hopping (Ctrl+C to stop)")
        print_info("  inject_test  Test packet injection capability")
        print_info("")
        print_info("Example - enable then hop:")
        print_info(
            "  set interface wlan0; set mode enable; "
            "set i_know_scope true; run"
        )
        print_info(
            "  set mode hop; set hop_channels 1,6,11; "
            "set hop_interval 0.5; run"
        )

    def _do_enable(self, iface: str) -> None:
        """Enable monitor mode.

        Args:
            iface: Wireless interface name.
        """
        print_status(f"Enabling monitor mode on {iface}...")
        mgr = self._get_manager()
        try:
            mon_iface = mgr.enable()
            print_success(f"Monitor mode active: {mon_iface}")
        except RuntimeError as exc:
            print_error(str(exc))

    def _do_disable(self, iface: str) -> None:
        """Restore managed mode.

        Args:
            iface: Wireless interface name.
        """
        print_status(f"Restoring managed mode on {iface}...")
        mgr = MonitorModeManager(interface=iface, restore_on_exit=False)
        # Determine current monitor iface name
        pairs = _parse_iw_dev_interfaces()
        for name, t in pairs:
            if t == "monitor" and (name == iface or name.startswith(iface)):
                mgr._monitor_iface = name  # noqa: SLF001
                break
        mgr.disable()
        print_success(f"Interface {iface} restored to managed mode.")

    def _do_channel(self, iface: str) -> None:
        """Set a fixed channel.

        Args:
            iface: Wireless interface name.
        """
        ch = int(self.channel)
        mgr = MonitorModeManager(interface=iface, restore_on_exit=False)
        mgr._monitor_iface = iface  # noqa: SLF001
        if mgr.set_channel(ch):
            print_success(f"Channel set to {ch} on {iface}.")
        else:
            print_error(
                f"Failed to set channel {ch} on {iface}. "
                "Verify monitor mode is active."
            )

    def _do_hop(self, iface: str) -> None:
        """Start channel hopping and block until Ctrl+C.

        Args:
            iface: Wireless interface name.
        """
        raw = str(self.hop_channels).strip()
        try:
            channels = [int(c.strip()) for c in raw.split(",") if c.strip()]
        except ValueError:
            print_error(f"Invalid hop_channels: {raw!r}. Use comma-separated integers.")
            return

        if not channels:
            print_error("hop_channels is empty.")
            return

        interval = float(self.hop_interval)
        mgr = MonitorModeManager(interface=iface, restore_on_exit=False)
        mgr._monitor_iface = iface  # noqa: SLF001

        print_status(
            f"Channel hopping on {iface}: {channels} ({interval:.2f}s interval). "
            "Ctrl+C to stop."
        )
        mgr.start_hop(channels, interval)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            mgr.stop_hop()
            print_info("Channel hopping stopped.")

    def _do_inject_test(self, iface: str) -> None:
        """Test packet injection capability.

        Args:
            iface: Wireless interface name.
        """
        print_status(f"Testing injection on {iface}...")
        mgr = MonitorModeManager(interface=iface, restore_on_exit=False)
        mgr._monitor_iface = iface  # noqa: SLF001
        ok = mgr.detect_injection()
        if ok:
            print_success(f"Injection: driver accepted the test frame on {iface}.")
        else:
            print_error(
                f"Injection test failed on {iface}. "
                "Ensure monitor mode is active and scapy is installed."
            )
