"""Global wireless interface registry for WirelessXPL-Forge.

Tracks which interfaces are assigned to which role (monitor/inject/ap/managed),
whether they provide the active internet connection, and handles NetworkManager
integration safely (only unmanages interfaces explicitly selected by the user).

Usage:
    from wirelessxpl.core.wifi.interface_registry import InterfaceRegistry
    reg = InterfaceRegistry.get()
    reg.assign("wlx44334cbe826b", role="monitor", channel=6)
    reg.release("wlx44334cbe826b")
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

ROLE_MONITOR = "monitor"
ROLE_INJECT  = "inject"
ROLE_AP      = "ap"
ROLE_MANAGED = "managed"
ROLE_IDLE    = "idle"

NM_CONF_PATH = "/etc/NetworkManager/conf.d/99-wxf-unmanaged.conf"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class InterfaceInfo:
    name: str
    phy: str
    mac: str
    driver: str
    current_mode: str       # monitor / managed / ap / etc
    provides_internet: bool # True if this iface has the default route
    nm_managed: bool        # True if NM is managing it
    bands: List[str]        # ["2.4GHz", "5GHz", "6GHz"]
    supports_monitor: bool
    supports_ap: bool
    supports_inject: bool
    role: str = ROLE_IDLE   # role assigned by WXF
    channel: Optional[int] = None


# ---------------------------------------------------------------------------
# Registry singleton
# ---------------------------------------------------------------------------

class InterfaceRegistry:
    """Singleton that tracks all wireless interfaces and their WXF assignments."""

    _instance: Optional["InterfaceRegistry"] = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self) -> None:
        self._interfaces: Dict[str, InterfaceInfo] = {}
        self._refresh_lock = threading.Lock()
        self.refresh()

    @classmethod
    def get(cls) -> "InterfaceRegistry":
        """Return the global singleton instance."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Re-scan all wireless interfaces from the OS."""
        with self._refresh_lock:
            self._interfaces.clear()
            default_gw_iface = self._default_gateway_iface()
            for info in self._enumerate_interfaces():
                info.provides_internet = (info.name == default_gw_iface)
                self._interfaces[info.name] = info
            logger.debug("InterfaceRegistry refreshed: %d interfaces", len(self._interfaces))

    def _run(self, cmd: List[str], timeout: int = 5) -> str:
        try:
            return subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, timeout=timeout
            ).decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _default_gateway_iface(self) -> str:
        """Return the interface name that carries the default route."""
        out = self._run(["ip", "route", "show", "default"])
        m = re.search(r"dev\s+(\S+)", out)
        return m.group(1) if m else ""

    def _enumerate_interfaces(self) -> List[InterfaceInfo]:
        iw_out = self._run(["iw", "dev"])
        if not iw_out:
            return []

        results: List[InterfaceInfo] = []
        current_phy = ""
        current_iface = ""
        current_addr = ""
        current_type = ""

        for line in iw_out.splitlines():
            s = line.strip()
            m = re.match(r"^(phy#\d+)$", s)
            if m:
                if current_iface:
                    results.append(self._build_info(
                        current_iface, current_phy, current_addr, current_type))
                current_phy = m.group(1)
                current_iface = current_addr = current_type = ""
                continue
            m = re.match(r"^Interface\s+(\S+)$", s)
            if m:
                if current_iface:
                    results.append(self._build_info(
                        current_iface, current_phy, current_addr, current_type))
                current_iface = m.group(1)
                current_addr = current_type = ""
                continue
            m = re.match(r"^addr\s+([0-9a-f:]{17})$", s)
            if m:
                current_addr = m.group(1)
            m = re.match(r"^type\s+(\S+)$", s)
            if m:
                current_type = m.group(1)

        if current_iface:
            results.append(self._build_info(
                current_iface, current_phy, current_addr, current_type))

        return [r for r in results if r is not None]

    def _build_info(self, name: str, phy: str, mac: str, mode: str) -> InterfaceInfo:
        driver = self._get_driver(name)
        phy_caps = self._phy_capabilities(phy)
        nm_managed = self._is_nm_managed(name)

        return InterfaceInfo(
            name=name,
            phy=phy,
            mac=mac,
            driver=driver,
            current_mode=mode,
            provides_internet=False,   # set by caller
            nm_managed=nm_managed,
            bands=phy_caps["bands"],
            supports_monitor=phy_caps["monitor"],
            supports_ap=phy_caps["ap"],
            supports_inject=phy_caps["inject"],
        )

    def _get_driver(self, iface: str) -> str:
        out = self._run(["ethtool", "-i", iface])
        m = re.search(r"^driver:\s+(\S+)", out, re.MULTILINE)
        return m.group(1) if m else "unknown"

    def _phy_capabilities(self, phy: str) -> dict:
        # iw dev reports "phy#4" but "iw phy" expects "phy4"
        phy_name = phy.replace("#", "")
        out = self._run(["iw", "phy", phy_name, "info"])
        # iw phy info uses tabs+spaces before "* <mode>" — use simple substring
        caps = {
            "monitor": "* monitor" in out,
            "ap":      "* AP" in out,
            "inject":  "* monitor" in out,  # if monitor works, injection works
            "bands":   [],
        }
        # Frequency-based band detection (MHz values in the output)
        if re.search(r"24\d\d\.?\d* MHz", out):
            caps["bands"].append("2.4GHz")
        if re.search(r"5[12]\d\d\.?\d* MHz", out):
            caps["bands"].append("5GHz")
        if re.search(r"59[5-9]\d\.?\d* MHz|60[0-9]\d\.?\d* MHz", out):
            caps["bands"].append("6GHz")
        return caps

    def _is_nm_managed(self, iface: str) -> bool:
        if not shutil.which("nmcli"):
            return False
        out = self._run(["nmcli", "-t", "-f", "DEVICE,STATE", "device", "status"])
        for line in out.splitlines():
            parts = line.split(":")
            if parts and parts[0] == iface:
                return parts[1] not in ("unmanaged", "não gerenciável")
        return False

    # ------------------------------------------------------------------
    # Role assignment
    # ------------------------------------------------------------------

    def assign(
        self,
        iface: str,
        role: str,
        channel: Optional[int] = None,
        force: bool = False,
    ) -> "InterfaceInfo":
        """Mark an interface for WXF use; configure NM if needed.

        Args:
            iface:   Wireless interface name.
            role:    One of ROLE_MONITOR / ROLE_INJECT / ROLE_AP / ROLE_MANAGED.
            channel: Optional channel to set after switching mode.
            force:   Skip internet-connection safety check (dangerous).

        Returns:
            Updated InterfaceInfo.

        Raises:
            ValueError: If the interface provides internet and force=False.
        """
        if iface not in self._interfaces:
            self.refresh()
        info = self._interfaces.get(iface)
        if info is None:
            raise KeyError(f"Interface {iface!r} not found")

        if info.provides_internet and not force:
            raise ValueError(
                f"Interface {iface} is currently providing the internet connection "
                f"(gateway interface). Selecting it for WXF use WILL drop your "
                f"connectivity. Re-call assign(..., force=True) if this is intentional."
            )

        # Unmanage from NetworkManager if needed
        if info.nm_managed and role in (ROLE_MONITOR, ROLE_INJECT):
            self._nm_unmanage(iface)
            info.nm_managed = False

        info.role = role
        info.channel = channel
        logger.info("Assigned %s -> role=%s ch=%s", iface, role, channel)
        return info

    def release(self, iface: str) -> None:
        """Return an interface to managed mode and re-add to NM."""
        info = self._interfaces.get(iface)
        if info is None:
            return
        if shutil.which("nmcli"):
            self._nm_remanage(iface)
            info.nm_managed = True
        info.role = ROLE_IDLE
        info.channel = None
        logger.info("Released %s back to managed/NM", iface)

    def release_all(self) -> None:
        """Release every interface that WXF assigned."""
        for name, info in list(self._interfaces.items()):
            if info.role != ROLE_IDLE:
                self.release(name)

    # ------------------------------------------------------------------
    # NetworkManager helpers
    # ------------------------------------------------------------------

    def _nm_unmanage(self, iface: str) -> None:
        if shutil.which("nmcli"):
            subprocess.run(
                ["nmcli", "device", "set", iface, "managed", "no"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            logger.debug("NM: set %s unmanaged", iface)

    def _nm_remanage(self, iface: str) -> None:
        if shutil.which("nmcli"):
            subprocess.run(
                ["nmcli", "device", "set", iface, "managed", "yes"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            logger.debug("NM: set %s managed", iface)

    def persist_nm_config(self, unmanaged_ifaces: Optional[List[str]] = None) -> bool:
        """Write /etc/NetworkManager/conf.d/99-wxf-unmanaged.conf.

        Args:
            unmanaged_ifaces: List of interface names to permanently unmanage.
                              If None, uses all currently WXF-assigned interfaces.

        Returns:
            True if written successfully.
        """
        if unmanaged_ifaces is None:
            unmanaged_ifaces = [
                i.name for i in self._interfaces.values() if i.role != ROLE_IDLE
            ]
        if not unmanaged_ifaces:
            return False

        macs = [self._interfaces[n].mac for n in unmanaged_ifaces if n in self._interfaces]
        entries = ";".join(f"mac:{m}" for m in macs if m)
        conf = (
            "# WirelessXPL-Forge: USB WiFi adapters under manual WXF control\n"
            "# The internal adapter (providing internet) stays NM-managed.\n"
            "[keyfile]\n"
            f"unmanaged-devices={entries}\n"
        )
        try:
            with open(NM_CONF_PATH, "w") as f:
                f.write(conf)
            subprocess.run(
                ["systemctl", "reload", "NetworkManager"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            logger.info("NM persistent config written: %s", NM_CONF_PATH)
            return True
        except PermissionError:
            logger.warning("No permission to write %s (run as root)", NM_CONF_PATH)
            return False

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def all(self) -> List[InterfaceInfo]:
        return list(self._interfaces.values())

    def get_by_role(self, role: str) -> List[InterfaceInfo]:
        return [i for i in self._interfaces.values() if i.role == role]

    def get_monitor_interfaces(self) -> List[str]:
        return [i.name for i in self.get_by_role(ROLE_MONITOR)]

    def __getitem__(self, name: str) -> InterfaceInfo:
        return self._interfaces[name]

    def __contains__(self, name: str) -> bool:
        return name in self._interfaces
