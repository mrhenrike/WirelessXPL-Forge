#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""WXF Interface Manager — select, configure and protect wireless interfaces.

This module is the single control point for wireless interface lifecycle in WXF:

  - Lists all available wireless interfaces with their current state, driver,
    supported bands, monitor/AP/injection capabilities, and whether they are
    currently providing the internet connection.
  - Lets the user assign interfaces to WXF roles (monitor, inject, ap, managed).
  - Warns explicitly when the selected interface carries the default route and
    explains the connectivity risk before proceeding.
  - Integrates with NetworkManager: when an interface is assigned to monitor or
    inject role, NM is instructed to stop managing it (per-interface, safe for
    multi-adapter setups). The internal internet-facing adapter is never touched.
  - Optionally writes a persistent NM configuration file so the settings survive
    reboots and NM restarts.
  - Releases all assigned interfaces on module exit, restoring NM management.

Modes:
    list       - Show all interfaces and their status (default)
    assign     - Assign one interface to a WXF role
    release    - Release one interface back to OS control
    release_all- Release all WXF-assigned interfaces
    persist_nm - Write persistent NM unmanaged config (requires root)
    status     - Show current WXF interface assignments

OS requirement: Linux only (iw, NetworkManager).
Version: 1.0.0
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Optional

from wirelessxpl.core.exploit import (
    Exploit, OptBool, OptString,
    print_error, print_info, print_status, print_success, print_warning,
)
from wirelessxpl.core.exploit.printer import color_blue, color_green, color_red
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.core.wifi.interface_registry import (
    InterfaceInfo, InterfaceRegistry,
    ROLE_MONITOR, ROLE_INJECT, ROLE_AP, ROLE_MANAGED, ROLE_IDLE,
)

_DISCLAIMER = (
    "\033[93m[AVISO]\033[0m  Selecionar uma interface que fornece conectividade "
    "com a internet IRÁ derrubar sua conexão enquanto estiver em modo monitor/AP.\n"
    "         Use apenas adaptadores USB externos para testes. Confirme com "
    "force=true para ignorar este aviso."
)

_ROLE_COLORS = {
    ROLE_MONITOR: "\033[94m",   # azul
    ROLE_INJECT:  "\033[91m",   # vermelho
    ROLE_AP:      "\033[93m",   # amarelo
    ROLE_MANAGED: "\033[92m",   # verde
    ROLE_IDLE:    "\033[90m",   # cinza
}
_RESET = "\033[0m"


def _colored_role(role: str) -> str:
    return f"{_ROLE_COLORS.get(role, '')}{role}{_RESET}"


def _internet_tag(info: InterfaceInfo) -> str:
    return " \033[91m[INTERNET]\033[0m" if info.provides_internet else ""


def _print_iface_table(interfaces: list[InterfaceInfo]) -> None:
    """Print a rich table of all interfaces."""
    sep = "-" * 100
    print_info(sep)
    print_info(
        f"  {'IFACE':<24} {'PHY':<8} {'MODE':<10} {'DRIVER':<14} "
        f"{'BANDS':<18} {'MON':>3} {'AP':>3} {'NM':>4}  ROLE / FLAGS"
    )
    print_info(sep)
    for i in interfaces:
        mon  = color_green("Y") if i.supports_monitor else color_red("N")
        ap   = color_green("Y") if i.supports_ap      else color_red("N")
        nm   = color_green("Y") if i.nm_managed       else color_red("N")
        bands = "/".join(i.bands) if i.bands else "?"
        role_str = _colored_role(i.role)
        inet = _internet_tag(i)
        ch   = f" ch{i.channel}" if i.channel else ""
        print_info(
            f"  {i.name:<24} {i.phy:<8} {i.current_mode:<10} {i.driver:<14} "
            f"{bands:<18} {mon:>3} {ap:>3} {nm:>4}  {role_str}{ch}{inet}"
        )
    print_info(sep)
    print_info(
        "  MON=monitor capable  AP=AP capable  NM=NetworkManager managed  "
        "\033[91m[INTERNET]\033[0m=active gateway"
    )
    print_info("")


@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """WXF Wireless Interface Manager.

    Select which interfaces WXF may use for attacks/tests. Handles
    NetworkManager safely: only unmanages the chosen interfaces, leaving
    all others (including the internet-providing adapter) untouched.
    """

    __info__ = {
        "name": "WXF Interface Manager",
        "description": (
            "Discovers all wireless interfaces, shows their capabilities, "
            "lets the user assign them to WXF roles (monitor/inject/ap), "
            "and configures NetworkManager safely so only the selected "
            "interfaces are unmanaged. The internet-providing adapter is "
            "never touched unless the user explicitly forces it."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://wireless.wiki.kernel.org/en/users/documentation/iw",
            "https://networkmanager.dev/docs/",
        ),
        "devices": ("wifi", "802.11", "networkmanager"),
    }

    mode = OptString(
        "list",
        "Mode: list | assign | release | release_all | persist_nm | status",
    )
    interface = OptString("", "Interface name for assign/release modes")
    role = OptString(
        ROLE_MONITOR,
        f"Role for assign mode: {ROLE_MONITOR} | {ROLE_INJECT} | {ROLE_AP} | {ROLE_MANAGED}",
    )
    channel = OptString("", "Channel to set after mode switch (e.g. 6)")
    force = OptBool(
        False,
        "Force assign even if interface provides internet (WILL drop connection)",
    )
    persist_nm_config = OptBool(
        False,
        "Write persistent NM config file to survive reboots",
    )

    # ------------------------------------------------------------------
    # check
    # ------------------------------------------------------------------

    def check(self) -> str:
        missing = []
        if not shutil.which("iw"):
            missing.append("iw")
        if not shutil.which("ip"):
            missing.append("ip")
        if missing:
            return f"Missing tools: {', '.join(missing)} — install iw and iproute2"
        nm_ok = "nmcli available" if shutil.which("nmcli") else "nmcli NOT found (NM integration disabled)"
        return f"Prerequisites OK | {nm_ok}"

    # ------------------------------------------------------------------
    # run
    # ------------------------------------------------------------------

    def run(self) -> None:
        reg = InterfaceRegistry.get()
        reg.refresh()
        op = str(self.mode).strip().lower()

        if op == "list":
            self._do_list(reg)

        elif op == "status":
            self._do_status(reg)

        elif op == "assign":
            self._do_assign(reg)

        elif op == "release":
            self._do_release(reg)

        elif op == "release_all":
            self._do_release_all(reg)

        elif op == "persist_nm":
            self._do_persist_nm(reg)

        else:
            print_error(
                f"Unknown mode: {op!r}. "
                "Valid: list | assign | release | release_all | persist_nm | status"
            )

    # ------------------------------------------------------------------
    # Mode handlers
    # ------------------------------------------------------------------

    def _do_list(self, reg: InterfaceRegistry) -> None:
        interfaces = reg.all()
        if not interfaces:
            print_error("No wireless interfaces found. Check iw / driver installation.")
            return

        print_status(f"Wireless interfaces found: {len(interfaces)}")
        _print_iface_table(interfaces)

        # Highlight internet interface
        inet_ifaces = [i for i in interfaces if i.provides_internet]
        if inet_ifaces:
            names = ", ".join(i.name for i in inet_ifaces)
            print_warning(
                f"Interface(s) providing internet: {names}\n"
                "  Assigning these to monitor/inject mode WILL drop your connection.\n"
                "  Use an external USB adapter for WXF tests."
            )

        # Suggest unmanaged USB adapters
        candidates = [
            i for i in interfaces
            if not i.provides_internet and i.supports_monitor
        ]
        if candidates:
            print_success(
                "Recommended interfaces for WXF (monitor capable, not internet-facing):"
            )
            for c in candidates:
                bands = "/".join(c.bands) if c.bands else "?"
                print_info(
                    f"  {c.name}  ({c.driver}, {bands})"
                    + (" [already in monitor]" if c.current_mode == "monitor" else "")
                )

    def _do_status(self, reg: InterfaceRegistry) -> None:
        assigned = [i for i in reg.all() if i.role != ROLE_IDLE]
        if not assigned:
            print_info("No interfaces currently assigned to WXF roles.")
            return
        print_status(f"WXF interface assignments ({len(assigned)}):")
        _print_iface_table(assigned)

    def _do_assign(self, reg: InterfaceRegistry) -> None:
        iface = str(self.interface).strip()
        if not iface:
            print_error("Set 'interface' to the name of the adapter to assign.")
            return

        role = str(self.role).strip().lower()
        if role not in (ROLE_MONITOR, ROLE_INJECT, ROLE_AP, ROLE_MANAGED):
            print_error(
                f"Invalid role {role!r}. "
                f"Valid: {ROLE_MONITOR} | {ROLE_INJECT} | {ROLE_AP} | {ROLE_MANAGED}"
            )
            return

        ch_str = str(self.channel).strip()
        channel = int(ch_str) if ch_str.isdigit() else None

        # Safety check
        if iface in reg and reg[iface].provides_internet and not bool(self.force):
            print_info(_DISCLAIMER)
            print_error(
                f"Interface {iface} carries the default route. "
                "Set force=true to proceed (connectivity will drop)."
            )
            return

        try:
            info = reg.assign(iface, role=role, channel=channel, force=bool(self.force))
        except KeyError:
            print_error(f"Interface {iface!r} not found. Run mode=list to see available interfaces.")
            return
        except ValueError as exc:
            print_info(_DISCLAIMER)
            print_error(str(exc))
            return

        # Actually switch mode
        self._switch_mode(iface, role, channel)

        print_success(f"Assigned {iface} -> role={role}" + (f" ch={channel}" if channel else ""))

        if not info.nm_managed:
            print_info(f"  NM no longer managing {iface} (safe for monitor/inject).")

        if bool(self.persist_nm_config):
            ok = reg.persist_nm_config()
            if ok:
                print_success("Persistent NM config written (survives reboots).")
            else:
                print_warning("Could not write NM config — run as root for persistence.")

    def _do_release(self, reg: InterfaceRegistry) -> None:
        iface = str(self.interface).strip()
        if not iface:
            print_error("Set 'interface' to the adapter name to release.")
            return
        reg.release(iface)
        # Switch back to managed mode
        self._set_managed(iface)
        print_success(f"Released {iface} back to managed mode (NM re-enabled).")

    def _do_release_all(self, reg: InterfaceRegistry) -> None:
        assigned = [i for i in reg.all() if i.role != ROLE_IDLE]
        if not assigned:
            print_info("No WXF-assigned interfaces to release.")
            return
        for info in assigned:
            reg.release(info.name)
            self._set_managed(info.name)
            print_success(f"Released {info.name} -> managed.")
        print_success(f"{len(assigned)} interface(s) released.")

    def _do_persist_nm(self, reg: InterfaceRegistry) -> None:
        assigned = [i.name for i in reg.all() if i.role != ROLE_IDLE]
        if not assigned:
            print_warning("No interfaces assigned. Assign interfaces first, then run persist_nm.")
            return
        ok = reg.persist_nm_config(assigned)
        if ok:
            print_success(
                f"Persistent NM config written for: {', '.join(assigned)}\n"
                "  These interfaces will remain unmanaged after reboot/NM restart."
            )
        else:
            print_error("Failed to write NM config. Run WXF as root for this operation.")

    # ------------------------------------------------------------------
    # OS operations
    # ------------------------------------------------------------------

    def _switch_mode(self, iface: str, role: str, channel: Optional[int] = None) -> None:
        """Switch the OS interface mode to match the assigned role."""
        if role in (ROLE_MONITOR, ROLE_INJECT):
            subprocess.run(["ip", "link", "set", iface, "down"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iw", "dev", iface, "set", "type", "monitor"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "set", iface, "up"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if channel:
                subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        elif role == ROLE_AP:
            # AP mode requires a separate hostapd invocation; just switch type
            subprocess.run(["ip", "link", "set", iface, "down"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iw", "dev", iface, "set", "type", "__ap"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "set", iface, "up"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        elif role == ROLE_MANAGED:
            self._set_managed(iface)

    def _set_managed(self, iface: str) -> None:
        subprocess.run(["ip", "link", "set", iface, "down"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", iface, "up"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


