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

import shutil
import subprocess
from typing import Optional

from wirelessxpl.core.exploit import (
    Exploit,
    OptBool,
    OptString,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)
from wirelessxpl.core.exploit.printer import color_green, color_red
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.core.wifi.interface_registry import (
    ROLE_AP,
    ROLE_IDLE,
    ROLE_INJECT,
    ROLE_MANAGED,
    ROLE_MONITOR,
    InterfaceInfo,
    InterfaceRegistry,
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
