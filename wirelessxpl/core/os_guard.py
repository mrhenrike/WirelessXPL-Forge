#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""OS compatibility guard for WirelessXPL-Forge modules.

Provides a decorator-based system to declare and enforce OS requirements
for each module. Modules that depend on Linux-only subsystems (raw sockets,
nl80211, netlink, monitor mode, etc.) are blocked on incompatible operating
systems with a clear, actionable error message.

Usage:
    from wirelessxpl.core.os_guard import requires_os, OSRequirement

    @requires_os(OSRequirement.LINUX_ONLY)
    class Exploit:
        ...

Version: 1.0.0
"""

from __future__ import annotations

import platform
import functools
from enum import Enum
from typing import Callable, Type, TypeVar, Union

T = TypeVar("T")


class OSRequirement(Enum):
    """Declares the OS requirement level of a WXF module.

    Attributes:
        LINUX_ONLY: Requires Linux. Uses raw sockets, nl80211, monitor mode,
            aircrack-ng, hcxdumptool, or hostapd. Will not run on Windows or macOS.
        LINUX_MAC: Runs on Linux and macOS. Uses BlueZ (Linux) or
            CoreBluetooth (macOS) for Bluetooth. Will not run on Windows.
        CROSS_PLATFORM: No OS-specific dependencies. Runs on Linux, macOS,
            and Windows. Typical for offline analysis, hash cracking, SIM
            operations, and data exporters.
    """

    LINUX_ONLY = "linux_only"
    LINUX_MAC = "linux_mac"
    CROSS_PLATFORM = "cross_platform"


class OSIncompatibleError(RuntimeError):
    """Raised when a module is executed on an incompatible operating system.

    Args:
        module_name: Name of the module that cannot run.
        requirement: The OS requirement declared by the module.
        current_os: The current operating system name.
        reason: Human-readable explanation of why this OS is unsupported.
        suggestion: Suggested fix for the user.
    """

    def __init__(
        self,
        module_name: str,
        requirement: OSRequirement,
        current_os: str,
        reason: str,
        suggestion: str,
    ) -> None:
        self.module_name = module_name
        self.requirement = requirement
        self.current_os = current_os
        self.reason = reason
        self.suggestion = suggestion
        message = (
            f"\n[ERRO] Modulo incompativel com o sistema operacional atual.\n"
            f"  Modulo:      {module_name}\n"
            f"  OS atual:    {current_os}\n"
            f"  OS exigido:  {requirement.value}\n"
            f"  Motivo:      {reason}\n"
            f"  Solucao:     {suggestion}\n"
        )
        super().__init__(message)


def _current_os() -> str:
    """Return the current OS platform string.

    Returns:
        One of: 'Linux', 'Darwin' (macOS), 'Windows', or the raw platform.system() value.
    """
    return platform.system()


def _check_os(requirement: OSRequirement, module_name: str) -> None:
    """Validate that the current OS satisfies the given requirement.

    Args:
        requirement: The OS requirement to check against.
        module_name: Name of the module performing the check (for error messages).

    Raises:
        OSIncompatibleError: If the current OS does not satisfy the requirement.
    """
    current = _current_os()

    if requirement == OSRequirement.CROSS_PLATFORM:
        return  # Always compatible.

    if requirement == OSRequirement.LINUX_ONLY:
        if current != "Linux":
            raise OSIncompatibleError(
                module_name=module_name,
                requirement=requirement,
                current_os=current,
                reason=(
                    "Este modulo requer Linux pois depende de raw sockets 802.11, "
                    "nl80211/netlink, modo monitor, ou ferramentas como aircrack-ng, "
                    "hcxdumptool, hashcat ou hostapd que nao estao disponiveis em "
                    f"{current}."
                ),
                suggestion=(
                    "Execute em Kali Linux, Debian/Ubuntu, ou WSL2 com kernel "
                    "customizado que suporte drivers WiFi em modo monitor."
                ),
            )

    if requirement == OSRequirement.LINUX_MAC:
        if current not in ("Linux", "Darwin"):
            raise OSIncompatibleError(
                module_name=module_name,
                requirement=requirement,
                current_os=current,
                reason=(
                    "Este modulo requer Linux (BlueZ) ou macOS (CoreBluetooth) "
                    f"para operacoes Bluetooth/BLE. {current} nao e suportado."
                ),
                suggestion=(
                    "Execute em Linux com BlueZ instalado (apt install bluez) "
                    "ou em macOS com CoreBluetooth disponivel."
                ),
            )


def requires_os(
    *requirements: OSRequirement,
) -> Callable[[Union[Type[T], Callable]], Union[Type[T], Callable]]:
    """Decorator that enforces OS compatibility before module execution.

    Can be applied to a class (checked when the class is instantiated via __init__)
    or to a function/method (checked when called).

    When applied to the module's Exploit class, the check runs in __init__,
    ensuring the error is raised as early as possible before any option parsing
    or resource allocation.

    Args:
        *requirements: One or more OSRequirement values. The module is compatible
            if the current OS satisfies ANY of the provided requirements.

    Returns:
        A decorator that wraps the target class or function.

    Example:
        @requires_os(OSRequirement.LINUX_ONLY)
        class Exploit:
            ...

        @requires_os(OSRequirement.LINUX_MAC)
        def scan_ble(interface: str) -> None:
            ...
    """
    # Collapse to a single most-permissive requirement for the check.
    # If CROSS_PLATFORM is in the list, always pass.
    effective = OSRequirement.LINUX_ONLY  # default most restrictive
    if OSRequirement.CROSS_PLATFORM in requirements:
        effective = OSRequirement.CROSS_PLATFORM
    elif OSRequirement.LINUX_MAC in requirements:
        effective = OSRequirement.LINUX_MAC
    elif OSRequirement.LINUX_ONLY in requirements:
        effective = OSRequirement.LINUX_ONLY

    def decorator(target: Union[Type[T], Callable]) -> Union[Type[T], Callable]:
        name = getattr(target, "__name__", str(target))

        if isinstance(target, type):
            # Wrap class: inject check into __init__.
            original_init = target.__init__

            @functools.wraps(original_init)
            def patched_init(self, *args, **kwargs):
                _check_os(effective, name)
                original_init(self, *args, **kwargs)

            target.__init__ = patched_init
            target._os_requirement = effective
            return target

        # Wrap function or method.
        @functools.wraps(target)
        def wrapper(*args, **kwargs):
            _check_os(effective, name)
            return target(*args, **kwargs)

        wrapper._os_requirement = effective  # type: ignore[attr-defined]
        return wrapper

    return decorator


def get_module_os_label(target: Union[type, Callable]) -> str:
    """Return a short OS compatibility label for display in the WXF CLI module list.

    Args:
        target: A class or function decorated with @requires_os.

    Returns:
        A short string label: 'Lx' (Linux only), 'Lx/Mac' (Linux + macOS),
        or 'All' (cross-platform). Returns 'Lx' for undecorated modules as
        a safe default (most WXF modules require Linux).
    """
    req = getattr(target, "_os_requirement", OSRequirement.LINUX_ONLY)
    labels = {
        OSRequirement.LINUX_ONLY: "Lx",
        OSRequirement.LINUX_MAC: "Lx/Mac",
        OSRequirement.CROSS_PLATFORM: "All",
    }
    return labels.get(req, "Lx")
