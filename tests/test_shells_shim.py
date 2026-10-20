"""Tests for wirelessxpl.core.shells shim and shell_mixin."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("xpl_core", reason="xpl_core not installed")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# Shells shim re-exports
# ---------------------------------------------------------------------------

def test_shells_shim_imports() -> None:
    from wirelessxpl.core.shells import (
        SHELL_TYPES,
        SessionManager,
        ShellEngine,
        ShellHandler,
    )
    assert ShellEngine is not None
    assert ShellHandler is not None
    assert SessionManager is not None
    assert isinstance(SHELL_TYPES, (list, tuple, dict))

def test_shells_shim_all_exports() -> None:
    from wirelessxpl.core import shells
    assert hasattr(shells, "__all__")
    assert len(shells.__all__) > 20

def test_shell_engine_is_abc() -> None:
    import abc

    from wirelessxpl.core.shells import ShellEngine
    assert issubclass(type(ShellEngine), abc.ABCMeta)

def test_shell_status_has_values() -> None:
    from wirelessxpl.core.shells import ShellStatus
    assert hasattr(ShellStatus, "CONNECTED")
    assert hasattr(ShellStatus, "DISCONNECTED")

def test_shell_mode_has_values() -> None:
    from wirelessxpl.core.shells import ShellMode
    assert hasattr(ShellMode, "REVERSE")
    assert hasattr(ShellMode, "BIND")

def test_session_state_has_values() -> None:
    from wirelessxpl.core.shells import SessionState
    assert hasattr(SessionState, "ACTIVE")
    assert hasattr(SessionState, "BACKGROUND")

def test_shell_error_hierarchy() -> None:
    from wirelessxpl.core.shells import ShellConnectionError, ShellError, ShellIOError, ShellTimeoutError
    assert issubclass(ShellConnectionError, ShellError)
    assert issubclass(ShellTimeoutError, ShellError)
    assert issubclass(ShellIOError, ShellError)
    assert issubclass(ShellError, Exception)

# ---------------------------------------------------------------------------
# Shell mixin
# ---------------------------------------------------------------------------

def test_shell_mixin_wireless_types() -> None:
    from wirelessxpl.core.shell_mixin import WIRELESS_SHELL_TYPES
    assert "busybox_nc" in WIRELESS_SHELL_TYPES
    assert "mkfifo" in WIRELESS_SHELL_TYPES
    assert "socat" in WIRELESS_SHELL_TYPES
    assert "telnet_reverse" in WIRELESS_SHELL_TYPES

def test_wireless_payload_busybox() -> None:
    from wirelessxpl.core.shell_mixin import _wireless_payload
    payload = _wireless_payload("busybox_nc", "10.0.0.1", 4444)
    assert "busybox" in payload
    assert "nc" in payload
    assert "10.0.0.1" in payload
    assert "4444" in payload

def test_wireless_payload_mkfifo() -> None:
    from wirelessxpl.core.shell_mixin import _wireless_payload
    payload = _wireless_payload("mkfifo", "10.0.0.1", 9999)
    assert "mkfifo" in payload
    assert "/tmp/.f" in payload
    assert "10.0.0.1" in payload
    assert "9999" in payload

def test_wireless_payload_telnet() -> None:
    from wirelessxpl.core.shell_mixin import _wireless_payload
    payload = _wireless_payload("telnet_reverse", "192.168.1.1", 5555)
    assert "telnet" in payload
    assert "192.168.1.1" in payload
    assert "5555" in payload

def test_wireless_payload_fallback_to_core() -> None:
    from wirelessxpl.core.shell_mixin import _wireless_payload
    payload = _wireless_payload("bash", "10.0.0.1", 4444)
    assert "bash" in payload or "/bin/sh" in payload
    assert "10.0.0.1" in payload

def test_get_session_manager() -> None:
    from wirelessxpl.core.shell_mixin import get_session_manager
    mgr = get_session_manager()
    assert mgr is not None
    from xpl_core.shells import SessionManager
    assert isinstance(mgr, SessionManager)

# ---------------------------------------------------------------------------
# generate_payload via shim
# ---------------------------------------------------------------------------

def test_generate_payload_bash() -> None:
    from wirelessxpl.core.shells import generate_payload
    payload = generate_payload("bash", "10.0.0.1", 4444)
    assert isinstance(payload, str)
    assert len(payload) > 0
    assert "10.0.0.1" in payload

def test_generate_payload_python() -> None:
    from wirelessxpl.core.shells import generate_payload
    payload = generate_payload("python", "192.168.1.100", 9001)
    assert "python" in payload.lower() or "socket" in payload
    assert "192.168.1.100" in payload

def test_tty_upgrade_commands() -> None:
    from wirelessxpl.core.shells import tty_upgrade_commands
    cmds = tty_upgrade_commands()
    assert isinstance(cmds, (list, tuple))
    assert len(cmds) > 0

def test_reverse_shell_payload() -> None:
    from wirelessxpl.core.shells import reverse_shell_payload
    payload = reverse_shell_payload("10.0.0.1", 4444)
    assert isinstance(payload, str)
    assert "10.0.0.1" in payload
