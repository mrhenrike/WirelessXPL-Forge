"""
wirelessxpl/modules/generic/wifi_lab/wpa3_transition_detector.py

WPA3 Network Transition Mode and Security Capabilities Detector.

Parses iw scan output or RSN IE bytes to detect:
  - WPA3-Personal (SAE), WPA3-Enterprise (Suite-B), WPA3-Transition Mode
  - PMF (Protected Management Frames) status
  - OWE (Opportunistic Wireless Encryption)
  - Attack surface summary per network

Native implementation rewritten from MoMo wpa3_detector.py.
No dependency on MoMo at runtime.

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from wirelessxpl.core.exploit import *

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class SAEStatus(str, Enum):
    NOT_SUPPORTED = "not_supported"
    SUPPORTED = "supported"
    REQUIRED = "required"
    TRANSITION = "transition"


class PMFStatus(str, Enum):
    DISABLED = "disabled"
    OPTIONAL = "optional"
    REQUIRED = "required"


class WPA3Mode(str, Enum):
    NONE = "none"
    PERSONAL = "personal"
    ENTERPRISE = "enterprise"
    TRANSITION = "transition"
    OWE = "owe"
    OWE_TRANSITION = "owe_transition"


@dataclass
class WPA3Network:
    """WPA3 security capabilities of an access point."""
    bssid: str
    ssid: str
    wpa3_mode: WPA3Mode = WPA3Mode.NONE
    sae_status: SAEStatus = SAEStatus.NOT_SUPPORTED
    pmf_status: PMFStatus = PMFStatus.DISABLED
    transition_mode: bool = False
    wpa2_available: bool = False
    owe_supported: bool = False
    mfp_capable: bool = False
    akm_suites: List[str] = field(default_factory=list)
    channel: int = 0
    signal_dbm: int = -100

    @property
    def vulnerable_to_deauth(self) -> bool:
        return self.pmf_status != PMFStatus.REQUIRED

    @property
    def downgradable(self) -> bool:
        return self.transition_mode and self.wpa2_available

    @property
    def attack_surface(self) -> List[str]:
        attacks = []
        if self.downgradable:
            attacks.append("DOWNGRADE: Force WPA2 association - capture PMKID/4-way handshake")
        if self.vulnerable_to_deauth:
            attacks.append("DEAUTH: PMF not required - standard deauth frames work")
        if self.sae_status in (SAEStatus.SUPPORTED, SAEStatus.TRANSITION, SAEStatus.REQUIRED):
            attacks.append("SAE_FLOOD: DoS via SAE Commit burst without Confirm")
        if self.owe_supported:
            attacks.append("OWE_DOWNGRADE: Force open network association")
        if not attacks:
            attacks.append("LIMITED: Pure WPA3 with PMF required - minimal attack surface")
        return attacks

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "wpa3_mode": self.wpa3_mode.value,
            "sae_status": self.sae_status.value,
            "pmf_status": self.pmf_status.value,
            "transition_mode": self.transition_mode,
            "wpa2_available": self.wpa2_available,
            "owe_supported": self.owe_supported,
            "vulnerable_to_deauth": self.vulnerable_to_deauth,
            "downgradable": self.downgradable,
            "attack_surface": self.attack_surface,
            "akm_suites": self.akm_suites,
            "channel": self.channel,
            "signal_dbm": self.signal_dbm,
        }


# ---------------------------------------------------------------------------
# iw scan parser
# ---------------------------------------------------------------------------

def parse_iw_scan(output: str) -> List[WPA3Network]:
    """Parse 'iw dev wlan0 scan' output into WPA3Network objects.

    Args:
        output: Raw string from iw scan stdout.

    Returns:
        List of WPA3Network objects, one per visible BSS.
    """
    results: List[WPA3Network] = []
    bssid = ssid = ""
    akm: List[str] = []
    has_wpa2 = has_wpa3 = pmf_cap = pmf_req = has_owe = False
    channel = 0
    signal = -100

    def _flush() -> None:
        if not bssid:
            return
        if has_wpa3 and has_wpa2:
            mode = WPA3Mode.TRANSITION
            sae = SAEStatus.TRANSITION
        elif has_wpa3:
            mode = WPA3Mode.PERSONAL
            sae = SAEStatus.REQUIRED
        elif has_owe:
            mode = WPA3Mode.OWE
            sae = SAEStatus.NOT_SUPPORTED
        else:
            mode = WPA3Mode.NONE
            sae = SAEStatus.NOT_SUPPORTED

        if pmf_req:
            pmf = PMFStatus.REQUIRED
        elif pmf_cap:
            pmf = PMFStatus.OPTIONAL
        else:
            pmf = PMFStatus.DISABLED

        results.append(WPA3Network(
            bssid=bssid,
            ssid=ssid,
            wpa3_mode=mode,
            sae_status=sae,
            pmf_status=pmf,
            transition_mode=has_wpa3 and has_wpa2,
            wpa2_available=has_wpa2,
            owe_supported=has_owe,
            mfp_capable=pmf_cap,
            akm_suites=list(akm),
            channel=channel,
            signal_dbm=signal,
        ))

    for line in output.splitlines():
        s = line.strip()

        if s.startswith("BSS "):
            _flush()
            bssid = ssid = ""
            akm = []
            has_wpa2 = has_wpa3 = pmf_cap = pmf_req = has_owe = False
            channel = 0
            signal = -100
            m = re.search(r"([0-9a-fA-F:]{17})", s)
            if m:
                bssid = m.group(1).upper()

        elif s.startswith("SSID:"):
            ssid = s[5:].strip()

        elif "primary channel:" in s.lower() or "DS Parameter set: channel" in s:
            m = re.search(r"(\d+)", s)
            if m:
                channel = int(m.group(1))

        elif s.startswith("signal:"):
            m = re.search(r"([-\d.]+)", s)
            if m:
                try:
                    signal = int(float(m.group(1)))
                except ValueError:
                    pass

        elif "00-0f-ac:2" in s:
            has_wpa2 = True
            if "PSK" not in akm:
                akm.append("PSK")

        elif "00-0f-ac:8" in s:
            has_wpa3 = True
            if "SAE" not in akm:
                akm.append("SAE")

        elif "00-0f-ac:18" in s:
            has_owe = True
            if "OWE" not in akm:
                akm.append("OWE")

        elif "00-0f-ac:12" in s:
            has_wpa3 = True
            if "Suite-B" not in akm:
                akm.append("Suite-B")

        elif "Authentication suites:" in s or "* Authentication suites:" in s:
            if "PSK" in s:
                has_wpa2 = True
                if "PSK" not in akm:
                    akm.append("PSK")
            if "SAE" in s:
                has_wpa3 = True
                if "SAE" not in akm:
                    akm.append("SAE")
            if "OWE" in s:
                has_owe = True
                if "OWE" not in akm:
                    akm.append("OWE")

        elif "Capabilities:" in s:
            if "MFPC" in s or "MFP capable" in s:
                pmf_cap = True
            if "MFPR" in s or "MFP required" in s:
                pmf_req = True

        elif "management frame protection" in s.lower():
            if "required" in s.lower():
                pmf_req = True
            elif "capable" in s.lower():
                pmf_cap = True

    _flush()
    return results


def parse_rsn_ie(rsn_ie: bytes) -> Dict[str, Any]:
    """Parse RSN Information Element bytes (without type/length header).

    Args:
        rsn_ie: RSN IE payload bytes (after 0x30 and length byte).

    Returns:
        dict with akm_suites, pmf_capable, pmf_required, group_cipher.
    """
    result: Dict[str, Any] = {
        "akm_suites": [],
        "pmf_capable": False,
        "pmf_required": False,
        "group_cipher": "",
        "pairwise_ciphers": [],
    }
    if len(rsn_ie) < 8:
        return result

    offset = 2  # skip version(2)

    # Group Cipher Suite
    if offset + 4 <= len(rsn_ie):
        cipher_oui = rsn_ie[offset:offset + 3].hex()
        cipher_type = rsn_ie[offset + 3]
        ciphers = {0: "Use Group", 1: "WEP-40", 2: "TKIP", 4: "CCMP-128", 6: "CMAC", 8: "GCMP-128", 9: "GCMP-256"}
        result["group_cipher"] = ciphers.get(cipher_type, f"0x{cipher_type:02X}")
        offset += 4

    # Pairwise Cipher Suite Count + List
    if offset + 2 <= len(rsn_ie):
        pw_count = struct.unpack_from("<H", rsn_ie, offset)[0]
        offset += 2
        for _ in range(pw_count):
            if offset + 4 > len(rsn_ie):
                break
            cipher_type = rsn_ie[offset + 3]
            ciphers = {0: "Use Group", 1: "WEP-40", 2: "TKIP", 4: "CCMP-128", 6: "CMAC", 8: "GCMP-128", 9: "GCMP-256"}
            result["pairwise_ciphers"].append(ciphers.get(cipher_type, f"0x{cipher_type:02X}"))
            offset += 4

    # AKM Suite Count + List
    if offset + 2 <= len(rsn_ie):
        akm_count = struct.unpack_from("<H", rsn_ie, offset)[0]
        offset += 2
        akm_map = {2: "PSK", 8: "SAE", 9: "FT-SAE", 12: "Suite-B-192", 18: "OWE", 24: "SAE-EXT"}
        for _ in range(akm_count):
            if offset + 4 > len(rsn_ie):
                break
            akm_type = rsn_ie[offset + 3]
            result["akm_suites"].append(akm_map.get(akm_type, f"0x{akm_type:02X}"))
            offset += 4

    # RSN Capabilities (2 bytes)
    if offset + 2 <= len(rsn_ie):
        caps = struct.unpack_from("<H", rsn_ie, offset)[0]
        result["pmf_capable"] = bool(caps & 0x0080)   # bit 7
        result["pmf_required"] = bool(caps & 0x0040)  # bit 6

    return result


# ---------------------------------------------------------------------------
# WXF Exploit module
# ---------------------------------------------------------------------------

class Exploit(Exploit):
    """WPA3 Network Transition Mode and Security Capabilities Detector.

    Scans visible networks using 'iw scan' and classifies each by WPA3 mode,
    PMF status, and attack surface. No active packet injection required.

    Native implementation - does not depend on MoMo framework.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    """

    __info__ = {
        "name": "WPA3 Transition Detector",
        "description": (
            "Scans visible WiFi networks and detects WPA3/SAE capabilities, "
            "PMF status, transition mode, and attack surface. "
            "Uses iw scan output - no raw injection needed."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "IEEE 802.11-2020",
            "CVE-2019-9494 (Dragonblood WPA3 SAE)",
            "wireless-research/MoMo wpa3_detector.py",
        ),
        "devices": ("wifi",),
        "platform": ("linux",),
    }

    interface = OptString("wlan0", "WiFi interface to scan")
    show_all = OptBool(False, "Show all networks (not only WPA3)")
    min_signal = OptInteger(-90, "Minimum signal strength (dBm) to include")
    dry_run = OptBool(False, "Test with mock data (no hardware required)")

    def check(self) -> bool:
        """Verify iw tool is available and interface exists."""
        import shutil
        if bool(self.dry_run):
            return True
        if not shutil.which("iw"):
            print("[-] 'iw' tool not found. Install: apt install iw")
            return False
        return True

    def run(self) -> None:
        """Run WPA3 detection scan."""
        from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab
        require_authorised_lab(self)

        if bool(self.dry_run):
            self._run_mock()
            return

        import subprocess
        iface = str(self.interface).strip()
        try:
            result = subprocess.run(
                ["iw", "dev", iface, "scan"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                print(f"[-] iw scan failed: {result.stderr[:200]}")
                return
            networks = parse_iw_scan(result.stdout)
        except subprocess.TimeoutExpired:
            print("[-] iw scan timed out")
            return
        except Exception as exc:
            print(f"[-] Scan error: {exc}")
            return

        self._print_results(networks)

    def _run_mock(self) -> None:
        """Print mock results for testing."""
        mock_output = """BSS AA:BB:CC:DD:EE:01
 SSID: SecureWPA3
 RSN: ...
  * Authentication suites: SAE
  Capabilities: MFPR
BSS AA:BB:CC:DD:EE:02
 SSID: OfficeWiFi
  * Authentication suites: PSK SAE
  00-0f-ac:2
  00-0f-ac:8
  Capabilities: MFPC
BSS AA:BB:CC:DD:EE:03
 SSID: LegacyNet
  * Authentication suites: PSK
  00-0f-ac:2
"""
        networks = parse_iw_scan(mock_output)
        self._print_results(networks)

    def _print_results(self, networks: List[WPA3Network]) -> None:
        min_sig = int(self.min_signal)
        show_all = bool(self.show_all)

        filtered = [n for n in networks if n.signal_dbm >= min_sig]
        if not show_all:
            filtered = [n for n in filtered if n.wpa3_mode != WPA3Mode.NONE]

        print()
        print(f"  WPA3 Detection Results ({len(filtered)} networks)")
        print("  " + "-" * 62)

        for n in sorted(filtered, key=lambda x: (-_sev_order(x), x.bssid)):
            mode = n.wpa3_mode.value.upper()
            pmf = n.pmf_status.value
            print(f"\n  [{mode}] {n.ssid or '<hidden>'} ({n.bssid})")
            print(f"    PMF: {pmf} | SAE: {n.sae_status.value} | AKMs: {', '.join(n.akm_suites)}")
            for a in n.attack_surface:
                print(f"    -> {a}")

        if not filtered:
            print("  No WPA3 networks found in range.")
        print()


def _sev_order(n: WPA3Network) -> int:
    if n.downgradable:
        return 3
    if n.vulnerable_to_deauth and n.wpa3_mode != WPA3Mode.NONE:
        return 2
    if n.wpa3_mode != WPA3Mode.NONE:
        return 1
    return 0
