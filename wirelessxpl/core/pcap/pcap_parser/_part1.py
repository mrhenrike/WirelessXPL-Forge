"""Core PCAP/PCAPNG parsing utilities for offline wireless analysis.

Provides structured extraction of 802.11 frames, EAPOL handshakes,
cleartext credentials, and AP/station mapping from capture files.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""


import logging
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("wirelessxpl.pcap")

try:
    from scapy.all import (  # noqa: F401
        EAPOL,
        IP,
        TCP,
        UDP,
        Dot11,
        Dot11AssoReq,
        Dot11AssoResp,
        Dot11Auth,
        Dot11Beacon,
        Dot11Deauth,
        Dot11Elt,
        Dot11ProbeReq,
        Dot11ProbeResp,
        PcapNgReader,
        PcapReader,
        Raw,
        rdpcap,
    )
    from scapy.all import (  # noqa: F401
        conf as scapy_conf,
    )

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

SUPPORTED_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".dump"}


# ---------------------------------------------------------------------------
# Data classes for structured output
# ---------------------------------------------------------------------------

@dataclass
class AccessPoint:
    """Represents a discovered wireless access point."""

    bssid: str
    ssid: str = ""
    channel: int = 0
    encryption: str = "OPEN"
    cipher: str = ""
    auth: str = ""
    beacon_count: int = 0
    vendor_oui: str = ""

    @property
    def key(self) -> str:
        return self.bssid.upper()


@dataclass
class Station:
    """Represents a wireless client station."""

    mac: str
    associated_bssid: str = ""
    probed_ssids: set[str] = field(default_factory=set)
    data_frames: int = 0

    @property
    def key(self) -> str:
        return self.mac.upper()


@dataclass
class EAPOLHandshake:
    """Represents a captured WPA/WPA2 4-way handshake."""

    bssid: str
    client_mac: str
    ssid: str = ""
    messages: list[int] = field(default_factory=list)
    packets: list[Any] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """A usable handshake needs at least messages 1+2 or 2+3."""
        msg_set = set(self.messages)
        return ({1, 2}.issubset(msg_set) or {2, 3}.issubset(msg_set))

    @property
    def completeness(self) -> str:
        unique = sorted(set(self.messages))
        if len(unique) == 4:
            return "full"
        if self.is_complete:
            return "partial_usable"
        return "incomplete"


@dataclass
class ExtractedCredential:
    """Represents a cleartext credential found in traffic."""

    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    username: str = ""
    password: str = ""
    extra: str = ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _detect_encryption(packet: Any) -> tuple[str, str, str]:
    """Derive encryption, cipher and auth from beacon/probe-response IEs."""
    encryption = "OPEN"
    cipher = ""
    auth = ""

    cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                         "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").strip()
    has_privacy = "privacy" in cap.lower() if cap else False

    rsn_found = False
    wpa_found = False
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 48:  # RSN (WPA2)
            rsn_found = True
            cipher, auth = _parse_rsn_wpa_ie(bytes(elt.info))
        elif elt.ID == 221 and elt.info and elt.info[:4] == b"\x00\x50\xf2\x01":
            wpa_found = True
            if not rsn_found:
                cipher, auth = _parse_rsn_wpa_ie(bytes(elt.info[4:]))
        elt = elt.payload.getlayer(Dot11Elt)

    if rsn_found:
        encryption = "WPA2"
    elif wpa_found:
        encryption = "WPA"
    elif has_privacy:
        encryption = "WEP"

    return encryption, cipher, auth


def _parse_rsn_wpa_ie(data: bytes) -> tuple[str, str]:
    """Extract cipher suite and AKM from RSN/WPA IE body."""
    cipher_map = {1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104"}
    akm_map = {1: "MGT", 2: "PSK"}
    cipher = ""
    auth = ""
    try:
        if len(data) < 10:
            return cipher, auth
        offset = 2  # version
        offset += 4  # group cipher suite
        pw_count = struct.unpack("<H", data[offset:offset + 2])[0]
        offset += 2
        for _ in range(pw_count):
            suite_type = data[offset + 3]
            cipher = cipher_map.get(suite_type, f"CIPHER-{suite_type}")
            offset += 4
        akm_count = struct.unpack("<H", data[offset:offset + 2])[0]
        offset += 2
        for _ in range(akm_count):
            akm_type = data[offset + 3]
            auth = akm_map.get(akm_type, f"AKM-{akm_type}")
            offset += 4
    except (struct.error, IndexError):
        pass
    return cipher, auth


def _extract_ssid(packet: Any) -> str:
    """Extract SSID from Dot11Elt layer."""
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0:
            try:
                return elt.info.decode("utf-8", errors="replace").strip("\x00")
            except Exception:
                return ""
        elt = elt.payload.getlayer(Dot11Elt)
    return ""


def _extract_channel(packet: Any) -> int:
    """Extract channel from DS Parameter Set IE."""
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3 and elt.info:
            return elt.info[0]
        elt = elt.payload.getlayer(Dot11Elt)
    return 0


def _classify_eapol_message(raw_eapol: bytes) -> int:
    """Determine EAPOL 4-way handshake message number (1-4)."""
    if len(raw_eapol) < 99:
        return 0
    try:
        key_info = struct.unpack("!H", raw_eapol[5:7])[0]
    except struct.error:
        return 0

    install = bool(key_info & (1 << 6))
    ack = bool(key_info & (1 << 7))
    mic = bool(key_info & (1 << 8))
    secure = bool(key_info & (1 << 9))

    if ack and not mic:
        return 1
    if mic and not ack and not install and not secure:
        return 2
    if ack and mic and install and secure:
        return 3
    if mic and not ack and secure:
        return 4
    return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_pcap_path(file_path: str) -> Path:
    """Validate that file_path points to a supported capture file.

    Args:
        file_path: Path to the capture file.

    Returns:
        Resolved Path object.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the extension is unsupported or scapy is missing.
    """
    if not SCAPY_AVAILABLE:
        raise ValueError(
            "scapy is required for PCAP analysis. "
            "Install it with: pip install scapy"
        )
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Capture file not found: {path}")
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            "Unsupported capture format '{}'. Supported: {}".format(
                path.suffix, ", ".join(sorted(SUPPORTED_EXTENSIONS))
            )
        )
    return path


def load_packets(file_path: str, max_packets: int = 0) -> list[Any]:
    """Load packets from a PCAP/PCAPNG file.

    Args:
        file_path: Path to the capture file.
        max_packets: Maximum number of packets to read (0 = unlimited).

    Returns:
        List of scapy packet objects.
    """
    path = validate_pcap_path(file_path)
    logger.info("Loading capture file: %s", path)
    packets = rdpcap(str(path), count=max_packets if max_packets > 0 else -1)
    logger.info("Loaded %d packets from %s", len(packets), path.name)
    return list(packets)


