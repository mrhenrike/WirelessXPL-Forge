"""Deterministic crackable material detector for PCAP/EAPOL captures.

Analyzes pcap files and detects crackable WPA material:
- EAPOL 4-way handshake completeness (M1+M2 or M1+M3 pairs)
- PMKID presence in M1 Key Data Extension (KDE)

Conceptual reference: airgorah handshake.rs (MIT, martin-olivier)
Recode: full Python rewrite using scapy, no code copied.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

try:
    from scapy.all import EAPOL, Dot11, Dot11Beacon, Dot11ProbeResp, rdpcap
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False

EAPOL_KEY_TYPE_PAIRWISE = 0x08
EAPOL_KEY_MIC_FLAG = 0x01
EAPOL_KEY_ACK_FLAG = 0x80
EAPOL_KEY_INSTALL_FLAG = 0x40
EAPOL_KEY_SECURE_FLAG = 0x02

KDE_PMKID_TYPE = 0x04
KDE_PMKID_OUI = b"\x00\x0f\xac"


@dataclass
class HandshakeState:
    bssid: str
    station: str
    has_m1: bool = False
    has_m2: bool = False
    has_m3: bool = False
    has_m4: bool = False
    pmkid: Optional[bytes] = None
    ssid: str = ""

    @property
    def has_full_handshake(self) -> bool:
        return self.has_m1 and self.has_m2

    @property
    def has_partial_handshake(self) -> bool:
        return self.has_m1 and self.has_m3

    @property
    def has_pmkid(self) -> bool:
        return self.pmkid is not None

    @property
    def is_crackable(self) -> bool:
        return self.has_full_handshake or self.has_partial_handshake or self.has_pmkid

    @property
    def crack_methods(self) -> List[str]:
        methods = []
        if self.has_full_handshake:
            methods.append("4way-m1m2")
        if self.has_partial_handshake:
            methods.append("4way-m1m3")
        if self.has_pmkid:
            methods.append("pmkid")
        return methods


@dataclass
class CrackableReport:
    filepath: str
    total_packets: int = 0
    handshakes: List[HandshakeState] = field(default_factory=list)
    ssids_seen: Set[str] = field(default_factory=set)

    @property
    def crackable_count(self) -> int:
        return sum(1 for h in self.handshakes if h.is_crackable)

    @property
    def has_crackable(self) -> bool:
        return self.crackable_count > 0


def _classify_eapol_message(key_info: int) -> int:
    ack = bool(key_info & EAPOL_KEY_ACK_FLAG)
    mic = bool(key_info & EAPOL_KEY_MIC_FLAG)
    install = bool(key_info & EAPOL_KEY_INSTALL_FLAG)
    secure = bool(key_info & EAPOL_KEY_SECURE_FLAG)

    if ack and not mic:
        return 1
    if not ack and mic and not install:
        return 2
    if ack and mic and install:
        return 3
    if not ack and mic and secure:
        return 4
    return 0


def _extract_pmkid_from_kde(key_data: bytes) -> Optional[bytes]:
    pos = 0
    while pos + 2 <= len(key_data):
        kde_type = key_data[pos]
        kde_len = key_data[pos + 1] if pos + 1 < len(key_data) else 0

        if kde_type == 0xdd and kde_len >= 20:
            oui_start = pos + 2
            if key_data[oui_start : oui_start + 3] == KDE_PMKID_OUI:
                data_type = key_data[oui_start + 3] if oui_start + 3 < len(key_data) else 0
                if data_type == KDE_PMKID_TYPE:
                    pmkid_start = oui_start + 4
                    pmkid = key_data[pmkid_start : pmkid_start + 16]
                    if len(pmkid) == 16 and pmkid != b"\x00" * 16:
                        return pmkid
        pos += 2 + kde_len
        if kde_len == 0:
            break
    return None


def detect_crackable(pcap_path: str) -> CrackableReport:
    """Analyze a pcap file for crackable WPA material.

    Args:
        pcap_path: Path to pcap/pcapng file.

    Returns:
        CrackableReport with detected handshakes and PMKID info.
    """
    if not _SCAPY_OK:
        raise ImportError("scapy is required: pip install scapy")

    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    report = CrackableReport(filepath=str(path))

    try:
        packets = rdpcap(str(path))
    except Exception as exc:
        logger.error("Failed to read pcap %s: %s", pcap_path, exc)
        return report

    report.total_packets = len(packets)

    pairs: Dict[Tuple[str, str], HandshakeState] = {}
    ssid_map: Dict[str, str] = {}

    for pkt in packets:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            try:
                dot11 = pkt[Dot11]
                bssid = dot11.addr3
                info = pkt.info
                if info and bssid:
                    ssid = info.decode("utf-8", errors="replace").strip()
                    if ssid:
                        ssid_map[bssid.lower()] = ssid
                        report.ssids_seen.add(ssid)
            except Exception:
                pass

        if not pkt.haslayer(EAPOL):
            continue

        try:
            dot11 = pkt[Dot11]
            eapol = pkt[EAPOL]

            src = dot11.addr2
            dst = dot11.addr1
            bssid = dot11.addr3

            if not all([src, dst, bssid]):
                continue

            raw_eapol = bytes(eapol)
            if len(raw_eapol) < 10:
                continue

            key_info = int.from_bytes(raw_eapol[5:7], "big")
            msg_num = _classify_eapol_message(key_info)
            if msg_num == 0:
                continue

            bssid_lower = bssid.lower()

            if msg_num in (1, 3):
                station = dst.lower()
            else:
                station = src.lower()

            pair_key = (bssid_lower, station)
            if pair_key not in pairs:
                pairs[pair_key] = HandshakeState(
                    bssid=bssid_lower,
                    station=station,
                    ssid=ssid_map.get(bssid_lower, ""),
                )

            state = pairs[pair_key]

            if msg_num == 1:
                state.has_m1 = True
                key_data_len = int.from_bytes(raw_eapol[97:99], "big") if len(raw_eapol) > 99 else 0
                if key_data_len > 0 and len(raw_eapol) > 99 + key_data_len:
                    key_data = raw_eapol[99 : 99 + key_data_len]
                    pmkid = _extract_pmkid_from_kde(key_data)
                    if pmkid:
                        state.pmkid = pmkid
            elif msg_num == 2:
                state.has_m2 = True
            elif msg_num == 3:
                state.has_m3 = True
            elif msg_num == 4:
                state.has_m4 = True

        except Exception as exc:
            logger.debug("Error parsing EAPOL packet: %s", exc)
            continue

    for state in pairs.values():
        if not state.ssid:
            state.ssid = ssid_map.get(state.bssid, "")
        report.handshakes.append(state)

    logger.info(
        "PCAP %s: %d packets, %d pairs, %d crackable",
        pcap_path,
        report.total_packets,
        len(report.handshakes),
        report.crackable_count,
    )

    return report
