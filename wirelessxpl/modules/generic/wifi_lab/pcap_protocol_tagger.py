"""
wirelessxpl/modules/generic/wifi_lab/pcap_protocol_tagger.py

PCAP Protocol Tagger using Suricata IoT event rules.

Parses Suricata .rules files and applies protocol-based frame detection
against PCAP captures. Identifies IoT protocols: MQTT, mDNS, DHCP, Modbus.

Sources:
  submodules/FraudDetection/suricata/rules/
    mqtt-events.rules, mdns-events.rules, dhcp-events.rules, modbus-events.rules

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__version__ = "1.0.0"

try:
    from scapy.all import rdpcap  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    _SCAPY = True
except ImportError:
    _SCAPY = False


@dataclass
class SuricataRule:
    """Parsed Suricata rule (minimal subset)."""
    sid: int
    protocol: str
    msg: str
    content_patterns: List[bytes] = field(default_factory=list)
    port_hint: Optional[int] = None


@dataclass
class TaggedFrame:
    """A network frame tagged with protocol information."""
    frame_index: int
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    matched_rules: List[str] = field(default_factory=list)
    payload_snippet: bytes = field(default_factory=bytes)


def load_suricata_rules(rules_path: str) -> List[SuricataRule]:
    """Parse a Suricata .rules file.

    Extracts: SID, protocol, msg, content patterns, destination ports.

    Args:
        rules_path: Path to .rules file.

    Returns:
        List of parsed SuricataRule objects.
    """
    rules = []
    try:
        text = Path(rules_path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return rules

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Extract SID
        sid_m = re.search(r"\bsid:(\d+)", line)
        if not sid_m:
            continue
        sid = int(sid_m.group(1))

        # Extract msg
        msg_m = re.search(r'msg:"([^"]+)"', line)
        msg = msg_m.group(1) if msg_m else f"SID:{sid}"

        # Extract protocol (first word after action)
        parts = line.split(None, 2)
        protocol = parts[1].lower() if len(parts) > 1 else "any"

        # Extract content patterns
        content_patterns = []
        for cm in re.finditer(r'content:"([^"]+)"', line):
            raw = cm.group(1)
            # Convert hex pipe patterns: |xx xx|
            try:
                def _decode(m):
                    return bytes.fromhex(m.group(1).replace(" ", ""))
                decoded = re.sub(r"\|([0-9a-fA-F ]+)\|", _decode, raw.encode()).decode("raw_unicode_escape").encode("raw_unicode_escape")
                content_patterns.append(raw.encode("latin-1", errors="replace"))
            except Exception:
                content_patterns.append(raw.encode("latin-1", errors="replace"))

        # Extract port hint from dst port
        port_m = re.search(r"\bany\s+(\d+)\s*->", line) or re.search(r"->\s*any\s+(\d+)", line)
        port_hint = int(port_m.group(1)) if port_m else None

        rules.append(SuricataRule(
            sid=sid,
            protocol=protocol,
            msg=msg,
            content_patterns=content_patterns,
            port_hint=port_hint,
        ))

    return rules


def _match_rule(rule: SuricataRule, payload: bytes) -> bool:
    """Check if payload matches a Suricata rule's content patterns."""
    if not rule.content_patterns:
        return False
    for pattern in rule.content_patterns[:3]:  # check first 3 patterns
        try:
            if pattern not in payload:
                return False
        except Exception:
            return False
    return True


def tag_pcap(
    pcap_path: str,
    rules_dir: Optional[str] = None,
    max_frames: int = 10_000,
) -> List[TaggedFrame]:
    """Tag PCAP frames with IoT protocol labels from Suricata rules.

    Args:
        pcap_path: Path to PCAP/PCAPNG file.
        rules_dir: Directory containing .rules files. Auto-discovers Suricata submodule.
        max_frames: Maximum frames to process.

    Returns:
        List of TaggedFrame objects with protocol matches.

    Raises:
        ImportError: If Scapy is not installed.
    """
    if not _SCAPY:
        raise ImportError("Scapy required: pip install scapy")

    # Auto-discover Suricata rules
    if rules_dir is None:
        wxf_root = Path(__file__).parents[5]
        candidates = [
            wxf_root / "FraudDetection" / "suricata" / "rules",
            wxf_root.parent / "FraudDetection" / "suricata" / "rules",
        ]
        for c in candidates:
            if c.is_dir():
                rules_dir = str(c)
                break

    rules: List[SuricataRule] = []
    if rules_dir:
        iot_rule_files = ["mqtt-events.rules", "mdns-events.rules",
                          "dhcp-events.rules", "modbus-events.rules"]
        for rf in iot_rule_files:
            rpath = Path(rules_dir) / rf
            if rpath.exists():
                rules.extend(load_suricata_rules(str(rpath)))

    packets = rdpcap(pcap_path)
    tagged: List[TaggedFrame] = []

    for i, pkt in enumerate(packets[:max_frames]):
        if not (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP))):
            continue

        ip = pkt[IP]
        is_tcp = pkt.haslayer(TCP)
        transport = pkt[TCP] if is_tcp else pkt[UDP]

        payload = bytes(transport.payload) if hasattr(transport, "payload") else b""
        if not payload:
            continue

        src_port = transport.sport
        dst_port = transport.dport

        matched = []
        for rule in rules:
            if rule.port_hint and rule.port_hint not in (src_port, dst_port):
                continue
            if _match_rule(rule, payload):
                matched.append(f"SID:{rule.sid} {rule.msg}")

        if matched:
            frame = TaggedFrame(
                frame_index=i,
                src_ip=str(ip.src),
                dst_ip=str(ip.dst),
                src_port=src_port,
                dst_port=dst_port,
                protocol="tcp" if is_tcp else "udp",
                matched_rules=matched,
                payload_snippet=payload[:32],
            )
            tagged.append(frame)

    return tagged
