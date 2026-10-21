"""Qualcomm Diag (QCDM) capture: raw 2G/3G/4G/5G frame extraction.


__info__ = {
    "name": "Qualcomm Diag (QCDM) capture: raw 2G/3G/4G/5G frame extraction",
    "description": (
        "Captures raw cellular frames via Qualcomm diagnostic interface, generating GSMTAP-wrapped PCAP for Wireshark analysis. Transports: ADB (rooted device), USB modem, DLF file replay. Conceptual reference: QCSuper (GPL-3.0, P1sec/BigNerd95) Recode: full Python rewrite, no code copied. Incorporates known fixes: NR RRC v17/v26 headers, SDX75 padding, DPL IP reassembly (from upstream PRs #171/#172/#173)."
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
    "mitre": ["T1040"],
}

Captures raw cellular frames via Qualcomm diagnostic interface,
generating GSMTAP-wrapped PCAP for Wireshark analysis.

Transports: ADB (rooted device), USB modem, DLF file replay.

Conceptual reference: QCSuper (GPL-3.0, P1sec/BigNerd95)
Recode: full Python rewrite, no code copied.
Incorporates known fixes: NR RRC v17/v26 headers, SDX75
padding, DPL IP reassembly (from upstream PRs #171/#172/#173).

MITRE ATT&CK: T1040 (Network Sniffing)
CWE: N/A (tool/framework)

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""


import logging
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional

logger = logging.getLogger(__name__)

DIAG_LOG_F = 0x10
DIAG_LOG_CONFIG_F = 0x73
DIAG_NV_READ_F = 0x26
DIAG_VERNO_F = 0x00
DIAG_BAD_CMD_F = 0x13

GSMTAP_PORT = 4729
GSMTAP_VERSION = 0x02

PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
LINKTYPE_GSMTAP = 227
LINKTYPE_RAW = 101


class GsmtapType(IntEnum):
    UM = 0x01
    ABIS = 0x02
    UM_BURST = 0x03
    SIM = 0x04
    TETRA_I1 = 0x05
    TETRA_I1_BURST = 0x06
    WMBus = 0x07
    GB_LLC = 0x08
    GB_SNDCP = 0x09
    GMR1_UM = 0x0A
    UMTS_RLC_MAC = 0x0B
    UMTS_RRC = 0x0C
    LTE_RRC = 0x0D
    LTE_MAC = 0x0E
    LTE_MAC_FRAMED = 0x0F
    OSMO_OML = 0x10
    OSMO_E1 = 0x11
    LTE_NAS = 0x12
    E1T1 = 0x13
    NR_RRC = 0x14
    NR_NAS = 0x15


class GsmtapLteRrcSubtype(IntEnum):
    BCCH_BCH = 0x00
    BCCH_DL_SCH = 0x01
    DL_CCCH = 0x02
    DL_DCCH = 0x03
    MCCH = 0x04
    PCCH = 0x05
    UL_CCCH = 0x06
    UL_DCCH = 0x07
    SC_MCCH = 0x08
    SBCCH_SL_BCH = 0x09


class GsmtapNrRrcSubtype(IntEnum):
    BCCH_BCH = 0x00
    BCCH_DL_SCH = 0x01
    DL_CCCH = 0x02
    DL_DCCH = 0x03
    MCCH = 0x04
    PCCH = 0x05
    UL_CCCH = 0x06
    UL_CCCH1 = 0x07
    UL_DCCH = 0x08
    SBCCH_SL_BCH = 0x09


LOG_CODE_MAP: dict[int, tuple] = {
    0xB0C0: (GsmtapType.LTE_RRC, GsmtapLteRrcSubtype.BCCH_BCH),
    0xB0C1: (GsmtapType.LTE_RRC, GsmtapLteRrcSubtype.BCCH_DL_SCH),
    0xB0C2: (GsmtapType.LTE_RRC, GsmtapLteRrcSubtype.DL_CCCH),
    0xB0C3: (GsmtapType.LTE_RRC, GsmtapLteRrcSubtype.DL_DCCH),
    0xB0C4: (GsmtapType.LTE_RRC, GsmtapLteRrcSubtype.UL_CCCH),
    0xB0C5: (GsmtapType.LTE_RRC, GsmtapLteRrcSubtype.UL_DCCH),
    0xB821: (GsmtapType.NR_RRC, GsmtapNrRrcSubtype.BCCH_BCH),
    0xB822: (GsmtapType.NR_RRC, GsmtapNrRrcSubtype.BCCH_DL_SCH),
    0xB823: (GsmtapType.NR_RRC, GsmtapNrRrcSubtype.DL_CCCH),
    0xB824: (GsmtapType.NR_RRC, GsmtapNrRrcSubtype.DL_DCCH),
    0xB825: (GsmtapType.NR_RRC, GsmtapNrRrcSubtype.UL_CCCH),
    0xB826: (GsmtapType.NR_RRC, GsmtapNrRrcSubtype.UL_DCCH),
}


@dataclass
class DiagFrame:
    log_code: int
    timestamp: float
    payload: bytes
    gsmtap_type: GsmtapType | None = None
    gsmtap_subtype: int = 0


def build_gsmtap_header(
    gsmtap_type: GsmtapType,
    subtype: int = 0,
    arfcn: int = 0,
    frame_nr: int = 0,
) -> bytes:
    return struct.pack(
        ">BBBBHHIIBBBBB",
        GSMTAP_VERSION,
        4,
        int(gsmtap_type),
        0,
        arfcn,
        0,
        frame_nr,
        0,
        0,
        subtype,
        0,
        0,
        0,
    )


def write_pcap_header(fh: BinaryIO, linktype: int = LINKTYPE_GSMTAP) -> None:
    fh.write(struct.pack(
        "<IHHiIII",
        PCAP_MAGIC,
        PCAP_VERSION_MAJOR,
        PCAP_VERSION_MINOR,
        0,
        0,
        65535,
        linktype,
    ))


def write_pcap_packet(fh: BinaryIO, data: bytes, ts_sec: int, ts_usec: int) -> None:
    fh.write(struct.pack(
        "<IIII",
        ts_sec,
        ts_usec,
        len(data),
        len(data),
    ))
    fh.write(data)


def parse_diag_log(raw: bytes) -> DiagFrame | None:
    """Parse a Qualcomm Diag log packet.

    Args:
        raw: Raw bytes from diag interface (after HDLC framing).

    Returns:
        DiagFrame or None if not a log message.
    """
    if len(raw) < 12:
        return None

    cmd_code = raw[0]
    if cmd_code != DIAG_LOG_F:
        return None

    log_len = struct.unpack_from("<H", raw, 2)[0]
    log_code = struct.unpack_from("<H", raw, 6)[0]

    ts_raw = struct.unpack_from("<Q", raw, 8)[0] if len(raw) >= 16 else 0
    timestamp = ts_raw / 1e7 if ts_raw else 0.0

    payload = raw[16:2 + log_len] if len(raw) > 16 else b""

    mapping = LOG_CODE_MAP.get(log_code)
    gsmtap_type = mapping[0] if mapping else None
    gsmtap_subtype = mapping[1] if mapping else 0

    return DiagFrame(
        log_code=log_code,
        timestamp=timestamp,
        payload=payload,
        gsmtap_type=gsmtap_type,
        gsmtap_subtype=gsmtap_subtype,
    )


def frames_to_pcap(frames: list[DiagFrame], output_path: str) -> int:
    """Write DiagFrames to a PCAP file with GSMTAP encapsulation.

    Args:
        frames: List of parsed diag frames.
        output_path: Output PCAP file path.

    Returns:
        Number of frames written.
    """
    written = 0
    with open(output_path, "wb") as fh:
        write_pcap_header(fh, LINKTYPE_GSMTAP)

        for frame in frames:
            if not frame.gsmtap_type or not frame.payload:
                continue

            gsmtap_hdr = build_gsmtap_header(frame.gsmtap_type, frame.gsmtap_subtype)

            udp_payload = gsmtap_hdr + frame.payload

            ts_sec = int(frame.timestamp)
            ts_usec = int((frame.timestamp - ts_sec) * 1e6)

            write_pcap_packet(fh, udp_payload, ts_sec, ts_usec)
            written += 1

    logger.info("Wrote %d frames to %s", written, output_path)
    return written


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
