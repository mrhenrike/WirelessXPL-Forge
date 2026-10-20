#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""SIM/USIM/eSIM card reader and decoder using pySim and pyscard.

Read, decode, and export all accessible data from SIM/USIM/ISIM/eUICC cards
via PC/SC smart card reader. Supports multiple read modes including full card
dump, individual EF reads, SMS extraction, phonebook export, ATR decoding,
service table analysis, and eUICC profile information.

Modes:
  info           - Print capabilities and dependency status
  read_all       - Read all standard EFs (IMSI, ICCID, MSISDN, SMSP, PLMN, SPN, SST, ADN)
  read_imsi      - Read IMSI only
  read_iccid     - Read ICCID only
  read_sms       - Read stored SMS from EF_SMS
  read_phonebook - Read ADN (phonebook) entries
  decode_atr     - Parse and decode the ATR (Answer To Reset)
  export_json    - Export all readable card data to JSON file
  check_services - Read SST/UST/EST service tables
  esim_info      - Read eUICC identification and profile info

Version: 1.0.0
"""


import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.sim._disclaimer import (
    require_authorised_lab,
    require_sim_ownership,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency probing
# ---------------------------------------------------------------------------
HAS_PYSCARD = False
try:
    from smartcard.CardConnection import CardConnection  # type: ignore[import-untyped]
    from smartcard.System import readers as list_readers  # type: ignore[import-untyped]
    from smartcard.util import toBytes, toHexString  # type: ignore[import-untyped]
    HAS_PYSCARD = True
except ImportError:
    pass

HAS_PYSIM = False
try:
    from pySim.cards import SimCard  # type: ignore[import-untyped]
    from pySim.commands import SimCardCommands  # type: ignore[import-untyped]
    from pySim.transport.pcsc import PcscSimLink  # type: ignore[import-untyped]
    HAS_PYSIM = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# EF file identifiers (ISO 7816 / 3GPP TS 11.11 / 31.102)
# ---------------------------------------------------------------------------
EF_ICCID = [0x2F, 0xE2]
EF_IMSI = [0x6F, 0x07]
EF_MSISDN = [0x6F, 0x40]
EF_SMS = [0x6F, 0x3C]
EF_ADN = [0x6F, 0x3A]
EF_SST = [0x6F, 0x38]
EF_SPN = [0x6F, 0x46]
EF_SMSP = [0x6F, 0x42]
EF_PLMNSEL = [0x6F, 0x30]
EF_UST = [0x6F, 0x38]

DF_GSM = [0x7F, 0x20]
DF_TELECOM = [0x7F, 0x10]
ADF_USIM = [0x7F, 0xFF]

SW_OK = (0x90, 0x00)


def _hex(data: list[int]) -> str:
    """Format byte list as hex string."""
    return " ".join(f"{b:02X}" for b in data)


def _decode_bcd_imsi(data: list[int]) -> str:
    """Decode BCD-encoded IMSI from raw EF_IMSI bytes.

    First byte is the IMSI length. The second byte contains parity in
    the low nibble and the first MCC digit in the high nibble. Remaining
    bytes are standard BCD with nibble-swap.
    """
    if not data or len(data) < 2:
        return ""
    length = data[0]
    if length < 1 or length > 8:
        return ""
    imsi = ""
    first_digit = (data[1] >> 4) & 0x0F
    imsi += str(first_digit)
    for i in range(2, min(1 + length + 1, len(data) + 1)):
        if i >= len(data):
            break
        low = data[i] & 0x0F
        high = (data[i] >> 4) & 0x0F
        if low <= 9:
            imsi += str(low)
        if high <= 9:
            imsi += str(high)
    return imsi


def _decode_bcd_iccid(data: list[int]) -> str:
    """Decode BCD-encoded ICCID with nibble-swap, strip trailing F."""
    iccid = ""
    for byte_val in data:
        low = byte_val & 0x0F
        high = (byte_val >> 4) & 0x0F
        if low <= 9:
            iccid += str(low)
        elif low == 0x0F:
            pass
        else:
            iccid += f"{low:X}"
        if high <= 9:
            iccid += str(high)
        elif high == 0x0F:
            pass
        else:
            iccid += f"{high:X}"
    return iccid.rstrip("F").rstrip("f")


def _decode_alpha_id(data: list[int]) -> str:
    """Decode GSM 7-bit or UCS-2 alpha identifier from ADN/MSISDN records."""
    if not data:
        return ""
    if data[0] == 0x80 and len(data) > 2:
        # UCS-2 encoding
        chars = []
        for i in range(1, len(data) - 1, 2):
            code = (data[i] << 8) | data[i + 1]
            if code == 0xFFFF or code == 0x0000:
                break
            chars.append(chr(code))
        return "".join(chars)
    result = ""
    for b in data:
        if b == 0xFF:
            break
        if 0x20 <= b <= 0x7E:
            result += chr(b)
    return result


def _decode_dialing_number(data: list[int]) -> str:
    """Decode BCD dialing number from ADN/MSISDN record."""
    number = ""
    for byte_val in data:
        low = byte_val & 0x0F
        high = (byte_val >> 4) & 0x0F
        if low <= 9:
            number += str(low)
        elif low == 0x0A:
            number += "*"
        elif low == 0x0B:
            number += "#"
        elif low == 0x0F:
            break
        if high <= 9:
            number += str(high)
        elif high == 0x0A:
            number += "*"
        elif high == 0x0B:
            number += "#"
        elif high == 0x0F:
            break
    return number


def _decode_atr_bytes(atr: list[int]) -> dict[str, Any]:
    """Parse ATR (Answer To Reset) according to ISO 7816-3."""
    result: dict[str, Any] = {
        "raw_hex": _hex(atr),
        "ts": "",
        "t0": "",
        "historical_bytes": "",
        "protocols": [],
    }
    if not atr:
        return result

    ts = atr[0]
    result["ts"] = "direct" if ts == 0x3B else ("inverse" if ts == 0x3F else f"unknown(0x{ts:02X})")

    if len(atr) < 2:
        return result

    t0 = atr[1]
    num_historical = t0 & 0x0F
    result["t0"] = f"0x{t0:02X} (historical bytes: {num_historical})"

    idx = 2
    protocols = set()

    y = t0
    while idx < len(atr):
        if y & 0x10:
            idx += 1  # TA
        if y & 0x20:
            idx += 1  # TB
        if y & 0x40:
            idx += 1  # TC
        if y & 0x80:
            if idx < len(atr):
                td = atr[idx]
                protocols.add(td & 0x0F)
                y = td
                idx += 1
            else:
                break
        else:
            break

    result["protocols"] = sorted(protocols)

    if num_historical > 0 and idx + num_historical <= len(atr):
        hist = atr[idx:idx + num_historical]
        result["historical_bytes"] = _hex(hist)
        printable = ""
        for b in hist:
            printable += chr(b) if 0x20 <= b <= 0x7E else "."
        result["historical_ascii"] = printable

    return result


class Exploit(Exploit):
    """SIM/USIM/eSIM card reader and decoder via PC/SC interface."""

    __info__ = {
        "name": "pySim SIM Card Reader",
        "description": (
            "Read, decode, and export data from SIM/USIM/ISIM/eUICC cards "
            "via PC/SC smart card reader. Supports IMSI, ICCID, MSISDN, "
            "SMS, phonebook, ATR decoding, service tables, and eUICC info. "
            "Uses pyscard for low-level APDU and pySim for higher-level operations."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/osmocom/pysim",
            "https://pyscard.sourceforge.io/",
            "3GPP TS 11.11 (SIM), 3GPP TS 31.102 (USIM)",
            "ISO/IEC 7816-3 (ATR), ISO/IEC 7816-4 (APDU)",
            "GSMA SGP.22 (eUICC / eSIM)",
        ),
        "devices": ("SIM", "USIM", "ISIM", "eUICC", "eSIM"),
    }

    mode = OptString(
        "info",
        "Modo: info | read_all | read_imsi | read_iccid | read_sms | "
        "read_phonebook | decode_atr | export_json | check_services | esim_info",
    )
    reader_index = OptInteger(0, "Indice do leitor PC/SC (padrao: 0)")
    pin = OptString("", "PIN do SIM (se necessario para acesso)")
    output_file = OptString("", "Arquivo de saida para export_json")
    output_dir = OptString(".tmp", "Diretorio de saida")
    max_records = OptInteger(250, "Maximo de registros a ler (SMS, ADN)")
    dry_run = OptBool(False, "Exibir operacoes sem executar")
    i_know_scope = OptBool(False, "Confirm authorized lab environment and SIM ownership")

    _VALID_MODES = frozenset({
        "info", "read_all", "read_imsi", "read_iccid", "read_sms",
        "read_phonebook", "decode_atr", "export_json", "check_services",
        "esim_info",
    })

    # ------------------------------------------------------------------
    # Infrastructure
    # ------------------------------------------------------------------

    def _ensure_output_dir(self) -> str | None:
        out = str(self.output_dir).strip() or ".tmp"
        try:
            os.makedirs(out, exist_ok=True)
            return out
        except OSError as exc:
            print_error(f"Falha ao criar diretorio de saida: {exc}")
            return None

    def _get_connection(self) -> Any | None:
        """Establish PC/SC connection to the SIM card."""
        if not HAS_PYSCARD:
            print_error("pyscard nao instalado. pip install pyscard")
            return None

        try:
            available = list_readers()
        except Exception as exc:
            print_error(f"Falha ao listar leitores PC/SC: {exc}")
            return None

        if not available:
            print_error("Nenhum leitor PC/SC detectado.")
            return None

        idx = int(self.reader_index)
        if idx < 0 or idx >= len(available):
            print_error(
                f"Indice {idx} invalido. Leitores disponiveis: {len(available)}"
            )
            for i, r in enumerate(available):
                print_info(f"  [{i}] {r}")
            return None

        reader = available[idx]
        print_status(f"Conectando ao leitor: {reader}")

        try:
            conn = reader.createConnection()
            conn.connect()
            return conn
        except Exception as exc:
            print_error(f"Falha na conexao com o cartao: {exc}")
            return None

    def _send_apdu(self, conn: Any, apdu: list[int]) -> tuple[list[int], int, int]:
        """Transmit APDU and return (data, sw1, sw2)."""
        data, sw1, sw2 = conn.transmit(apdu)
        if sw1 == 0x61:
            get_resp = [0x00, 0xC0, 0x00, 0x00, sw2]
            data, sw1, sw2 = conn.transmit(get_resp)
        return data, sw1, sw2

    def _select_file(self, conn: Any, fid: list[int]) -> tuple[bool, list[int]]:
        """SELECT a file by FID. Returns (success, response_data)."""
        apdu = [0x00, 0xA4, 0x00, 0x00, 0x02] + fid
        data, sw1, sw2 = self._send_apdu(conn, apdu)
        if (sw1, sw2) == SW_OK or sw1 == 0x61 or sw1 == 0x9F:
            return True, data
        if sw1 == 0x6C:
            apdu_retry = [0x00, 0xA4, 0x00, 0x00, 0x02] + fid
            data, sw1, sw2 = self._send_apdu(conn, apdu_retry)
            if (sw1, sw2) == SW_OK:
                return True, data
        return False, []

    def _read_binary(self, conn: Any, length: int = 0, offset: int = 0) -> tuple[bool, list[int]]:
        """READ BINARY from the currently selected EF."""
        if length == 0:
            length = 0xFF
        p1 = (offset >> 8) & 0x7F
        p2 = offset & 0xFF
        apdu = [0x00, 0xB0, p1, p2, length]
        data, sw1, sw2 = self._send_apdu(conn, apdu)
        if (sw1, sw2) == SW_OK:
            return True, data
        if sw1 == 0x6C and sw2 > 0:
            apdu[4] = sw2
            data, sw1, sw2 = self._send_apdu(conn, apdu)
            if (sw1, sw2) == SW_OK:
                return True, data
        return False, []

    def _read_record(self, conn: Any, record_num: int, length: int = 0) -> tuple[bool, list[int]]:
        """READ RECORD (absolute mode) from the currently selected EF."""
        if length == 0:
            length = 0xFF
        apdu = [0x00, 0xB2, record_num, 0x04, length]
        data, sw1, sw2 = self._send_apdu(conn, apdu)
        if (sw1, sw2) == SW_OK:
            return True, data
        if sw1 == 0x6C and sw2 > 0:
            apdu[4] = sw2
            data, sw1, sw2 = self._send_apdu(conn, apdu)
            if (sw1, sw2) == SW_OK:
                return True, data
        return False, []

    def _verify_pin(self, conn: Any) -> bool:
        """Verify CHV1 (PIN1) if provided."""
        pin_str = str(self.pin).strip()
        if not pin_str:
            return True
        if len(pin_str) < 4 or len(pin_str) > 8:
            print_error("PIN deve ter entre 4 e 8 digitos.")
            return False
        if not pin_str.isdigit():
            print_error("PIN deve conter apenas digitos.")
            return False

        pin_bytes = [ord(c) for c in pin_str]
        while len(pin_bytes) < 8:
            pin_bytes.append(0xFF)

        apdu = [0x00, 0x20, 0x00, 0x01, 0x08] + pin_bytes
        _, sw1, sw2 = self._send_apdu(conn, apdu)
        if (sw1, sw2) == SW_OK:
            print_success("PIN verificado com sucesso.")
            return True
        if sw1 == 0x63:
            remaining = sw2 & 0x0F
            print_error(f"PIN incorreto. Tentativas restantes: {remaining}")
        elif sw1 == 0x69 and sw2 == 0x83:
            print_error("PIN bloqueado. Use PUK para desbloqueio.")
        else:
            print_error(f"Falha na verificacao do PIN: SW={sw1:02X}{sw2:02X}")
        return False

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def _read_imsi(self, conn: Any) -> str:
        ok, _ = self._select_file(conn, DF_GSM)
        if not ok:
            ok, _ = self._select_file(conn, ADF_USIM)
        ok, _ = self._select_file(conn, EF_IMSI)
        if not ok:
            return ""
        ok, data = self._read_binary(conn, 9)
        if not ok or not data:
            return ""
        return _decode_bcd_imsi(data)

    def _read_iccid(self, conn: Any) -> str:
        ok, _ = self._select_file(conn, EF_ICCID)
        if not ok:
            return ""
        ok, data = self._read_binary(conn, 10)
        if not ok or not data:
            return ""
        return _decode_bcd_iccid(data)

    def _read_msisdn(self, conn: Any) -> str:
        ok, _ = self._select_file(conn, DF_TELECOM)
        if not ok:
            ok, _ = self._select_file(conn, DF_GSM)
        ok, _ = self._select_file(conn, EF_MSISDN)
