def extract_sae_commits(packets: list[Any], ssid_map: dict[str, str] | None = None) -> DragonbloodAnalysis:
    """Extract SAE (Dragonfly) commit frames for Dragonblood analysis.

    Detects CVE-2019-9494 (timing side-channel), CVE-2019-9496 (transition
    mode downgrade) and weak group usage from captured SAE authentication frames.

    Args:
        packets: List of scapy packets.
        ssid_map: Optional BSSID → SSID mapping.

    Returns:
        DragonbloodAnalysis with commits and vulnerability indicators.
    """
    if ssid_map is None:
        ssid_map = _build_ssid_map(packets)

    commits: list[SAECommit] = []
    timestamps: list[float] = []
    transition_mode = False
    group_downgrade = False
    seen_groups: set[int] = set()
    primary_bssid = ""
    last_ts: float = 0.0

    for idx, pkt in enumerate(packets):
        if not pkt.haslayer(Dot11):
            continue
        if not pkt.haslayer(Dot11Auth):
            continue

        dot11 = pkt[Dot11]
        auth = pkt[Dot11Auth]

        # SAE uses algo=3 (SAE) or algo=4 (SAE with FT)
        if auth.algo not in (3, 4):
            # Check for transition mode: WPA3 AP also accepts algo=0 (Open)
            if auth.algo == 0:
                bssid = (dot11.addr3 or dot11.addr1 or "").upper()
                if bssid and bssid in ssid_map:
                    transition_mode = True
            continue

        # seq_num 1 = Commit, seq_num 2 = Confirm
        if auth.seqnum != 1:
            continue

        bssid = (dot11.addr3 or dot11.addr1 or "").upper()
        client = (dot11.addr2 or "").upper()
        if not primary_bssid:
            primary_bssid = bssid

        # Parse SAE commit body (after auth header)
        body = bytes(auth.payload) if auth.payload else b""
        if len(body) < 36:
            continue

        # SAE commit: group_id(2) + anti_clogging_token(variable) + scalar(32) + element(64)
        group_id = struct.unpack("<H", body[0:2])[0]
        seen_groups.add(group_id)

        # Simplified: assume no anti-clogging token for initial commit
        scalar = body[2:34]
        element = body[34:98] if len(body) >= 98 else body[34:]
        anti_clogging = None

        ts = float(pkt.time) * 1e6 if hasattr(pkt, "time") else idx * 1000.0

        commits.append(SAECommit(
            bssid=bssid,
            client_mac=client,
            ssid=ssid_map.get(bssid, ""),
            group_id=group_id,
            scalar=scalar,
            element=element,
            anti_clogging_token=anti_clogging,
            timestamp_us=ts,
            frame_index=idx,
        ))

        if last_ts > 0:
            timestamps.append(ts - last_ts)
        last_ts = ts

    # Check group downgrade: if multiple groups seen, attacker may force weaker group
    if len(seen_groups) > 1:
        group_downgrade = True

    # Timing analysis: high variance in commit timing may indicate cache/timing side-channel
    timing_suspicious = False
    if len(timestamps) >= 3:
        avg = sum(timestamps) / len(timestamps)
        variance = sum((t - avg) ** 2 for t in timestamps) / len(timestamps)
        std_dev = variance ** 0.5
        # Coefficient of variation > 0.5 is suspicious
        if avg > 0 and (std_dev / avg) > 0.5:
            timing_suspicious = True

    return DragonbloodAnalysis(
        bssid=primary_bssid,
        ssid=ssid_map.get(primary_bssid, ""),
        commits=commits,
        timing_deltas_us=timestamps,
        group_downgrade_detected=group_downgrade,
        transition_mode_detected=transition_mode,
        timing_variance_suspicious=timing_suspicious,
    )


# =====================================================================
# WPE — EAP/PEAP/MSCHAPv2 identity + challenge harvest
# =====================================================================

def extract_eap_identities(packets: list[Any], ssid_map: dict[str, str] | None = None) -> list[EAPIdentity]:
    """Extract EAP identities and challenge-response pairs for WPE-style offline attacks.

    Captures EAP-PEAP, EAP-TTLS, EAP-MD5, LEAP and MSCHAPv2 exchanges
    from PCAPs (typically from evil-twin / rogue AP captures).

    Args:
        packets: List of scapy packets.
        ssid_map: Optional BSSID → SSID mapping.

    Returns:
        List of EAPIdentity objects.
    """
    if ssid_map is None:
        ssid_map = _build_ssid_map(packets)

    EAP_TYPE_MAP = {
        1: "EAP-Identity",
        4: "EAP-MD5",
        13: "EAP-TLS",
        17: "LEAP",
        21: "EAP-TTLS",
        25: "PEAP",
        26: "MSCHAPv2",
        43: "EAP-FAST",
    }

    sessions: dict[str, dict[str, Any]] = {}  # keyed by client_mac
    results: list[EAPIdentity] = []

    for pkt in packets:
        if not pkt.haslayer(EAP):
            continue

        eap = pkt[EAP]
        eap_code = eap.code  # 1=Request, 2=Response, 3=Success, 4=Failure
        eap_type = eap.type if hasattr(eap, "type") else 0

        bssid = ""
        client = ""
        if pkt.haslayer(Dot11):
            dot11 = pkt[Dot11]
            to_ds = dot11.FCfield & 0x1
            from_ds = dot11.FCfield & 0x2
            if to_ds and not from_ds:
                bssid = (dot11.addr1 or "").upper()
                client = (dot11.addr2 or "").upper()
            elif from_ds and not to_ds:
                bssid = (dot11.addr2 or "").upper()
                client = (dot11.addr1 or "").upper()
            else:
                bssid = (dot11.addr3 or "").upper()
                client = (dot11.addr2 or "").upper()

        if not client:
            continue

        session = sessions.setdefault(client, {
            "bssid": bssid,
            "identity": "",
            "eap_type": "",
            "challenge": None,
            "response": None,
            "success": None,
        })

        if bssid:
            session["bssid"] = bssid

        eap_payload = bytes(eap.payload) if eap.payload else b""

        # Identity response
        if eap_code == 2 and eap_type == 1:
            identity = eap_payload.decode("utf-8", errors="replace").strip("\x00").strip()
            if identity:
                session["identity"] = identity

        # EAP-MD5 Challenge
        elif eap_type == 4:
            if eap_code == 1 and len(eap_payload) >= 17:  # Request with challenge
                value_size = eap_payload[0]
                session["challenge"] = eap_payload[1:1 + value_size]
                session["eap_type"] = "EAP-MD5"
            elif eap_code == 2 and len(eap_payload) >= 17:  # Response
                value_size = eap_payload[0]
                session["response"] = eap_payload[1:1 + value_size]

        # LEAP
        elif eap_type == 17:
            session["eap_type"] = "LEAP"
            if eap_code == 1 and len(eap_payload) >= 11:
                session["challenge"] = eap_payload[3:11]  # 8-byte challenge
            elif eap_code == 2 and len(eap_payload) >= 27:
                session["response"] = eap_payload[3:27]  # 24-byte response

        # MSCHAPv2 (inside EAP or standalone)
        elif eap_type == 26:
            session["eap_type"] = "MSCHAPv2"
            if len(eap_payload) >= 4:
                mschap_opcode = eap_payload[0]
                if mschap_opcode == 1 and len(eap_payload) >= 20:  # Challenge
                    session["challenge"] = eap_payload[4:20]
                elif mschap_opcode == 2 and len(eap_payload) >= 54:  # Response
                    session["response"] = eap_payload[4:54]  # peer challenge + NT response

        # PEAP / EAP-TTLS (mark the type, inner auth extracted above if decrypted)
        elif eap_type in (21, 25):
            session["eap_type"] = EAP_TYPE_MAP.get(eap_type, "PEAP/TTLS")

        # EAP-FAST
        elif eap_type == 43:
            session["eap_type"] = "EAP-FAST"

        # Success/Failure
        if eap_code == 3:
            session["success"] = True
        elif eap_code == 4:
            session["success"] = False

    # Build results from sessions with identities or challenge/response
    for client_mac, sess in sessions.items():
        if not sess["identity"] and not sess["challenge"]:
            continue

        bssid = sess["bssid"]
        ssid = ssid_map.get(bssid, "")
        eap_type = sess["eap_type"] or "Unknown"

        hashcat_line = ""
        if sess["challenge"] and sess["response"]:
            if eap_type == "MSCHAPv2":
                # NetNTLMv1 / MSCHAPv2 hashcat format (mode 5500)
                hashcat_line = "{}::::{}:{}".format(
                    sess["identity"] or "unknown",
                    sess["response"].hex(),
                    sess["challenge"].hex(),
                )
            elif eap_type == "LEAP":
                hashcat_line = "{}:$LEAP${}${}".format(
                    sess["identity"] or "unknown",
                    sess["challenge"].hex(),
                    sess["response"].hex(),
                )
            elif eap_type == "EAP-MD5":
                hashcat_line = "{}:$MD5${}${}".format(
                    sess["identity"] or "unknown",
                    sess["challenge"].hex(),
                    sess["response"].hex(),
                )

        results.append(EAPIdentity(
            bssid=bssid,
            client_mac=client_mac,
            ssid=ssid,
            eap_type=eap_type,
            identity=sess["identity"],
            challenge=sess["challenge"],
            response=sess["response"],
            success=sess["success"],
            hashcat_line=hashcat_line,
        ))

    return results


# =====================================================================
# Shared helpers
# =====================================================================

def _build_ssid_map(packets: list[Any]) -> dict[str, str]:
    """Build BSSID → SSID mapping from beacons/probe-responses."""
    ssid_map: dict[str, str] = {}
    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = (pkt[Dot11].addr3 or "").upper()
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    try:
                        ssid_map[bssid] = elt.info.decode("utf-8", errors="replace").strip("\x00")
                    except Exception:
                        pass
                    break
                elt = elt.payload.getlayer(Dot11Elt)
    return ssid_map


@dataclass
class EAPOLFourwaySurveyRow:
    """Aggregated EAPOL Key 4-way handshake observations for one AP + STA pair."""

    bssid: str
    station_mac: str
    ssid: str
    message_counts: dict[str, int]
    distinct_anonce: int
    distinct_snonce: int
    replay_counters_seen: list[int]
    hints: list[str]


def _bssid_sta_from_dot11(dot11: Any) -> tuple[str, str]:
    """Derive BSSID and STA MAC from a Dot11 wrapper around EAPOL."""

    to_ds = int(dot11.FCfield) & 0x1
    from_ds = int(dot11.FCfield) & 0x2
    if from_ds and not to_ds:
        bssid = (dot11.addr2 or "").upper()
        sta = (dot11.addr1 or "").upper()
    elif to_ds and not from_ds:
        bssid = (dot11.addr1 or "").upper()
        sta = (dot11.addr2 or "").upper()
    else:
        bssid = (dot11.addr3 or dot11.addr2 or "").upper()
        sta = (dot11.addr1 or dot11.addr2 or "").upper()
        if sta == bssid:
            sta = (dot11.addr1 if (dot11.addr1 or "").upper() != bssid else dot11.addr2 or "").upper()
    return bssid, sta


def _classify_eapol_key_message(key_info: int) -> str:
    """Heuristic 802.11i 4-way EAPOL-Key message label from Key Information field."""

    ack = bool(key_info & 0x0080)
    mic = bool(key_info & 0x0100)
    secure = bool(key_info & 0x0200)
    if ack and not mic:
        return "msg1"
    if mic and (not ack) and (not secure):
        return "msg2"
    if ack and mic and (not secure):
        return "msg3"
    if mic and (not ack) and secure:
        return "msg4"
    return "unknown"


def survey_eapol_fourway_sessions(
    packets: list[Any],
    ssid_map: dict[str, str] | None = None,
) -> list[EAPOLFourwaySurveyRow]:
    """Summarise WPA/WPA2 EAPOL 4-way exchanges: counts, nonces, replay counters, KRACK-style hints.

    Does not crack keys; pairs well with ``aircrack-ng``/hashcat after ``pcap_handshake_extractor``.

    References:
        • KRACK (CVE-2017-13077, CVE-2017-13078, …) — nonce/reinstall behaviour in handshakes.
        • Dragonblood (CVE-2019-9494, CVE-2019-9496) — use ``pcap_dragonblood`` for WPA3-SAE.

    Args:
        packets: Scapy packets from a PCAP/PCAPNG.
        ssid_map: Optional BSSID → SSID map (built from beacons when omitted).

    Returns:
        One row per (BSSID, STA) pair that had EAPOL-Key traffic.
    """

    if ssid_map is None:
        ssid_map = _build_ssid_map(packets)

    counts: defaultdict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"msg1": 0, "msg2": 0, "msg3": 0, "msg4": 0, "unknown": 0}
    )
    anonces: defaultdict[tuple[str, str], list[bytes]] = defaultdict(list)
    snonces: defaultdict[tuple[str, str], list[bytes]] = defaultdict(list)
    replays: defaultdict[tuple[str, str], list[int]] = defaultdict(list)

    for pkt in packets:
        if not pkt.haslayer(EAPOL) or not pkt.haslayer(Dot11):
            continue
        eapol_raw = bytes(pkt[EAPOL])
        if len(eapol_raw) < 99:
            continue
        try:
            key_info = struct.unpack("!H", eapol_raw[5:7])[0]
        except struct.error:
            continue
        label = _classify_eapol_key_message(key_info)
        dot11 = pkt[Dot11]
        bssid, sta = _bssid_sta_from_dot11(dot11)
        if not bssid or not sta:
            continue
        pair = (bssid, sta)
        if label in counts[pair]:
            counts[pair][label] += 1
        else:
            counts[pair]["unknown"] += 1

        replay = 0
        if len(eapol_raw) >= 17:
            try:
                replay = struct.unpack("!Q", eapol_raw[9:17])[0]
            except struct.error:
                replay = 0
        replays[pair].append(replay)

        nonce = eapol_raw[17:49] if len(eapol_raw) >= 49 else b""
        if nonce and len(nonce) == 32:
            if label in ("msg1", "msg3"):
                anonces[pair].append(nonce)
            elif label in ("msg2", "msg4"):
                snonces[pair].append(nonce)

    rows: list[EAPOLFourwaySurveyRow] = []
    for (bssid, sta), msg_counts in counts.items():
        if sum(msg_counts[k] for k in ("msg1", "msg2", "msg3", "msg4", "unknown")) == 0:
            continue
        hints: list[str] = []
        au = len({x.hex() for x in anonces[(bssid, sta)]})
        su = len({x.hex() for x in snonces[(bssid, sta)]})
        anonce_list = anonces[(bssid, sta)]
        if len(anonce_list) != len({x.hex() for x in anonce_list}):
            hints.append(
                "Repeated ANonce across EAPOL-Key frames — review for KRACK-style "
                "reinstall / nonce reuse (CVE-2017-13077 family)."
            )
        rc_list = replays[(bssid, sta)]
        if len(rc_list) >= 2 and any(rc_list[i] > rc_list[i + 1] for i in range(len(rc_list) - 1)):
            hints.append("Replay counter decreased in sequence — unusual capture or reordering.")
        if msg_counts["msg3"] and not msg_counts["msg4"]:
            hints.append("M3 seen without M4 — incomplete handshake (common in deauth-heavy captures).")
        if msg_counts["msg1"] and msg_counts["msg2"] and not msg_counts["msg3"]:
            hints.append("M1/M2 only — PTK may not complete; check capture duration / channel.")

        rows.append(
            EAPOLFourwaySurveyRow(
                bssid=bssid,
                station_mac=sta,
                ssid=ssid_map.get(bssid, ""),
                message_counts=dict(msg_counts),
                distinct_anonce=au,
                distinct_snonce=su,
                replay_counters_seen=sorted(set(rc_list)),
                hints=hints,
            )
        )

    rows.sort(key=lambda r: (r.bssid, r.station_mac))
    return rows
