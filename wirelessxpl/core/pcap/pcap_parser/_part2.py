def extract_access_points(packets: list[Any]) -> dict[str, AccessPoint]:
    """Extract all access points from 802.11 beacon and probe-response frames.

    Args:
        packets: List of scapy packets.

    Returns:
        Dict mapping BSSID to AccessPoint.
    """
    aps: dict[str, AccessPoint] = {}
    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            continue

        bssid = pkt[Dot11].addr3
        if not bssid:
            continue
        bssid = bssid.upper()

        ssid = _extract_ssid(pkt)
        channel = _extract_channel(pkt)
        encryption, cipher, auth = _detect_encryption(pkt)

        if bssid in aps:
            ap = aps[bssid]
            ap.beacon_count += 1
            if ssid and not ap.ssid:
                ap.ssid = ssid
            if channel and not ap.channel:
                ap.channel = channel
        else:
            aps[bssid] = AccessPoint(
                bssid=bssid,
                ssid=ssid,
                channel=channel,
                encryption=encryption,
                cipher=cipher,
                auth=auth,
                beacon_count=1,
            )
    return aps


def extract_stations(packets: list[Any]) -> dict[str, Station]:
    """Extract client stations from 802.11 frames.

    Args:
        packets: List of scapy packets.

    Returns:
        Dict mapping station MAC to Station.
    """
    broadcast = {"FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"}
    stations: dict[str, Station] = {}

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt[Dot11]
        frame_type = dot11.type
        _frame_subtype = dot11.subtype

        # Probe requests → station with probed SSID
        if pkt.haslayer(Dot11ProbeReq):
            src = (dot11.addr2 or "").upper()
            if src and src not in broadcast:
                sta = stations.setdefault(src, Station(mac=src))
                ssid = _extract_ssid(pkt)
                if ssid:
                    sta.probed_ssids.add(ssid)
            continue

        # Data frames (type 2) → station associated to AP
        if frame_type == 2:
            to_ds = dot11.FCfield & 0x1
            from_ds = dot11.FCfield & 0x2

            if to_ds and not from_ds:
                client_mac = (dot11.addr2 or "").upper()
                bssid = (dot11.addr1 or "").upper()
            elif from_ds and not to_ds:
                client_mac = (dot11.addr1 or "").upper()
                bssid = (dot11.addr2 or "").upper()
            else:
                continue

            if client_mac and client_mac not in broadcast:
                sta = stations.setdefault(client_mac, Station(mac=client_mac))
                if bssid:
                    sta.associated_bssid = bssid
                sta.data_frames += 1

    return stations


def extract_eapol_handshakes(
    packets: list[Any],
    ap_map: dict[str, AccessPoint] | None = None,
) -> list[EAPOLHandshake]:
    """Extract WPA/WPA2 4-way EAPOL handshakes from capture.

    Args:
        packets: List of scapy packets.
        ap_map: Optional AP mapping to resolve SSIDs.

    Returns:
        List of EAPOLHandshake objects grouped by (BSSID, client_mac).
    """
    handshakes: dict[tuple[str, str], EAPOLHandshake] = {}

    for pkt in packets:
        if not pkt.haslayer(EAPOL):
            continue
        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt[Dot11]
        eapol_raw = bytes(pkt[EAPOL])
        msg_num = _classify_eapol_message(eapol_raw)
        if msg_num == 0:
            continue

        to_ds = dot11.FCfield & 0x1
        from_ds = dot11.FCfield & 0x2

        if to_ds and not from_ds:
            client_mac = (dot11.addr2 or "").upper()
            bssid = (dot11.addr1 or "").upper()
        elif from_ds and not to_ds:
            client_mac = (dot11.addr1 or "").upper()
            bssid = (dot11.addr2 or "").upper()
        else:
            bssid = (dot11.addr3 or dot11.addr1 or "").upper()
            client_mac = (dot11.addr2 or "").upper()

        key = (bssid, client_mac)
        hs = handshakes.setdefault(
            key,
            EAPOLHandshake(bssid=bssid, client_mac=client_mac),
        )
        hs.messages.append(msg_num)
        hs.packets.append(pkt)

        if ap_map and bssid in ap_map and not hs.ssid:
            hs.ssid = ap_map[bssid].ssid

    return list(handshakes.values())


def extract_cleartext_credentials(packets: list[Any]) -> list[ExtractedCredential]:
    """Extract cleartext credentials from TCP streams (HTTP, FTP, Telnet, SNMP).

    Args:
        packets: List of scapy packets.

    Returns:
        List of ExtractedCredential objects.
    """
    creds: list[ExtractedCredential] = []
    ftp_sessions: dict[tuple[str, str], dict[str, str]] = {}

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        if not pkt.haslayer(Raw):
            continue

        ip_layer = pkt[IP]
        payload = bytes(pkt[Raw].load)

        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            continue

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)

        # HTTP Basic Auth
        auth_match = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE)
        if auth_match:
            import base64
            try:
                decoded = base64.b64decode(auth_match.group(1)).decode("utf-8", errors="replace")
                user, _, pwd = decoded.partition(":")
                creds.append(ExtractedCredential(
                    protocol="HTTP-Basic",
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    username=user, password=pwd,
                ))
            except Exception:
                pass

        # HTTP form POST body (common patterns)
        if dst_port in (80, 8080, 443) or "POST" in text[:10]:
            form_user = re.search(
                r"(?:user(?:name)?|login|email)=([^&\s]+)", text, re.IGNORECASE
            )
            form_pass = re.search(
                r"(?:pass(?:word)?|pwd|passwd)=([^&\s]+)", text, re.IGNORECASE
            )
            if form_user and form_pass:
                creds.append(ExtractedCredential(
                    protocol="HTTP-Form",
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    username=form_user.group(1),
                    password=form_pass.group(1),
                ))

        # FTP USER/PASS
        if dst_port == 21 or src_port == 21:
            session_key = (src_ip, dst_ip) if dst_port == 21 else (dst_ip, src_ip)
            ftp_user_match = re.match(r"USER\s+(.+)\r?\n", text, re.IGNORECASE)
            ftp_pass_match = re.match(r"PASS\s+(.+)\r?\n", text, re.IGNORECASE)
            if ftp_user_match:
                ftp_sessions.setdefault(session_key, {})["user"] = ftp_user_match.group(1).strip()
            if ftp_pass_match:
                ftp_sessions.setdefault(session_key, {})["pass"] = ftp_pass_match.group(1).strip()

        # Telnet (raw login patterns)
        if dst_port == 23 or src_port == 23:
            login_match = re.search(r"(?:login|username):\s*(\S+)", text, re.IGNORECASE)
            pass_match = re.search(r"(?:password|passwd):\s*(\S+)", text, re.IGNORECASE)
            if login_match:
                creds.append(ExtractedCredential(
                    protocol="Telnet",
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    username=login_match.group(1),
                    password=pass_match.group(1) if pass_match else "",
                ))

        # SNMP community strings (v1/v2c) in UDP payload
        if pkt.haslayer(UDP) and (dst_port == 161 or src_port == 161):
            snmp_match = re.search(rb"[\x04]([\x20-\x7e]{2,32})", payload)
            if snmp_match:
                community = snmp_match.group(1).decode("ascii", errors="ignore")
                creds.append(ExtractedCredential(
                    protocol="SNMP",
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    username="", password="",
                    extra=f"community={community}",
                ))

    # Consolidate FTP sessions
    for (client_ip, server_ip), session in ftp_sessions.items():
        if "user" in session:
            creds.append(ExtractedCredential(
                protocol="FTP",
                src_ip=client_ip, dst_ip=server_ip,
                src_port=0, dst_port=21,
                username=session.get("user", ""),
                password=session.get("pass", ""),
            ))

    return creds


def save_handshake_pcap(
    handshake: EAPOLHandshake,
    output_path: str,
    include_beacons: list[Any] | None = None,
) -> Path:
    """Save EAPOL handshake packets to a standalone PCAP for cracking.

    Args:
        handshake: The EAPOLHandshake to export.
        output_path: Destination file path.
        include_beacons: Optional beacon packets to include (needed by some tools).

    Returns:
        Path to the written PCAP file.
    """
    from scapy.all import wrpcap

    out = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    pkts = []
    if include_beacons:
        pkts.extend(include_beacons)
    pkts.extend(handshake.packets)

    wrpcap(str(out), pkts)
    logger.info("Saved %d packets to %s", len(pkts), out)
    return out
