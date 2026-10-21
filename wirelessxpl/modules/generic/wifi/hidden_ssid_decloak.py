"""Hidden SSID decloaking via passive probe response monitoring.


__info__ = {
    "name": "Hidden SSID decloaking via passive probe response monitoring",
    "description": (
        "Reveals hidden network SSIDs by monitoring probe requests from associated stations and probe responses from the AP. Conceptual reference: wifit3 campaigns/decloak.py (GPL-2.0, derv82) Recode: full Python rewrite using scapy, no code copied."
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
    "mitre": ["T1040"],
}

Reveals hidden network SSIDs by monitoring probe requests from
associated stations and probe responses from the AP.

Conceptual reference: wifit3 campaigns/decloak.py (GPL-2.0, derv82)
Recode: full Python rewrite using scapy, no code copied.

MITRE ATT&CK: T1040 (Network Sniffing)

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""


import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from collections.abc import Callable

logger = logging.getLogger(__name__)

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, sniff
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False


@dataclass
class HiddenNetwork:
    bssid: str
    channel: int = 0
    power: int = -100
    first_seen: float = 0.0
    decloaked_ssid: str | None = None
    decloaked_via: str = ""
    associated_stations: set[str] = field(default_factory=set)


def decloak_passive(
    interface: str,
    duration: int = 60,
    target_bssid: str | None = None,
    on_decloak: Callable[[HiddenNetwork], None] | None = None,
) -> list[HiddenNetwork]:
    """Passively monitor for hidden SSIDs.

    Listens for probe responses that reveal the SSID of hidden
    networks detected via beacons with empty/null SSID fields.

    Args:
        interface: Monitor-mode interface name.
        duration: Capture duration in seconds.
        target_bssid: Optional specific BSSID to target.
        on_decloak: Callback when a hidden SSID is revealed.

    Returns:
        List of HiddenNetwork objects (decloaked and not).
    """
    if not _SCAPY_OK:
        raise ImportError("scapy is required: pip install scapy")

    hidden: dict[str, HiddenNetwork] = {}
    start_time = time.time()

    def _process_packet(pkt):
        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]

        if pkt.haslayer(Dot11Beacon):
            bssid = dot11.addr3
            if not bssid:
                return
            bssid = bssid.lower()

            if target_bssid and bssid != target_bssid.lower():
                return

            ssid = b""
            try:
                ssid = pkt.info or b""
            except Exception:
                pass

            is_hidden = not ssid or ssid == b"\x00" * len(ssid)

            if is_hidden and bssid not in hidden:
                hidden[bssid] = HiddenNetwork(
                    bssid=bssid,
                    first_seen=time.time(),
                )
                logger.info("Hidden network detected: %s", bssid)

        if pkt.haslayer(Dot11ProbeResp):
            bssid = dot11.addr3
            if not bssid:
                return
            bssid = bssid.lower()

            if bssid in hidden and not hidden[bssid].decloaked_ssid:
                try:
                    ssid = pkt.info.decode("utf-8", errors="replace").strip()
                except Exception:
                    ssid = ""

                if ssid and ssid != "\x00" * len(ssid):
                    hidden[bssid].decloaked_ssid = ssid
                    hidden[bssid].decloaked_via = "probe-response"
                    logger.info("Decloaked %s -> %s (probe-response)", bssid, ssid)
                    if on_decloak:
                        on_decloak(hidden[bssid])

        if pkt.haslayer(Dot11ProbeReq):
            src = dot11.addr2
            if not src:
                return
            src = src.lower()

            for net in hidden.values():
                if not net.decloaked_ssid:
                    try:
                        ssid = pkt.info.decode("utf-8", errors="replace").strip()
                    except Exception:
                        ssid = ""
                    if ssid:
                        net.associated_stations.add(src)

    try:
        sniff(
            iface=interface,
            prn=_process_packet,
            timeout=duration,
            store=False,
        )
    except Exception as exc:
        logger.error("Sniff error on %s: %s", interface, exc)

    result = list(hidden.values())
    decloaked = sum(1 for n in result if n.decloaked_ssid)
    logger.info(
        "Decloak complete: %d hidden networks, %d decloaked in %ds",
        len(result),
        decloaked,
        int(time.time() - start_time),
    )
    return result


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
