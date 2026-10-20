#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Zigbee Network Realignment Attack module.

Forces Zigbee devices to rejoin the network by injecting IEEE 802.15.4
Coordinator Realignment or Orphan Notification frames. During the rejoin
process, the Trust Center re-transmits the network key via APS Transport Key
command, potentially exposing it if the default Trust Center link key is used.

Attack vectors:
  - Coordinator Realignment injection: craft a Realignment command frame that
    instructs the target device to switch to a new PAN ID or channel, forcing
    it to dissociate and rejoin.
  - Orphan Notification: send an Orphan Notification frame impersonating a
    device, triggering the coordinator to issue a Realignment response.
  - Rejoin Monitor: sniff for APS Transport Key frames during the device
    rejoin process (leverages zigbee_key_extract logic).

Requires KillerBee hardware (RZUSB, APIMOTE, CC253x, TelosB) for frame
injection. Uses KillerBee CLI tools (zbdump, zbreplay) via subprocess.

Scapy with 802.15.4 layers is used for frame crafting.

Version: 1.0.0
"""


import logging
import os
import shutil
import struct
import subprocess
from typing import List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

try:
    from scapy.all import (  # type: ignore[import-untyped]
        Dot15d4,
        Dot15d4Cmd,
        Dot15d4FCS,
        rdpcap,
        wrpcap,
    )
    from scapy.all import (
        raw as scapy_raw,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


MAC_CMD_COORD_REALIGNMENT = 0x08
MAC_CMD_ORPHAN_NOTIFICATION = 0x06
APS_CMD_TRANSPORT_KEY = 0x05


def _which_kb(tool: str) -> str | None:
    """Resolve KillerBee CLI tool from PATH."""
    return shutil.which(tool)


def _validate_short_addr(value: str) -> bool:
    """Validate a 16-bit short address in hex."""
    value = value.strip()
    if value.startswith("0x") or value.startswith("0X"):
        value = value[2:]
    if len(value) > 4 or not value:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def _parse_short_addr(value: str) -> int:
    """Parse a short address string to integer."""
    return int(value.strip().replace("0x", "").replace("0X", ""), 16)


@requires_os(OSRequirement.LINUX_ONLY)
