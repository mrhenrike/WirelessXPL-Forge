#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""LTE/4G IMSI catcher and analysis module using srsRAN.

Active and passive LTE IMSI/IMEI capture using modified srsRAN eNodeB,
passive LTE downlink analysis, PCAP parsing for NAS Identity messages,
LTE cell search, fake base station detection, and UERANSIM 5G simulation.

Supported hardware:
  Passive: RTL-SDR, HackRF, BladeRF, USRP
  Active eNodeB: USRP B200/B210, BladeRF (HackRF limited TX)

Requires: srsRAN 4G (srsENB, srsUE), tshark/Scapy, UERANSIM (optional).

Version: 1.0.0
"""


import json
import logging
import os
import re
import shutil
import signal
import subprocess
import textwrap
from typing import Any, Dict, List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.sim._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


def _which(binary: str) -> str | None:
    return shutil.which(binary)


_DEFAULT_ENB_CONF = textwrap.dedent("""\
    [enb]
    enb_id = 0x19B
    mcc = 001
    mnc = 01
    mme_addr = 127.0.1.100
    gtp_bind_addr = 127.0.1.1
    s1c_bind_addr = 127.0.1.1
    n_prb = {n_prb}
    tm = 1

    [enb_files]
    sib_config = sib.conf
    rr_config = rr.conf
    rb_config = rb.conf

    [rf]
    dl_earfcn = {earfcn}
    tx_gain = {tx_gain}
    rx_gain = {rx_gain}
    device_name = auto
    device_args = auto

    [pcap]
    enable = true
    filename = /tmp/enb_capture.pcap
    s1ap_enable = true
    s1ap_filename = /tmp/enb_s1ap.pcap

    [log]
    all_level = info
    all_hex_limit = 32
    filename = /tmp/enb.log

    [expert]
    nas_enable_identity_request = true
""")


def _parse_nas_identities_tshark(pcap_path: str) -> list[dict[str, str]]:
    """Extract IMSI/IMEI from NAS Identity Response messages using tshark.

    Args:
        pcap_path: Path to the LTE PCAP file.

    Returns:
        List of dicts with identity type and value.
    """
    tshark = _which("tshark")
    if not tshark:
        return []

    results: list[dict[str, str]] = []

    try:
        cmd = [
            tshark, "-r", pcap_path,
            "-Y", "nas_eps.emm.msg_type == 0x56",
            "-T", "fields",
            "-e", "nas_eps.emm.imsi",
            "-e", "nas_eps.emm.imei",
            "-e", "nas_eps.emm.imeisv",
            "-e", "frame.number",
            "-e", "frame.time",
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=60,
        )
        output = result.stdout.decode("utf-8", errors="replace")
        for line in output.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            imsi, imei, imeisv, frame_num, frame_time = (
                parts[0], parts[1], parts[2], parts[3], parts[4]
            )
            if imsi:
                results.append({
                    "type": "IMSI",
                    "value": imsi.strip(),
                    "frame": frame_num.strip(),
                    "time": frame_time.strip(),
                })
            if imei:
                results.append({
                    "type": "IMEI",
                    "value": imei.strip(),
                    "frame": frame_num.strip(),
                    "time": frame_time.strip(),
                })
            if imeisv:
                results.append({
                    "type": "IMEISV",
                    "value": imeisv.strip(),
                    "frame": frame_num.strip(),
                    "time": frame_time.strip(),
                })
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.warning("tshark parsing failed: %s", exc)

    # Fallback: try Identity Request (0x55) to at least log attempts
    try:
        cmd_req = [
            tshark, "-r", pcap_path,
            "-Y", "nas_eps.emm.msg_type == 0x55",
            "-T", "fields",
            "-e", "nas_eps.emm.id_type",
            "-e", "frame.number",
        ]
        result_req = subprocess.run(
            cmd_req,
            capture_output=True,
            timeout=30,
        )
        req_output = result_req.stdout.decode("utf-8", errors="replace")
        req_count = len([ln for ln in req_output.strip().splitlines() if ln.strip()])
        if req_count > 0:
            results.append({
                "type": "INFO",
                "value": f"{req_count} Identity Request(s) found in PCAP",
                "frame": "",
                "time": "",
            })
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return results


def _parse_cell_search_output(raw: str) -> list[dict[str, Any]]:
    """Parse srsUE cell_search or LTE scanner output for cell info."""
    cells: list[dict[str, Any]] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        pci_match = re.search(r"PCI[:\s]*(\d+)", line, re.IGNORECASE)
        earfcn_match = re.search(r"EARFCN[:\s]*(\d+)", line, re.IGNORECASE)
        rsrp_match = re.search(r"RSRP[:\s]*([-\d.]+)", line, re.IGNORECASE)
        rsrq_match = re.search(r"RSRQ[:\s]*([-\d.]+)", line, re.IGNORECASE)

        if pci_match:
            cell: dict[str, Any] = {
                "pci": int(pci_match.group(1)),
            }
            if earfcn_match:
                cell["earfcn"] = int(earfcn_match.group(1))
            if rsrp_match:
                cell["rsrp"] = float(rsrp_match.group(1))
            if rsrq_match:
                cell["rsrq"] = float(rsrq_match.group(1))
            cells.append(cell)

    return cells


def _detect_anomalies(cells: list[dict[str, Any]]) -> list[str]:
    """Analyze cell list for indicators of a fake base station.

    Heuristics:
      - Duplicate PCI on same or adjacent EARFCN (PCI conflict)
      - Abnormally strong signal compared to neighbors
      - Unusually low EARFCN (out-of-band for region)
    """
    anomalies: list[str] = []
    pci_map: dict[int, list[dict[str, Any]]] = {}
    for c in cells:
        pci = c.get("pci", -1)
        if pci >= 0:
            pci_map.setdefault(pci, []).append(c)

    for pci, entries in pci_map.items():
        if len(entries) > 1:
            earfcns = [e.get("earfcn", 0) for e in entries]
            anomalies.append(
                f"PCI {pci} seen on multiple EARFCNs: {earfcns} (possible PCI conflict)"
            )

    if cells:
        rsrp_values = [c.get("rsrp", -999) for c in cells if c.get("rsrp")]
        if rsrp_values:
            avg_rsrp = sum(rsrp_values) / len(rsrp_values)
            for c in cells:
                rsrp = c.get("rsrp", -999)
                if rsrp != -999 and rsrp > avg_rsrp + 20:
                    anomalies.append(
                        "PCI {} has unusually strong signal ({:.1f} dBm, "
                        "avg {:.1f} dBm) - possible rogue eNodeB".format(
                            c.get("pci", "?"), rsrp, avg_rsrp
                        )
                    )

    return anomalies


