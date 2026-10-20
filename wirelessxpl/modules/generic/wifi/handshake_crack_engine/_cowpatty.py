"""CoWPAtty runner."""
from __future__ import annotations
import logging, os, re, subprocess, time
from pathlib import Path
log = logging.getLogger(__name__)
from ._common import _SessionLog
from ._hashcat import CrackResult

def _run_cowpatty(
    pcap_file: Path,
    wordlist: Path,
    essid: str,
    result: CrackResult,
) -> None:
    if not shutil.which("cowpatty"):
        print_error("cowpatty not found")
        result.status = "error"
        return
    if not essid:
        print_error("cowpatty requires ESSID (set essid option)")
        result.status = "error"
        return
    cmd = ["cowpatty", "-f", str(wordlist), "-r", str(pcap_file), "-s", essid]
    print_info(f"  CMD: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, bufsize=1)
        for line in proc.stdout:
            line = line.rstrip()
            result.raw_lines.append(line)
            if "The PSK is" in line:
                m = re.search(r"The PSK is[:\s]+(.+)", line)
                if m:
                    result.add_found(essid, m.group(1).strip(), "cowpatty")
                    result.status = "finished"
            elif "Unable to identify correct PSK" in line:
                result.status = "exhausted"
            elif "%" in line or "key(s)" in line.lower():
                result.progress = line.strip()
        proc.wait()
    except Exception as exc:
        logger.debug("cowpatty: %s", exc)
        result.status = "error"
    if result.status == "running":
        result.status = "exhausted"


# ---------------------------------------------------------------------------
# Multi-ESSID detection and selection
# ---------------------------------------------------------------------------

def _detect_essids_with_handshakes(pcap_path: Path) -> list[dict]:
    """Scan pcap/pcapng and return list of ESSIDs with valid WPA handshakes.

    Uses Scapy directly (no aircrack-ng TUI dependency) to parse
    beacon/probe frames for SSID discovery and EAPOL frames for handshake
    detection. Works even when aircrack-ng uses ANSI/TUI output.

    Returns:
        List of dicts: {index, essid, bssid, encryption, handshakes, has_pmkid, has_hs}
    """
    try:
        from scapy.all import EAPOL, Dot11, Dot11Beacon, Dot11Elt, rdpcap
    except ImportError:
        # Fallback to aircrack-ng parsing (may fail with TUI)
        return _detect_essids_aircrack(pcap_path)

    networks: dict[str, dict] = {}  # bssid → info
    try:
        pkts = rdpcap(str(pcap_path))
    except Exception as exc:
        logger.debug("rdpcap failed: %s", exc)
        return []

    # Pass 1: discover SSIDs from beacons and probe responses
    for p in pkts:
        if not p.haslayer(Dot11):
            continue
        bssid = (p[Dot11].addr3 or "").lower()
        if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
            continue
        if p.haslayer(Dot11Beacon) or (p.haslayer(Dot11) and p[Dot11].subtype == 5):
            elt = p.getlayer(Dot11Elt)
            ssid = ""
            while elt:
                if elt.ID == 0:
                    try: ssid = elt.info.decode("utf-8", errors="replace")
                    except: pass
                    break
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
            if bssid not in networks:
                networks[bssid] = {
                    "bssid": bssid.upper(),
                    "essid": ssid,
                    "eapol_msgs": set(),
                    "handshakes": 0,
                    "has_pmkid": False,
                    "has_hs": False,
                }
            elif ssid and not networks[bssid]["essid"]:
                networks[bssid]["essid"] = ssid

    # Pass 2: count EAPOL messages per AP (detect complete handshakes)
    for p in pkts:
        if not p.haslayer(EAPOL):
            continue
        if not p.haslayer(Dot11):
            continue
        # Determine AP BSSID from frame
        src = (p[Dot11].addr2 or "").lower()
        dst = (p[Dot11].addr1 or "").lower()
        raw = bytes(p[EAPOL])
        if len(raw) < 7 or raw[1] != 3:
            continue
        ki = (raw[5] << 8) | raw[6]
        ack = bool(ki & 0x80); mic = bool(ki & 0x100); sec = bool(ki & 0x200)
        if ack and not mic:    mtype, ap_bssid = "M1", src
        elif mic and not ack and not sec: mtype, ap_bssid = "M2", dst
        elif ack and mic and sec:         mtype, ap_bssid = "M3", src
        elif mic and not ack and sec:     mtype, ap_bssid = "M4", dst
        else: continue

        if ap_bssid not in networks:
            networks[ap_bssid] = {
                "bssid": ap_bssid.upper(),
                "essid": "",
                "eapol_msgs": set(),
                "handshakes": 0,
                "has_pmkid": False,
                "has_hs": False,
            }
        networks[ap_bssid]["eapol_msgs"].add(mtype)
        msgs = networks[ap_bssid]["eapol_msgs"]
        if "M1" in msgs and "M2" in msgs:
            networks[ap_bssid]["handshakes"] = 1
            networks[ap_bssid]["has_hs"] = True

    # Build sorted result list
    result: list[dict] = []
    idx = 0
    for bssid, info in sorted(networks.items()):
        if info.get("has_hs") or info.get("handshakes", 0) > 0:
            idx += 1
            enc = "WPA2"
            hs_str = f"{info['handshakes']} handshake" if info["handshakes"] else ""
            result.append({
                "index":      idx,
                "bssid":      info["bssid"],
                "essid":      info["essid"],
                "encryption": f"{enc} ({hs_str})" if hs_str else enc,
                "handshakes": info["handshakes"],
                "has_pmkid":  info.get("has_pmkid", False),
                "has_hs":     True,
            })

    return result


def _detect_essids_aircrack(pcap_path: Path) -> list[dict]:
    """Fallback: parse aircrack-ng stdout for network listing."""
    if not shutil.which("aircrack-ng"):
        return []
    try:
        r = subprocess.run(
            ["aircrack-ng", str(pcap_path)],
            capture_output=True, text=True, timeout=15,
        )
        networks: list[dict] = []
        idx = 0
        for line in r.stdout.splitlines():
            # Strip ANSI escape codes
            clean = re.sub(r"\x1b\[[0-9;]*m|\x1b\[[0-9]*[ABCDJK]|\r", "", line)
            m = re.match(
                r"\s+(\d+)\s+([0-9A-Fa-f:]{17})\s+(.*?)\s{2,}(WPA\S*.*?)\s*$", clean
            )
            if m:
                idx += 1
                essid   = m.group(3).strip()
                enc     = m.group(4).strip()
                hs_count = 0
                hs_m = re.search(r"(\d+)\s+handshake", enc)
                if hs_m:
                    hs_count = int(hs_m.group(1))
                networks.append({
                    "index": idx, "bssid": m.group(2).strip(),
                    "essid": essid, "encryption": enc,
                    "handshakes": hs_count, "has_pmkid": "PMKID" in enc,
                    "has_hs": hs_count > 0 or "PMKID" in enc,
                })
        return networks
    except Exception as exc:
        logger.debug("aircrack detection: %s", exc)
        return []


def _detect_essids_from_hash(hash_path: Path) -> list[dict]:
    """Extract unique ESSIDs from a .hash / .22000 file."""
    networks: list[dict] = []
    seen: set = set()
    try:
        idx = 0
        for line in hash_path.read_text(errors="replace").splitlines():
            parts = line.strip().split("*")
            if len(parts) > 5:
                try:
                    essid = bytes.fromhex(parts[5]).decode("utf-8", errors="replace")
                    bssid = ":".join(parts[3][i:i+2] for i in range(0, 12, 2)) if len(parts[3]) == 12 else parts[3]
                    hash_type = "PMKID" if "WPA*01*" in line else "EAPOL"
                    key = essid + bssid
                    if key not in seen:
                        seen.add(key)
                        idx += 1
                        networks.append({
                            "index":      idx,
                            "bssid":      bssid.upper(),
                            "essid":      essid,
                            "encryption": f"WPA2 {hash_type}",
                            "handshakes": 1,
                            "has_pmkid":  hash_type == "PMKID",
                            "has_hs":     True,
                        })
                except Exception:
                    pass
    except Exception as exc:
        logger.debug("Hash ESSID parse: %s", exc)
    return networks


def _resolve_essid_selection(
    networks: list[dict],
    essid_spec: str,
) -> list[str]:
    """Resolve essid_spec to a list of ESSID strings to crack.

    Spec formats:
      (empty)      → if 1 network: auto-select; if >1: show list and use all
      all          → all networks with handshake
      1            → network at index 1
      1,3          → networks at index 1 and 3
      1-3          → networks at index 1 through 3
      BeYellow     → exact ESSID match (case-sensitive)

    Prints a selection table when multiple networks are detected.
    """
    with_hs = [n for n in networks if n.get("has_hs")]
    without = [n for n in networks if not n.get("has_hs")]

    if not with_hs:
        print_warning("Nenhum ESSID com handshake válido encontrado no arquivo.")
        return [""]  # let caller try anyway

    # Always show the table when >1 network
    if len(with_hs) > 1 or essid_spec.strip().lower() not in ("", "all"):
        print_info("")
        print_info(f"  {'#':>3}  {'BSSID':<20} {'HANDSHAKE':>10}  ESSID")
        print_info(f"  {'─'*65}")
        for n in with_hs:
            hs_tag = f"{n['handshakes']} HS" if n['handshakes'] else ""
            if n.get("has_pmkid"):
                hs_tag += " +PMKID" if hs_tag else "PMKID"
            enc_short = n["encryption"].replace("(", "").replace(")", "")[:12]
            print_success(f"  \033[1m{n['index']:>3}\033[0m  {n['bssid']:<20} {hs_tag:>10}  {n['essid']}")
        if without:
            print_warning(f"  (+ {len(without)} rede(s) sem handshake capturado)")
        print_info("")
        print_info("  Seleção: set essid all | 1 | 1,2 | 1-3 | <nome>")
        print_info("")

    spec = essid_spec.strip()

    # Single network → auto select
    if len(with_hs) == 1 and not spec:
        n = with_hs[0]
        print_success(f"  Auto-selecionado: '{n['essid']}' ({n['bssid']})")
        return [n["essid"]]

    # Empty + multiple → crack all
    if not spec or spec.lower() == "all":
        essids = [n["essid"] for n in with_hs]
        print_success(f"  Crackeando todos ({len(essids)}): {essids}")
        return essids

    # Exact ESSID match
    by_name = [n["essid"] for n in with_hs if n["essid"] == spec]
    if by_name:
        return by_name

    # Index selection (1, 1,2, 1-3)
    selected_essids: list[str] = []
    if "-" in spec and spec.replace("-", "").isdigit():
        a, b = map(int, spec.split("-", 1))
        selected_essids = [n["essid"] for n in with_hs if a <= n["index"] <= b]
    else:
        for part in spec.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part)
                matches = [n["essid"] for n in with_hs if n["index"] == idx]
                selected_essids.extend(matches)

    if selected_essids:
        print_success(f"  Selecionados: {selected_essids}")
        return selected_essids

    # Fallback: use spec as literal ESSID
    print_warning(f"  Especificação '{spec}' não casou com nenhum índice/ESSID. Usando como ESSID literal.")
    return [spec]


# ---------------------------------------------------------------------------
# WXF Exploit class
# ---------------------------------------------------------------------------

@requires_os(OSRequirement.LINUX_ONLY)
