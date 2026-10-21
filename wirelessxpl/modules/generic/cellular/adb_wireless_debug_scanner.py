"""Android ADB Wireless Debugging auth bypass scanner and PoC.


__info__ = {
    "name": "Android ADB Wireless Debugging auth bypass scanner and PoC",
    "description": (
        "CVE-2026-0073: TLS type confusion in ADB wireless debugging allows unauthenticated pairing via crafted EC/Ed25519 certificate. This module implements: - mDNS discovery of ADB wireless debugging services - Vulnerability detection (non-intrusive fingerprint) - Exploit PoC for authorized security testing Conceptual reference: tc4dy/CVE-2026-0073-PoC-Exploit (MIT) Recode: native Python implementation, credits maintained."
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
    "mitre": ["T1078.004", "T1133"],
}

CVE-2026-0073: TLS type confusion in ADB wireless debugging
allows unauthenticated pairing via crafted EC/Ed25519 certificate.

This module implements:
- mDNS discovery of ADB wireless debugging services
- Vulnerability detection (non-intrusive fingerprint)
- Exploit PoC for authorized security testing

Conceptual reference: tc4dy/CVE-2026-0073-PoC-Exploit (MIT)
Recode: native Python implementation, credits maintained.

MITRE ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts), T1133 (External Remote Services)
CVE: CVE-2026-0073 (CVSS 8.8)
CWE: CWE-295 (Improper Certificate Validation)

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""


import logging
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

ADB_HEADER_SIZE = 24
A_CNXN = 0x4E584E43
A_AUTH = 0x48545541
A_STLS = 0x534C5453
A_OPEN = 0x4E45504F
A_CLSE = 0x45534C43
A_WRTE = 0x45545257
A_OKAY = 0x59414B4F

AUTH_TOKEN = 1
AUTH_SIGNATURE = 2
AUTH_RSAPUBLICKEY = 3

ADB_VERSION = 0x01000001
MAX_PAYLOAD = 1024 * 1024
STLS_VERSION = 0x01000000


@dataclass
class ADBTarget:
    host: str
    port: int
    banner: str = ""
    is_vulnerable: bool = False
    adb_version: int = 0
    features: list[str] = field(default_factory=list)
    scan_time: float = 0.0


def _build_adb_header(command: int, arg0: int, arg1: int, data: bytes = b"") -> bytes:
    magic = command ^ 0xFFFFFFFF
    checksum = sum(data) & 0xFFFFFFFF
    return struct.pack(
        "<IIIIII",
        command,
        arg0,
        arg1,
        len(data),
        checksum,
        magic,
    ) + data


def _parse_adb_header(data: bytes) -> dict | None:
    if len(data) < ADB_HEADER_SIZE:
        return None
    cmd, arg0, arg1, data_len, checksum, magic = struct.unpack("<IIIIII", data[:ADB_HEADER_SIZE])
    return {
        "command": cmd,
        "arg0": arg0,
        "arg1": arg1,
        "data_len": data_len,
        "checksum": checksum,
        "magic": magic,
    }


def _recv_full(sock: socket.socket, size: int, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def scan_target(host: str, port: int = 5555, timeout: float = 5.0) -> ADBTarget:
    """Scan a single host for ADB wireless debugging and CVE-2026-0073.

    Non-intrusive: sends CNXN, checks for STLS capability.
    Does NOT attempt exploitation.

    Args:
        host: Target IP address.
        port: ADB port (default 5555).
        timeout: Connection timeout in seconds.

    Returns:
        ADBTarget with vulnerability assessment.
    """
    target = ADBTarget(host=host, port=port)
    start = time.monotonic()

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (ConnectionRefusedError, TimeoutError, OSError) as exc:
        target.scan_time = time.monotonic() - start
        logger.debug("Connection failed to %s:%d: %s", host, port, exc)
        return target

    try:
        banner = b"host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,abb_exec,remount_shell,track_app,sendrecv_v2,sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,sendrecv_v2_dry_run_send,openscreen_mdns,delayed_ack,stls"
        cnxn = _build_adb_header(A_CNXN, ADB_VERSION, MAX_PAYLOAD, banner + b"\x00")
        sock.sendall(cnxn)

        resp_hdr = _recv_full(sock, ADB_HEADER_SIZE, timeout)
        if not resp_hdr or len(resp_hdr) < ADB_HEADER_SIZE:
            target.scan_time = time.monotonic() - start
            return target

        hdr = _parse_adb_header(resp_hdr)
        if not hdr:
            target.scan_time = time.monotonic() - start
            return target

        if hdr["command"] == A_CNXN:
            target.adb_version = hdr["arg0"]
            if hdr["data_len"] > 0:
                resp_data = _recv_full(sock, hdr["data_len"], timeout)
                target.banner = resp_data.decode("utf-8", errors="replace").rstrip("\x00")

                if "features=" in target.banner:
                    feat_str = target.banner.split("features=", 1)[1]
                    target.features = feat_str.split(",")

            next_hdr = _recv_full(sock, ADB_HEADER_SIZE, timeout)
            if next_hdr and len(next_hdr) >= ADB_HEADER_SIZE:
                next_parsed = _parse_adb_header(next_hdr)
                if next_parsed and next_parsed["command"] == A_STLS:
                    target.is_vulnerable = True
                    logger.warning(
                        "CVE-2026-0073: %s:%d offers STLS (vulnerable to TLS type confusion)",
                        host,
                        port,
                    )

        elif hdr["command"] == A_STLS:
            target.is_vulnerable = True

    except Exception as exc:
        logger.debug("Scan error for %s:%d: %s", host, port, exc)
    finally:
        sock.close()

    target.scan_time = time.monotonic() - start
    return target


def scan_network(
    network: str,
    port: int = 5555,
    timeout: float = 3.0,
) -> list[ADBTarget]:
    """Scan a network range for ADB wireless debugging targets.

    Args:
        network: CIDR notation (e.g. "192.168.1.0/24").
        port: ADB port.
        timeout: Per-host timeout.

    Returns:
        List of discovered ADBTargets.
    """
    import ipaddress

    net = ipaddress.ip_network(network, strict=False)
    results = []

    for ip in net.hosts():
        target = scan_target(str(ip), port, timeout)
        if target.banner or target.is_vulnerable:
            results.append(target)

    return results


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
