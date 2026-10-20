# Author: André Henrique (LinkedIn/X: @mrhenrike)
import json
import os
import socket
import struct
import subprocess
import threading
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Remote Distributed Sensor Node for Coordinated Wireless Operations.

    Deploys and coordinates multiple remote sensor nodes for distributed
    wireless monitoring, triangulation, and coordinated attack execution.
    Each node runs on a Raspberry Pi (or similar SBC) with an SDR device,
    connected via IP network to a central controller.

    Supports operations:
      - Distributed spectrum monitoring across multiple locations
      - Signal triangulation via TDOA (Time Difference of Arrival)
      - Coordinated deauthentication from multiple vantage points
      - Distributed capture with time-synchronized sampling
      - Mesh-based signal relay for extended range operations

    Hardware requirements per node:
      - Raspberry Pi 4/5 (~$35-80) or similar ARM SBC
      - RTL-SDR v3/v4 (~$30) or HackRF One (~$350)
      - External antenna appropriate for target frequency
      - Ethernet or WiFi connectivity to controller network
      - GPS module (u-blox NEO-6M/7M, ~$15) for time sync and location

    CVSS: N/A (infrastructure tool)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Remote Distributed Sensor Node Controller",
        "description": (
            "Coordinates multiple remote SDR sensor nodes for distributed "
            "wireless operations.  Supports spectrum monitoring across "
            "locations, signal triangulation via TDOA, coordinated "
            "deauthentication, and time-synchronized distributed capture.  "
            "Each node runs on a Raspberry Pi with SDR hardware."
        ),
        "authors": (
            "mrhenrike (Andre Henrique)",
        ),
        "references": (
            "https://www.raspberrypi.com/",
            "https://www.rtl-sdr.com/",
        ),
        "disclosure_date": "2026-10-01",
        "platform": "linux",
        "arch": "all",
        "privileged": False,
        "targets": (
            "Distributed wireless monitoring and attack coordination",
        ),
    }

    target = OptIP("", "Not used (multi-node controller)")
    port = OptPort(9090, "Controller listening port for node registration")
    timeout = OptFloat(30.0, "Operation timeout in seconds")
    nodes = OptString("", "Comma-separated node addresses (ip:port)")
    center_freq = OptFloat(2.437e9, "Center frequency in Hz for all nodes")
    sample_rate = OptFloat(2.4e6, "Sample rate in samples/sec")
    operation = OptString("monitor", "Operation: monitor, triangulate, deauth, capture")
    capture_duration = OptFloat(5.0, "Per-node capture duration in seconds")
    output_dir = OptString("/tmp/sensor_data", "Directory for captured data")
    auth_token = OptString("", "Shared authentication token for node communication")

    _PROTO_VERSION = 1
    _CMD_PING = 0x01
    _CMD_CONFIGURE = 0x02
    _CMD_START_CAPTURE = 0x03
    _CMD_STOP_CAPTURE = 0x04
    _CMD_GET_STATUS = 0x05
    _CMD_GET_DATA = 0x06
    _CMD_DEAUTH = 0x07

    _RSP_OK = 0x00
    _RSP_ERROR = 0xFF

    def _build_command(self, cmd_type: int, payload: bytes = b"") -> bytes:
        """Build a sensor node command packet."""
        # Header: version(1) + cmd(1) + payload_len(2) + payload
        header = struct.pack("<BBH", self._PROTO_VERSION, cmd_type, len(payload))
        return header + payload

    def _parse_response(self, data: bytes) -> tuple:
        """Parse a sensor node response. Returns (status, payload)."""
        if len(data) < 4:
            return (self._RSP_ERROR, b"")
        version, status, payload_len = struct.unpack("<BBH", data[:4])
        payload = data[4: 4 + payload_len]
        return (status, payload)

    def _send_to_node(self, addr: str, cmd: bytes) -> tuple:
        """Send command to a remote node and receive response."""
        try:
            host, port_str = addr.rsplit(":", 1)
            node_port = int(port_str)
        except (ValueError, AttributeError):
            return (self._RSP_ERROR, b"invalid address")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, node_port))
            sock.sendall(cmd)
            response = sock.recv(65536)
            sock.close()
            return self._parse_response(response)
        except OSError as e:
            return (self._RSP_ERROR, str(e).encode())

    def _get_node_list(self) -> list:
        """Parse the nodes configuration string into a list of addresses."""
        if not self.nodes:
            return []
        return [n.strip() for n in str(self.nodes).split(",") if n.strip()]

    def _ping_node(self, addr: str) -> bool:
        """Ping a remote sensor node."""
        cmd = self._build_command(self._CMD_PING)
        status, _ = self._send_to_node(addr, cmd)
        return status == self._RSP_OK

    def _configure_node(self, addr: str) -> bool:
        """Configure a node with current capture parameters."""
        config = struct.pack(
            "<ddf",
            self.center_freq,
            self.sample_rate,
            self.capture_duration,
        )
        cmd = self._build_command(self._CMD_CONFIGURE, config)
        status, _ = self._send_to_node(addr, cmd)
        return status == self._RSP_OK

    def _start_capture_on_node(self, addr: str) -> bool:
        """Start capture on a remote node."""
        cmd = self._build_command(self._CMD_START_CAPTURE)
        status, _ = self._send_to_node(addr, cmd)
        return status == self._RSP_OK

    def _get_data_from_node(self, addr: str) -> bytes:
        """Retrieve captured data from a remote node."""
        cmd = self._build_command(self._CMD_GET_DATA)
        status, payload = self._send_to_node(addr, cmd)
        if status == self._RSP_OK:
            return payload
        return b""

    def _distributed_monitor(self, node_list: list) -> dict:
        """Run distributed spectrum monitoring across all nodes."""
        results = {}
        for addr in node_list:
            if self._configure_node(addr):
                print_info(f"  Node {addr}: configured")
                if self._start_capture_on_node(addr):
                    print_info(f"  Node {addr}: capturing...")
                    results[addr] = "capturing"
                else:
                    results[addr] = "capture_failed"
            else:
                results[addr] = "config_failed"

        if any(v == "capturing" for v in results.values()):
            time.sleep(self.capture_duration + 1)

        for addr in node_list:
            if results.get(addr) == "capturing":
                data = self._get_data_from_node(addr)
                if data:
                    output_path = os.path.join(
                        str(self.output_dir),
                        f"capture_{addr.replace(':', '_')}.raw",
                    )
                    try:
                        with open(output_path, "wb") as f:
                            f.write(data)
                        results[addr] = f"captured ({len(data)} bytes)"
                    except OSError:
                        results[addr] = "save_failed"
                else:
                    results[addr] = "no_data"

        return results

    def _triangulate(self, node_list: list) -> dict:
        """Perform TDOA triangulation using multiple nodes."""
        if len(node_list) < 3:
            return {"error": "triangulation requires at least 3 nodes"}

        timestamps = {}
        for addr in node_list:
            cmd = self._build_command(self._CMD_GET_STATUS)
            status, payload = self._send_to_node(addr, cmd)
            if status == self._RSP_OK and len(payload) >= 24:
                lat, lon, ts = struct.unpack("<ddd", payload[:24])
                timestamps[addr] = {
                    "lat": lat, "lon": lon,
                    "timestamp_ns": ts,
                }

        if len(timestamps) < 3:
            return {"error": "insufficient node responses for triangulation"}

        return {
            "nodes": timestamps,
            "method": "TDOA",
            "status": "data_collected",
            "note": "Post-processing required for position estimate",
        }

    @mute
    def check(self) -> bool:
        """Verify at least one node is reachable."""
        node_list = self._get_node_list()
        if not node_list:
            return False
        return any(self._ping_node(addr) for addr in node_list)

    def run(self) -> None:
        node_list = self._get_node_list()
        if not node_list:
            print_error(
                "No sensor nodes configured. Set 'nodes' to a "
                "comma-separated list of ip:port addresses."
            )
            return

        print_status(f"Checking {len(node_list)} sensor node(s)...")
        reachable = []
        for addr in node_list:
            if self._ping_node(addr):
                print_info(f"  {addr}: online")
                reachable.append(addr)
            else:
                print_error(f"  {addr}: unreachable")

        if not reachable:
            print_error("No reachable sensor nodes")
            return

        print_success(f"{len(reachable)}/{len(node_list)} nodes online")
        self._exploit()

    def _exploit(self) -> None:
        node_list = self._get_node_list()
        operation = str(self.operation).lower()

        os.makedirs(str(self.output_dir), exist_ok=True)

        freq_mhz = self.center_freq / 1e6
        print_status(
            f"Operation: {operation}, "
            f"freq: {freq_mhz:.3f} MHz, "
            f"nodes: {len(node_list)}"
        )

        if operation == "monitor":
            results = self._distributed_monitor(node_list)
            for addr, status in results.items():
                print_info(f"  {addr}: {status}")
            print_success("Distributed monitoring complete")

        elif operation == "triangulate":
            results = self._triangulate(node_list)
            if "error" in results:
                print_error(results["error"])
            else:
                print_success("TDOA data collected from nodes")
                for addr, data in results.get("nodes", {}).items():
                    print_info(
                        f"  {addr}: lat={data['lat']:.6f}, "
                        f"lon={data['lon']:.6f}"
                    )

        elif operation == "deauth":
            print_status("Sending coordinated deauth via all nodes...")
            for addr in node_list:
                cmd = self._build_command(self._CMD_DEAUTH)
                status, _ = self._send_to_node(addr, cmd)
                if status == self._RSP_OK:
                    print_info(f"  {addr}: deauth sent")
                else:
                    print_error(f"  {addr}: deauth failed")
            print_success("Coordinated deauth complete")

        elif operation == "capture":
            results = self._distributed_monitor(node_list)
            for addr, status in results.items():
                print_info(f"  {addr}: {status}")
            print_success(f"Captures saved to {self.output_dir}")

        else:
            print_error(f"Unknown operation: {operation}")
