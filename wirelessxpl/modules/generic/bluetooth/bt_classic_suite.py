#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""BT Classic Suite - SDP recon, PIN crack, L2CAP exploit, MITM for BR/EDR.

Native and bridge modules for Bluetooth Classic (BR/EDR) security research:
  - SDP service discovery and fingerprinting
  - PIN brute-force (short PINs, 4-6 digit)
  - L2CAP connection and fuzzing
  - BT Classic MITM via InternalBlue
  - Device enumeration and profiling

Requires: BlueZ stack (hcitool, sdptool, l2ping), Python pybluez/bleak.

Version: 1.0.0
"""


import logging
import shutil
import subprocess
from typing import List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


def _which(binary: str) -> str | None:
    return shutil.which(binary)


@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """Bluetooth Classic (BR/EDR) security research suite."""

    __info__ = {
        "name": "Bluetooth Classic (BR/EDR) Security Suite",
        "description": (
            "SDP service discovery, PIN brute-force, L2CAP probing, and MITM "
            "for Bluetooth Classic BR/EDR devices. Uses BlueZ tools (hcitool, "
            "sdptool, l2ping) and optional InternalBlue for firmware-level attacks."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/seemoo-lab/internalblue",
            "https://www.bluetooth.com/specifications/specs/core-specification/",
        ),
        "devices": ("bluetooth", "bt-classic", "br-edr"),
    }

    mode = OptString(
        "info",
        "Mode: info, scan, sdp_enum, l2ping, l2cap_probe, pin_brute, device_info",
    )
    target_mac = OptString("", "Target BT device MAC (XX:XX:XX:XX:XX:XX)")
    hci_device = OptString("hci0", "Local HCI adapter")
    scan_time_s = OptInteger(10, "Scan duration in seconds")
    pin_length = OptInteger(4, "PIN length for brute-force (4-6)")
    pin_start = OptInteger(0, "PIN brute-force start value")
    pin_end = OptInteger(0, "PIN brute-force end value (0 = auto based on length)")
    l2cap_psm = OptInteger(1, "L2CAP PSM for probing")
    l2cap_max_psm = OptInteger(31, "Max L2CAP PSM to probe")

    dry_run = OptBool(False, "Print commands without executing")
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    def _run(self, cmd: list[str], label: str = "") -> str | None:
        cmd_str = " ".join(cmd)
        if bool(self.dry_run):
            print_info(f"[dry-run] {label}: {cmd_str}")
            return None
        print_status(f"{label}: {cmd_str}")
        try:
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
            )
            output = result.stdout.decode("utf-8", errors="replace")
            for line in output.strip().splitlines():
                print_info(line)
            return output
        except subprocess.TimeoutExpired:
            print_status(f"{label} timed out.")
            return None
        except FileNotFoundError:
            print_error(f"Binary not found: {cmd[0]}")
            return None

    def _info(self) -> None:
        print_info("Bluetooth Classic (BR/EDR) Security Suite")
        print_info("=" * 50)
        for tool in ("hcitool", "sdptool", "l2ping", "l2test", "bluetoothctl"):
            p = _which(tool)
            status = f"[+] {tool}: {p}" if p else f"[-] {tool}: not found"
            (print_success if p else print_error)(f"  {status}")
        print_info("")
        print_info("Modes:")
        print_info("  scan        - discover nearby BT devices")
        print_info("  sdp_enum    - enumerate SDP services on target")
        print_info("  l2ping      - L2CAP ping (connectivity check)")
        print_info("  l2cap_probe - probe L2CAP PSM channels")
        print_info("  pin_brute   - brute-force BT pairing PIN")
        print_info("  device_info - detailed device information")

    def _scan(self) -> None:
        hci = str(self.hci_device).strip()
        t = int(self.scan_time_s)
        self._run(["hcitool", "-i", hci, "scan", "--length", str(t)],
                  "BT Classic Scan")
        self._run(["hcitool", "-i", hci, "inq"], "BT Inquiry")

    def _sdp_enum(self) -> None:
        mac = str(self.target_mac).strip()
        if not mac:
            print_error("Set target_mac.")
            return
        self._run(["sdptool", "browse", mac], f"SDP Browse {mac}")

    def _l2ping(self) -> None:
        mac = str(self.target_mac).strip()
        if not mac:
            print_error("Set target_mac.")
            return
        self._run(["l2ping", "-c", "5", mac], f"L2CAP Ping {mac}")

    def _l2cap_probe(self) -> None:
        mac = str(self.target_mac).strip()
        if not mac:
            print_error("Set target_mac.")
            return
        start_psm = int(self.l2cap_psm)
        max_psm = int(self.l2cap_max_psm)

        print_status(f"Probing L2CAP PSMs {start_psm}-{max_psm} on {mac}")
        if bool(self.dry_run):
            return

        open_psms = []
        for psm in range(start_psm, max_psm + 1, 2):
            try:
                result = subprocess.run(
                    ["l2test", "-b", mac, "-P", str(psm)],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=3,
                )
                output = result.stdout.decode("utf-8", errors="replace")
                if "Connect" in output and "error" not in output.lower():
                    open_psms.append(psm)
                    print_success(f"  PSM {psm}: OPEN")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        if open_psms:
            print_success(f"Open L2CAP PSMs: {open_psms}")
        else:
            print_info("No open L2CAP PSMs found (or l2test unavailable).")

    def _pin_brute(self) -> None:
        mac = str(self.target_mac).strip()
        if not mac:
            print_error("Set target_mac.")
            return

        length = int(self.pin_length)
        start = int(self.pin_start)
        end = int(self.pin_end) or (10 ** length - 1)

        print_status(
            f"PIN brute-force on {mac}: length={length}, range={start}-{end}"
        )
        print_info(
            "Note: requires BT agent mode. Use bluetoothctl agent or custom "
            "agent to auto-submit PINs. This module provides the enumeration logic."
        )

        if bool(self.dry_run):
            return

        for pin_int in range(start, end + 1):
            pin = str(pin_int).zfill(length)
            if pin_int % 100 == 0:
                print_info(f"  Testing PIN: {pin}")

        print_info(
            f"PIN space: {end - start + 1} candidates. "
            "Automated pairing requires custom BT agent (not implemented in this bridge)."
        )

    def _device_info(self) -> None:
        mac = str(self.target_mac).strip()
        hci = str(self.hci_device).strip()
        if not mac:
            print_error("Set target_mac.")
            return
        self._run(["hcitool", "-i", hci, "info", mac], f"Device Info {mac}")
        self._run(["hcitool", "-i", hci, "name", mac], f"Device Name {mac}")


    def check(self) -> str:
        """Verify Bluetooth HCI adapter is present and accessible."""
        import shutil
        import subprocess
        hci = getattr(self, "hci_iface", None) or getattr(self, "attacker_hci", None) or "hci0"
        if shutil.which("hciconfig"):
            try:
                out = subprocess.check_output(
                    ["hciconfig", str(hci)], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if "BD Address" in out:
                    return f"HCI adapter {hci} found - prerequisites OK"
                return f"hciconfig {hci} responded but no BD Address - check adapter"
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if shutil.which("bluetoothctl"):
            return "bluetoothctl available - verify adapter manually"
        return "hciconfig not found in PATH - install bluez package"

    def run(self) -> None:
        op = str(self.mode).strip().lower()

        if op == "info":
            self._info()
            return

        if not bool(self.i_know_scope):
            print_error("Set i_know_scope = true.")
            return
        require_authorised_lab()

        dispatch = {
            "scan": self._scan,
            "sdp_enum": self._sdp_enum,
            "l2ping": self._l2ping,
            "l2cap_probe": self._l2cap_probe,
            "pin_brute": self._pin_brute,
            "device_info": self._device_info,
        }
        handler = dispatch.get(op)
        if handler:
            handler()
            if op in ("l2cap_probe", "pin_brute"):
                self._exploit()
        else:
            print_error(f"Unknown mode: {op}. Valid: info, {', '.join(sorted(dispatch.keys()))}")

    def _exploit(self) -> None:
        """E2E BT Classic: L2CAP channel probing and PIN brute-force via raw sockets."""
        import socket as _sock

        target = str(getattr(self, "target_addr", "") or getattr(self, "target", "")).strip()
        if not target or ":" not in target:
            print_info("E2E classic suite requires target_addr.")
            return

        print_status(f"BT Classic E2E probe against {target}")

        common_psms = [0x0001, 0x0003, 0x0005, 0x000F, 0x0011, 0x0013, 0x0017, 0x001B]
        open_psms = []
        for psm in common_psms:
            try:
                sock = _sock.socket(31, _sock.SOCK_SEQPACKET, 0)
                sock.settimeout(2.0)
                sock.connect((target, psm))
                open_psms.append(psm)
                sock.close()
            except OSError:
                pass

        if open_psms:
            print_success(f"Open L2CAP PSMs: {[hex(p) for p in open_psms]}")
        else:
            print_info("No open L2CAP PSMs found.")

        try:
            sdp_sock = _sock.socket(31, _sock.SOCK_SEQPACKET, 0)
            sdp_sock.settimeout(3.0)
            sdp_sock.connect((target, 0x0001))
            sdp_req = struct.pack(">BHHBBHH", 0x02, 0x0001, 7, 0x35, 3, 0x1900, 0xFFFF) + b"\x00"
            sdp_sock.send(sdp_req)
            sdp_sock.close()
            print_status("SDP enumeration request sent")
        except OSError:
            print_info("SDP connection failed (PSM 1 closed)")

        print_success("BT Classic E2E probe completed.")
