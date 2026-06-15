#!/usr/bin/env python3
"""Inject check() methods into WirelessXPL modules that are missing them.

Detects module category from path and applies the appropriate check() template.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULES_DIR = ROOT / "wirelessxpl" / "modules"

# ── check() templates by category ──────────────────────────────────────────
BT_CHECK = '''\
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
'''

WIFI_CHECK = '''\
    def check(self) -> str:
        """Verify wireless interface is in monitor mode and ready."""
        import shutil
        import subprocess
        iface = getattr(self, "iface", None) or getattr(self, "interface", None) or "wlan0"
        if shutil.which("iwconfig"):
            try:
                out = subprocess.check_output(
                    ["iwconfig", str(iface)], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if "Monitor" in out:
                    return f"Interface {iface} is in Monitor mode - prerequisites OK"
                if "no wireless extensions" not in out.lower():
                    return f"Interface {iface} found but NOT in Monitor mode - run airmon-ng start {iface}"
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if shutil.which("iw"):
            try:
                out = subprocess.check_output(
                    ["iw", "dev"], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if str(iface) in out:
                    return f"Interface {iface} detected via iw - verify monitor mode"
            except Exception:
                pass
        return f"Interface {iface} not found - connect wireless adapter and enable monitor mode"
'''

EXTERNAL_CHECK = '''\
    def check(self) -> str:
        """Verify external tool dependencies are installed."""
        import shutil
        tools: list[str] = []
        src = getattr(self.__class__, "__doc__", "") or ""
        for t in ("aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng",
                   "hashcat", "hcxdumptool", "hcxtools", "wifite", "bettercap",
                   "kismet", "hostapd", "dnsmasq", "mdk4", "mdk3",
                   "hostapd-wpe", "hostapd-mana", "eaphammer"):
            if t.replace("-ng", "").replace("-", "") in (src + self.__class__.__name__).lower():
                tools.append(t)
        if not tools:
            tools = ["aircrack-ng"]
        missing = [t for t in tools if not shutil.which(t.rstrip("_"))]
        if missing:
            return f"Missing tools: {', '.join(missing)} - install before use"
        return f"Tool dependencies found: {', '.join(tools)} - prerequisites OK"
'''

CELLULAR_CHECK = '''\
    def check(self) -> str:
        """Verify SDR hardware and cellular tools are available."""
        import shutil
        sdr_tools = ["uhd_find_devices", "osmocom_fft", "gr-gsm", "gnuradio-companion"]
        gsm_tools = ["grgsm_livemon", "grgsm_decode", "kalibrate"]
        found = [t for t in sdr_tools + gsm_tools if shutil.which(t)]
        if found:
            return f"SDR tools found: {', '.join(found)} - verify hardware connection"
        return "No SDR tools found in PATH - install gnuradio, gr-osmosdr, gr-gsm"
'''

SIM_CHECK = '''\
    def check(self) -> str:
        """Verify SIM card reader and related tools are present."""
        import shutil
        tools = ["pySIM-shell", "pcsc_scan", "openssl"]
        found = [t for t in tools if shutil.which(t)]
        pysim = shutil.which("pySIM-shell") or shutil.which("pysim-shell")
        if pysim:
            return f"pySIM tools found at {pysim} - insert SIM card to proceed"
        if found:
            return f"Partial tools found: {', '.join(found)} - pySIM-shell missing"
        return "SIM tools not found - install pysim, pcscd, pcsc-tools"
'''

PCAP_CHECK = '''\
    def check(self) -> str:
        """Verify pcap file or capture interface is available."""
        import shutil
        pcap_file = getattr(self, "pcap_file", None) or getattr(self, "capture_file", None)
        iface = getattr(self, "iface", None)
        if pcap_file:
            import os
            if os.path.isfile(str(pcap_file)):
                size = os.path.getsize(str(pcap_file))
                return f"PCAP file found: {pcap_file} ({size} bytes)"
            return f"PCAP file not found: {pcap_file}"
        if iface and shutil.which("tcpdump"):
            return f"tcpdump available - capture interface: {iface}"
        if shutil.which("wireshark") or shutil.which("tshark"):
            return "Wireshark/tshark available - set pcap_file or iface"
        return "Set pcap_file option or ensure tshark is installed"
'''

GENERIC_CHECK = '''\
    def check(self) -> str:
        """Verify basic prerequisites for this exploit module."""
        import shutil
        target = getattr(self, "target", None)
        if not target:
            return "Set target option before running"
        port = getattr(self, "port", None)
        if port:
            import socket
            try:
                with socket.create_connection((str(target), int(port)), timeout=5):
                    return f"Target {target}:{port} is reachable"
            except Exception:
                return f"Target {target}:{port} is not reachable - check connectivity"
        return f"Target set to {target} - run connectivity check manually"
'''

CATEGORY_MAP = {
    "bluetooth": BT_CHECK,
    "wifi_lab": WIFI_CHECK,
    "external": EXTERNAL_CHECK,
    "cellular": CELLULAR_CHECK,
    "sim": SIM_CHECK,
    "pcap": PCAP_CHECK,
}


def detect_category(path: Path) -> str:
    parts = {p.lower() for p in path.parts}
    if "bluetooth" in parts or "ble" in parts:
        return "bluetooth"
    if "wifi_lab" in parts:
        return "wifi_lab"
    if "external" in parts:
        return "external"
    if "cellular" in parts:
        return "cellular"
    if "sim" in parts:
        return "sim"
    if "pcap" in parts:
        return "pcap"
    return "generic"


def has_check(source: str) -> bool:
    return bool(re.search(r"\bdef check\b", source))


def has_exploit_class(source: str) -> bool:
    return bool(re.search(r"\bclass Exploit\b", source))


def inject_check(source: str, check_body: str) -> str:
    """Insert check() right before def run() or at end of Exploit class."""
    insertion = "\n" + check_body + "\n"

    # Try to insert before first def run(
    m = re.search(r"^([ \t]+def run\b)", source, re.MULTILINE)
    if m:
        pos = m.start()
        return source[:pos] + insertion + source[pos:]

    # Fall back: insert before last method or at class end (just before last non-blank)
    m = re.search(r"^([ \t]+def \w+\b)", source, re.MULTILINE)
    if m:
        pos = m.start()
        return source[:pos] + insertion + source[pos:]

    return source + insertion


def process_file(path: Path) -> bool:
    source = path.read_text(encoding="utf-8", errors="replace")
    if not has_exploit_class(source) or has_check(source):
        return False

    category = detect_category(path)
    check_body = CATEGORY_MAP.get(category, GENERIC_CHECK)
    new_source = inject_check(source, check_body)

    try:
        compile(new_source, str(path), "exec")
    except SyntaxError as exc:
        print(f"  SYNTAX ERROR after injection in {path.name}: {exc}", file=sys.stderr)
        return False

    path.write_text(new_source, encoding="utf-8", newline="\n")
    return True


def main() -> None:
    fixed = 0
    skipped = 0
    for py in sorted(MODULES_DIR.rglob("*.py")):
        if py.name == "__init__.py" or "__pycache__" in str(py):
            continue
        if process_file(py):
            fixed += 1
            print(f"  [FIXED] {py.relative_to(ROOT)}")
        else:
            skipped += 1
    print(f"\nDone: fixed={fixed}, skipped={skipped}")


if __name__ == "__main__":
    main()
