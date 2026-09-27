"""WXF Global Configuration — singleton accessible from any module.

Holds framework-wide defaults that apply to all modules unless overridden:
  - destructive:   True  (full destructive/intrusive/disruptive mode)
  - simulate:      False (never simulate — always execute for real)
  - verbose:       True  (normal logging level)
  - timing:        T3/normal (nmap-style T0-T5)
  - reverse_host:  local machine IP (for reverse-shell payloads)
  - reverse_port:  4444
  - iface_mon:     first external USB WiFi interface in monitor mode
  - iface_inj:     second external USB WiFi interface (for injection/AP)
  - iface_extra:   remaining external interfaces
  - lhost/lport:   same as reverse_host/reverse_port (metasploit naming)

Timing profiles (nmap-style, T0–T5):
  T0 / paranoid   — 5 min between probes, max stealth
  T1 / sneaky     — 15 s between probes, slow
  T2 / polite     — 0.4 s between probes, low noise
  T3 / normal     — default balanced (most modules use this)
  T4 / aggressive — minimal delays, faster scans, more noise
  T5 / insane     — no delays, maximum speed/aggression

Interface selection rules (applied at startup and on refresh):
  1. Never select the interface providing the default route (internet)
  2. Never select wlp*/wl0*/wl1* (PCIe/built-in/internal)
  3. Prefer wlx* (USB: identified by driver path or bus type)
  4. iface_mon = first USB interface (monitor capable preferred)
  5. iface_inj = second USB interface
  6. Warn if < 2 external USB adapters (many attacks need both)

Usage from any module:
    from wirelessxpl.core.config import WXFConfig
    cfg = WXFConfig.get()
    iface = cfg.iface_mon   # → "wlx44334cbe826b"
    if cfg.destructive:
        # proceed with full attack
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Timing profiles
# ---------------------------------------------------------------------------

TIMING_PROFILES: Dict[str, Dict] = {
    "0": {"name": "paranoid",   "level": 0, "scan_delay_ms": 300_000, "timeout_ms": 60_000, "retries": 0},
    "1": {"name": "sneaky",     "level": 1, "scan_delay_ms": 15_000,  "timeout_ms": 30_000, "retries": 1},
    "2": {"name": "polite",     "level": 2, "scan_delay_ms": 400,     "timeout_ms": 10_000, "retries": 2},
    "3": {"name": "normal",     "level": 3, "scan_delay_ms": 100,     "timeout_ms": 5_000,  "retries": 3},
    "4": {"name": "aggressive", "level": 4, "scan_delay_ms": 20,      "timeout_ms": 2_000,  "retries": 5},
    "5": {"name": "insane",     "level": 5, "scan_delay_ms": 0,       "timeout_ms": 500,    "retries": 10},
}

# Also accept names
TIMING_BY_NAME: Dict[str, str] = {v["name"]: k for k, v in TIMING_PROFILES.items()}


def parse_timing(value: str) -> Dict:
    """Accept T0-T5, 0-5, or name (paranoid/sneaky/polite/normal/aggressive/insane)."""
    v = str(value).strip().lower().lstrip("t")
    if v in TIMING_BY_NAME:
        v = TIMING_BY_NAME[v]
    if v not in TIMING_PROFILES:
        v = "3"  # default normal
    return TIMING_PROFILES[v]


# ---------------------------------------------------------------------------
# Interface helpers
# ---------------------------------------------------------------------------

def _get_default_route_iface() -> str:
    """Return the interface that carries the default route (internet)."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, timeout=5
        )
        m = re.search(r"dev\s+(\S+)", out)
        return m.group(1) if m else ""
    except Exception:
        return ""


def _is_internal(iface: str) -> bool:
    """Return True if interface is likely built-in PCIe/internal (not USB)."""
    # PCIe/built-in patterns: wlp*, wl0, wl1
    if re.match(r"^wlp\d+s\d+", iface):
        return True
    if re.match(r"^wl[01]$", iface):
        return True
    # Check sysfs: if path contains /usb → USB adapter (external, not internal)
    # USB devices connect via: /pci.../usb1/1-N/...  (has both /pci AND /usb)
    # PCIe internal cards:    /pci.../0000:00:XX.X    (has /pci but NO /usb)
    sysfs = f"/sys/class/net/{iface}/device"
    try:
        real = os.path.realpath(sysfs)
        if "/usb" in real:
            return False   # USB device connected through USB controller → external
        return "/pci" in real   # Pure PCIe → internal
    except Exception:
        pass
    return False


def _is_usb_wifi(iface: str) -> bool:
    """Return True if interface is a USB WiFi adapter."""
    # USB devices show under /sys/bus/usb
    sysfs = f"/sys/class/net/{iface}/device"
    try:
        real = os.path.realpath(sysfs)
        if "/usb" in real:
            return True
    except Exception:
        pass
    # wlx* prefix is typically USB (USB-based adapters use randomised MAC → wlx)
    if iface.startswith("wlx"):
        return True
    return False


def _supports_monitor(iface: str) -> bool:
    """Return True if interface supports 802.11 monitor mode."""
    try:
        phy = _get_phy(iface)
        if not phy:
            return False
        out = subprocess.check_output(
            ["iw", "phy", phy.replace("#", ""), "info"],
            stderr=subprocess.DEVNULL, text=True, timeout=5,
        )
        return "* monitor" in out
    except Exception:
        return False


def _get_phy(iface: str) -> str:
    try:
        out = subprocess.check_output(
            ["iw", "dev", iface, "info"],
            stderr=subprocess.DEVNULL, text=True, timeout=5,
        )
        m = re.search(r"wiphy\s+(\d+)", out)
        return f"phy#{m.group(1)}" if m else ""
    except Exception:
        return ""


def _get_current_mode(iface: str) -> str:
    try:
        out = subprocess.check_output(
            ["iw", "dev", iface, "info"],
            stderr=subprocess.DEVNULL, text=True, timeout=5,
        )
        m = re.search(r"type\s+(\S+)", out)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


def _get_local_ip() -> str:
    """Return this machine's primary IP (non-loopback)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _detect_external_ifaces() -> List[str]:
    """List external USB WiFi interfaces sorted by suitability."""
    default_iface = _get_default_route_iface()
    try:
        out = subprocess.check_output(["iw", "dev"], text=True, timeout=5)
    except Exception:
        return []

    found: List[str] = []
    for line in out.splitlines():
        m = re.match(r"\s+Interface\s+(\S+)", line)
        if m:
            iface = m.group(1)
            if iface == default_iface:
                continue
            if _is_internal(iface):
                continue
            if _is_usb_wifi(iface) or iface.startswith("wlx"):
                found.append(iface)

    # Sort: monitor mode first, then by name
    found.sort(key=lambda i: (0 if _get_current_mode(i) == "monitor" else 1, i))
    return found


# ---------------------------------------------------------------------------
# WXF Interface descriptor
# ---------------------------------------------------------------------------

@dataclass
class IfaceInfo:
    name:        str
    index:       int
    usb:         bool
    monitor_cap: bool
    current_mode: str
    internet:    bool


# ---------------------------------------------------------------------------
# WXF Global Config singleton
# ---------------------------------------------------------------------------

@dataclass
class WXFConfig:
    """Global framework defaults."""

    # ── Behaviour ──────────────────────────────────────────────────────────
    destructive:     bool  = True   # always run in full destructive mode
    simulate:        bool  = False  # never simulate — execute for real
    verbose:         bool  = True   # normal log verbosity
    dry_run:         bool  = False  # print commands but don't execute

    # ── Timing (nmap-style) ─────────────────────────────────────────────────
    timing:          str   = "3"    # T3 / normal
    timing_profile:  Dict  = field(default_factory=lambda: TIMING_PROFILES["3"])

    # ── Reverse shell defaults ─────────────────────────────────────────────
    reverse_host:    str   = ""     # filled at init
    reverse_port:    int   = 4444
    lhost:           str   = ""     # alias
    lport:           int   = 4444

    # ── Wireless interfaces ────────────────────────────────────────────────
    iface_mon:       str   = ""     # monitor/capture interface
    iface_inj:       str   = ""     # injection/AP interface
    iface_extra:     List[str] = field(default_factory=list)
    all_ext_ifaces:  List[IfaceInfo] = field(default_factory=list)

    # ── Internal ───────────────────────────────────────────────────────────
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ── Singleton ─────────────────────────────────────────────────────────
    _instance: Optional["WXFConfig"] = field(default=None, init=False, repr=False)

    @classmethod
    def get(cls) -> "WXFConfig":
        if not hasattr(cls, "_singleton") or cls._singleton is None:
            cfg = cls()
            cfg._init()
            cls._singleton = cfg
        return cls._singleton

    @classmethod
    def reset(cls) -> "WXFConfig":
        """Re-detect everything (call after attaching new adapters)."""
        cls._singleton = None
        return cls.get()

    def _init(self) -> None:
        self.reverse_host = _get_local_ip()
        self.lhost        = self.reverse_host
        self.lport        = self.reverse_port
        self._refresh_ifaces()

    def _refresh_ifaces(self) -> None:
        ext = _detect_external_ifaces()
        default_iface = _get_default_route_iface()

        self.all_ext_ifaces = []
        for i, name in enumerate(ext, start=1):
            self.all_ext_ifaces.append(IfaceInfo(
                name=name,
                index=i,
                usb=_is_usb_wifi(name),
                monitor_cap=_supports_monitor(name),
                current_mode=_get_current_mode(name),
                internet=(name == default_iface),
            ))

        self.iface_mon   = ext[0] if len(ext) >= 1 else ""
        self.iface_inj   = ext[1] if len(ext) >= 2 else ""
        self.iface_extra = ext[2:] if len(ext) > 2 else []

    # ------------------------------------------------------------------
    # Timing helpers
    # ------------------------------------------------------------------

    def set_timing(self, value: str) -> None:
        """Set timing by level (0-5), T-prefixed (T0-T5), or name."""
        self.timing_profile = parse_timing(value)
        self.timing = str(self.timing_profile["level"])

    @property
    def timing_name(self) -> str:
        return self.timing_profile.get("name", "normal")

    @property
    def scan_delay_ms(self) -> int:
        return self.timing_profile.get("scan_delay_ms", 100)

    @property
    def timeout_ms(self) -> int:
        return self.timing_profile.get("timeout_ms", 5000)

    # ------------------------------------------------------------------
    # Interface selection
    # ------------------------------------------------------------------

    def select_ifaces(self, spec: str) -> List[str]:
        """Parse interface spec and return list of interface names.

        Spec formats:
          all        → all external interfaces
          1          → interface #1 from list
          2,3        → interfaces #2 and #3
          1-3        → interfaces #1 through #3
          wlx...     → interface by name
        """
        if not self.all_ext_ifaces:
            return []
        spec = spec.strip().lower()
        if spec == "all":
            return [i.name for i in self.all_ext_ifaces]
        if "-" in spec and spec.replace("-", "").isdigit():
            a, b = map(int, spec.split("-", 1))
            return [i.name for i in self.all_ext_ifaces if a <= i.index <= b]
        selected = []
        for part in spec.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part)
                matches = [i.name for i in self.all_ext_ifaces if i.index == idx]
                selected.extend(matches)
            elif part.startswith("wl"):
                if part in [i.name for i in self.all_ext_ifaces]:
                    selected.append(part)
        return selected

    def needs_two_ifaces(self, module_name: str) -> bool:
        """Return True if module typically requires two interfaces."""
        two_iface_modules = {
            "handshake_snooper", "evil_twin", "karma_mana", "pmkid_autopwn",
            "deauth_multimode", "csa_handshake_capture", "captive_portal",
            "evil_twin_workflow", "eap_relay_attack", "dualband_evil_twin",
        }
        for m in two_iface_modules:
            if m in module_name.lower():
                return True
        return False

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def print_banner(self) -> None:
        """Print startup config summary."""
        from wirelessxpl.core.exploit.printer import print_info, print_success, print_warning
        import subprocess as _sp, shutil as _sh

        print_info("=" * 70)
        print_info("  WXF Global Configuration")
        print_info("=" * 70)

        # Behaviour
        destr = "\033[92m✓ DESTRUTIVO\033[0m" if self.destructive else "\033[93m simulado\033[0m"
        sim   = "\033[91m✗ OFF\033[0m" if not self.simulate else "\033[93m✓ ON\033[0m"
        print_info(f"  Modo         │ {destr}  │  simulate={sim}  │  T{self.timing}/{self.timing_name}")
        print_info(f"  LHOST:LPORT  │ \033[92m{self.lhost}:{self.lport}\033[0m  (reverse shell default)")

        # GPU detection
        if _sh.which("hashcat"):
            try:
                r = _sp.run(["hashcat", "-I"], capture_output=True, text=True, timeout=10)
                gpu_lines = [l.strip() for l in r.stdout.splitlines()
                             if "Name" in l and ("Iris" in l or "AMD" in l or "NVIDIA" in l or "GPU" in l.upper())]
                if gpu_lines:
                    print_info(f"  GPU          │ \033[92m{gpu_lines[0]}\033[0m  (hashcat -D 2 --force)")
                else:
                    print_info(f"  GPU          │ \033[93mSó CPU disponível\033[0m  (hashcat -D 1)")
            except Exception:
                pass
        print_info("")

        # Interfaces
        n = len(self.all_ext_ifaces)
        print_info(f"  Interfaces externas USB encontradas: {n}")
        if n == 0:
            print_warning("  NENHUMA interface USB/externa encontrada!")
            print_warning("  Conecte ao menos 1 adaptador WiFi USB externo e reinicie.")
        else:
            print_info(f"  {'#':>3}  {'INTERFACE':<22} {'MODO':<10} {'MON':>4} {'USB':>4}  NOTA")
            print_info(f"  {'-'*65}")
            for iface in self.all_ext_ifaces:
                mon  = "\033[92m✓\033[0m" if iface.monitor_cap else "\033[91m✗\033[0m"
                usb  = "\033[92m✓\033[0m" if iface.usb else "-"
                role = ""
                if iface.name == self.iface_mon:
                    role = "\033[94m[MON/CAPTURE]\033[0m"
                elif iface.name == self.iface_inj:
                    role = "\033[93m[INJECT/AP]\033[0m"
                elif iface.name in self.iface_extra:
                    role = "\033[90m[extra]\033[0m"
                print_info(f"  {iface.index:>3}  {iface.name:<22} {iface.current_mode:<10} {mon:>4} {usb:>4}  {role}")
            print_info("")
            if n == 1:
                print_warning("  Apenas 1 interface externa. Ataques que precisam de 2 adaptadores")
                print_warning("  (handshake snooper, evil twin, CSA capture) precisarão de um segundo.")
            else:
                print_success(f"  {n} interfaces disponíveis. iface_mon={self.iface_mon}  iface_inj={self.iface_inj}")

        print_info("  Para reconfigurar: use generic/wifi/interface_manager")
        print_info("=" * 70)

    def __repr__(self) -> str:
        return (
            f"WXFConfig(timing=T{self.timing}/{self.timing_name}, "
            f"destructive={self.destructive}, simulate={self.simulate}, "
            f"iface_mon={self.iface_mon!r}, iface_inj={self.iface_inj!r}, "
            f"lhost={self.lhost}:{self.lport})"
        )
