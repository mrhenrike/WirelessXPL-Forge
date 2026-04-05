"""Generate a minimal ``hostapd`` configuration and launch ``hostapd`` (Linux lab AP).

Open or WPA2-PSK; for evil-twin lab pair with ``dnsmasq`` / ``captive_portal_modern_lab``.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from wirelessxpl.core.exploit import *

from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab


class Exploit(Exploit):
    """hostapd helper for rogue / test AP."""

    __info__ = {
        "name": "hostapd rogue AP bridge",
        "description": "Writes hostapd.conf for AP mode (nl80211) and execs hostapd. "
                       "Requires ap-mode capable NIC + correct driver.",
        "authors": ("André Henrique (@mrhenrike)",),
        "references": ("https://w1.fi/hostapd/",),
        "devices": ("Linux AP-capable WLAN",),
    }

    interface = OptString("", "AP interface in managed/AP mode (e.g. wlan0)")
    ssid = OptString("WXF-LAB", "ESSID to announce")
    channel = OptInteger(6, "2.4 GHz channel (1-11 typical)")
    hw_mode = OptString("g", "hostapd hw_mode: g (2.4) or a (5 GHz)")
    wpa = OptInteger(0, "0=open, 2=WPA2-PSK")
    wpa_passphrase = OptString("", "WPA2 passphrase (8+ chars) when wpa=2")
    country_code = OptString("", "ISO country (e.g. US) — optional but recommended")
    dump_config_path = OptString(
        "",
        "Write conf here and exit without running hostapd (empty = run)",
        advanced=True,
    )
    dry_run = OptBool(False, "Print conf only")

    def run(self) -> None:
        require_authorised_lab()
        if not self.interface:
            print_error("Set interface.")
            return
        if int(self.wpa) == 2 and len(str(self.wpa_passphrase)) < 8:
            print_error("WPA2 PSK must be at least 8 characters.")
            return

        conf_lines = [
            "driver=nl80211",
            "interface={}".format(self.interface),
            "ssid={}".format(self.ssid),
            "hw_mode={}".format(self.hw_mode),
            "channel={}".format(int(self.channel)),
            "auth_algs=1",
            "wmm_enabled=1",
        ]
        cc = str(self.country_code).strip()
        if cc:
            conf_lines.append("country_code={}".format(cc))

        if int(self.wpa) == 2:
            conf_lines.extend(
                [
                    "wpa=2",
                    "wpa_key_mgmt=WPA-PSK",
                    "rsn_pairwise=CCMP",
                    'wpa_passphrase="{}"'.format(str(self.wpa_passphrase).replace('"', "")),
                ]
            )
        else:
            conf_lines.append("wpa=0")

        text = "\n".join(conf_lines) + "\n"
        dump = str(self.dump_config_path).strip()
        if dump:
            Path(dump).write_text(text, encoding="utf-8")
            print_success("Wrote {}".format(dump))
            return

        if self.dry_run:
            print_status(text)
            return

        hp = shutil.which("hostapd")
        if not hp:
            print_error("hostapd not found. Install hostapd package.")
            return

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix="_hostapd.conf",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            tmp.write(text)
            cfg = tmp.name
        print_status("Starting hostapd with {}".format(cfg))
        print_info(text)
        try:
            subprocess.run([hp, cfg], check=False)
        except KeyboardInterrupt:
            print_status("hostapd stop requested.")
        finally:
            try:
                os.unlink(cfg)
            except OSError:
                pass
