"""Bridge to legacy ``mdk3`` (requires compatible drivers; prefer ``mdk4_bridge``).

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import shutil
import subprocess

from wirelessxpl.core.exploit import *

from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab, warn_pmf_ios


class Exploit(Exploit):
    """mdk3 subprocess launcher."""

    __info__ = {
        "name": "mdk3 legacy bridge",
        "description": "Invokes mdk3 <iface> <mode> [options]. Modes include b, a, p, d, m, x, w, f.",
        "authors": ("André Henrique (@mrhenrike)",),
        "references": ("https://svn.mdk3.org/",),
        "devices": ("Linux monitor interface (legacy stacks)",),
    }

    interface = OptString("", "Monitor-mode interface")
    mode = OptString("d", "mdk3 mode letter")
    mode_args = OptString("", "Additional CLI tokens after mode")
    dry_run = OptBool(False, "Print command only")

    def run(self) -> None:
        require_authorised_lab()
        if str(self.mode).lower().startswith("d"):
            warn_pmf_ios()

        exe = shutil.which("mdk3")
        if not exe:
            print_error("mdk3 not in PATH — use distro packages or build; consider mdk4_bridge.")
            return
        if not self.interface:
            print_error("Set interface.")
            return

        cmd = [exe, self.interface, str(self.mode).strip()[:1]]
        rest = str(self.mode_args).strip()
        if rest:
            cmd.extend(rest.split())
        print_status("mdk3: {}".format(" ".join(cmd)))
        if self.dry_run:
            return
        try:
            subprocess.run(cmd, check=False)
        except KeyboardInterrupt:
            print_status("Stopped.")
