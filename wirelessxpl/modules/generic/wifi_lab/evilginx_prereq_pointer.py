"""Check for Evilginx / MITM tooling on PATH and print upstream references.

Wi-Fi evil-twin often hands off HTTP(S) credential phishing to reverse proxies;
this module does not bundle Evilginx — it only audits prerequisites.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import shutil

from wirelessxpl.core.exploit import *


class Exploit(Exploit):
    """Detect Evilginx binary and show clone URLs for MFA bypass research labs."""

    __info__ = {
        "name": "Evilginx prerequisite pointer",
        "description": "Locates ``evilginx`` on PATH and references the upstream project; "
                       "use only in isolated phishing/MFA labs with written consent.",
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://github.com/kgretzky/evilginx2",
            "https://help.evilginx.com/",
        ),
        "devices": ("Lab attacker host",),
    }

    def run(self) -> None:
        for name in ("evilginx", "evilginx2"):
            p = shutil.which(name)
            if p:
                print_success("{} → {}".format(name, p))
            else:
                print_error("{} — not on PATH".format(name))
        print_status(
            "MFA/session bypass flows pair Wi-Fi L2 traps with HTTPS phishing — "
            "run Evilginx on a separate orchestration host if your distro packages it."
        )
