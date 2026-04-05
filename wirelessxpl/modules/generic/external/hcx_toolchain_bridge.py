"""Run ZerBea hcxtools helpers against a capture (optional conversion to hashcat formats).

Requires ``hcxpcapngtool`` / ``hcxpcaptool`` on PATH — installed from Linux distro packages
or https://github.com/ZerBea/hcxtools

Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from wirelessxpl.core.exploit import *


class Exploit(Exploit):
    """Subprocess bridge to hcxtools."""

    __info__ = {
        "name": "hcxtools PCAP bridge",
        "description": "Invokes hcxpcapngtool (preferred) or hcxpcaptool on a WPA/WPA2 capture "
                       "to emit hashcat-compatible lines (e.g. 22000). Does not ship hcxtools.",
        "authors": ("André Henrique (@mrhenrike)",),
        "references": ("https://github.com/ZerBea/hcxtools",),
        "devices": ("802.11 WPA2/WPA3-transition PCAP/PCAPNG",),
    }

    pcap_file = OptString("", "Input PCAP/PCAPNG path")
    output_file = OptString("", "Output .hc22000 or hash file (empty = alongside input)")
    tool_preference = OptString(
        "hcxpcapngtool",
        "Binary name: hcxpcapngtool | hcxpcaptool",
    )
    extra_args = OptString("", "Extra CLI args (advanced)", advanced=True)

    def run(self) -> None:
        if not self.pcap_file or not os.path.isfile(self.pcap_file):
            print_error("Set pcap_file to a valid file.")
            return
        tool = shutil.which(str(self.tool_preference).strip()) or shutil.which("hcxpcapngtool")
        if not tool:
            tool = shutil.which("hcxpcaptool")
        if not tool:
            print_error("hcxpcapngtool/hcxpcaptool not found. Install hcxtools.")
            return
        outp = str(self.output_file).strip()
        if not outp:
            base = Path(self.pcap_file).resolve()
            outp = str(base.with_suffix(".hc22000"))
        cmd = [tool, "-o", outp, self.pcap_file]
        extra = str(self.extra_args).strip()
        if extra:
            cmd.extend(extra.split())
        print_status("Running: {}".format(" ".join(cmd)))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except Exception as exc:
            print_error(str(exc))
            return
        if proc.stdout:
            print_info(proc.stdout.strip())
        if proc.stderr:
            print_status(proc.stderr.strip())
        if proc.returncode == 0:
            print_success("Wrote: {}".format(outp))
            print_info("Try: hashcat -m 22000 {} wordlist.txt".format(outp))
        else:
            print_error("hcxtools exited with code {}".format(proc.returncode))
