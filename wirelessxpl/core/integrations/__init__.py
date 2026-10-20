"""Optional bridges to external frameworks and compiler runners.

WirelessXPL-Forge does not ship the vendored Exploit-DB tree; use upstream
repositories and system tools (aircrack-ng, hcxtools, hashcat) as documented.

The lang_bridge module provides a generic compiler/interpreter bridge for
integrating non-Python code (Rust, C, C++) via compilation and execution.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from wirelessxpl.core.integrations.msf_cli import find_msfconsole, run_msf_batch_commands

__all__ = (
    "find_msfconsole",
    "run_msf_batch_commands",
)
