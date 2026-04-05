"""Optional bridges to external frameworks (e.g. Metasploit).

WirelessXPL-Forge does not ship the vendored Exploit-DB tree; use upstream repositories and system tools (aircrack-ng, hcxtools, hashcat) as documented.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from wirelessxpl.core.integrations.msf_cli import find_msfconsole, run_msf_batch_commands

__all__ = (
    "find_msfconsole",
    "run_msf_batch_commands",
)
