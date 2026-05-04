#!/usr/bin/env python3
"""Fix hcxdumptool v6.3 compatibility: --enable_status flag was removed."""
import re
from pathlib import Path

BASE = Path("/mnt/d/Projetos-SafeLabs/submodules/IoT/WirelessXPL-Forge/wirelessxpl/modules")

files_to_fix = [
    BASE / "generic/wifi_lab/pmkid_autopwn.py",
    BASE / "generic/wifi_lab/momo_integrated_attack.py",
    BASE / "generic/wifi_lab/ap_less_client_attack.py",
    BASE / "generic/external/hcxdumptool_live_bridge.py",
]

for f in files_to_fix:
    if not f.exists():
        print(f"SKIP: {f.name}")
        continue
    content = f.read_text(encoding="utf-8")
    
    # Remove standalone --enable_status=N from command lists
    new_content = re.sub(r'\s*"--enable_status=\d+",?\s*\n', '\n', content)
    # Remove f-string versions
    new_content = re.sub(r'\s*f?"--enable_status=\{[^}]+\}",?\s*\n', '\n', new_content)
    # Remove cmd.append("--enable_status=...") lines
    new_content = re.sub(r'\s*cmd\.append\(.*enable_status.*\)\s*\n', '\n', new_content)
    # Remove cmd.extend([f"--enable_status=..."]) lines
    new_content = re.sub(r'\s*cmd\.extend\(\[.*enable_status.*\]\)\s*\n', '\n', new_content)
    
    if new_content != content:
        f.write_text(new_content, encoding="utf-8")
        print(f"FIXED: {f.name}")
    else:
        print(f"OK (no change needed): {f.name}")
