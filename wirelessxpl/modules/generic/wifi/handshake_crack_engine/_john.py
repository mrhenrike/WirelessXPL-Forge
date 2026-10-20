"""John the Ripper runner."""
from __future__ import annotations
import logging, os, re, subprocess, time
from pathlib import Path
log = logging.getLogger(__name__)
from ._common import _SessionLog
from ._hashcat import CrackResult

def _run_john(
    input_file: Path,
    wordlist: Path,
    result: CrackResult,
    rules: bool,
) -> None:
    john = shutil.which("john") or "/usr/sbin/john"
    cmd = [john, f"--wordlist={wordlist}", "--format=wpapsk"]
    if rules:
        cmd.append("--rules=best64")
    cmd.append(str(input_file))
    print_info(f"  CMD: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, bufsize=1)
        # Skip lines that are john status/info messages, not cracked passwords
        _JOHN_SKIP_PREFIXES = (
            "Will", "Loaded", "Session", "No pass", "Created", "Remaining",
            "Press", "0 password", "guesses:", "Using", "OpenMP", "Default",
        )
        for line in proc.stdout:
            line = line.rstrip()
            result.raw_lines.append(line)
            # John outputs cracked passwords as: hash:password (from --show)
            # During cracking, it outputs: password (ESSID) at position...
            # Skip system/status messages
            if any(line.strip().startswith(p) for p in _JOHN_SKIP_PREFIXES):
                continue
            if ":" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    pwd = parts[0].strip()
                    essid = parts[1].strip() if len(parts) > 1 else "?"
                    # Validate: password should be a likely WPA PSK (8-63 chars, not a path/message)
                    if (pwd and 8 <= len(pwd) <= 63
                            and not pwd.startswith("/") and " " not in pwd
                            and not any(c in pwd for c in ("directory", "hash", "Session"))):
                        result.add_found(essid, pwd, "john")
            elif "Session completed" in line or "No password hashes left" in line:
                result.status = "exhausted"
            if line: print_info(f"  {line}")
        proc.wait()
        # john --show
        r2 = subprocess.run([john, "--show", "--format=wpapsk", str(input_file)],
                             capture_output=True, text=True)
        for line in r2.stdout.splitlines():
            if ":" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    pwd = parts[1].strip()
                    essid = parts[0].strip()
                    if pwd:
                        result.add_found(essid, pwd, "john-show")
    except FileNotFoundError:
        print_error("john not found in PATH")
        result.status = "error"
    except Exception as exc:
        logger.debug("john run: %s", exc)
        result.status = "error"
    if result.status == "running":
        result.status = "exhausted"


