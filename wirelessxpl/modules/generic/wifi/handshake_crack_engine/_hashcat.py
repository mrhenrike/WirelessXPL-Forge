"""Hashcat runner."""
from __future__ import annotations
import logging, os, re, shutil, subprocess, time
from dataclasses import dataclass, field
from pathlib import Path
log = logging.getLogger(__name__)
from ._common import _SessionLog, _get_gpu_temperature, _wait_gpu_cooldown, _hashcat_safety_args

class CrackResult:
    def __init__(self) -> None:
        self.found: list[tuple[str, str, str]] = []  # (essid, password, source)
        self.progress: str = ""
        self.speed: str = ""
        self.eta: str = ""
        self.status: str = "running"  # running | finished | exhausted | error
        self.raw_lines: list[str] = []

    def add_found(self, essid: str, password: str, source: str) -> None:
        key = (essid, password)
        if key not in [(f[0], f[1]) for f in self.found]:
            self.found.append((essid, password, source))
            print_success(f"  PASSWORD FOUND: '{password}'  (ESSID: {essid})  [{source}]")


def _run_hashcat(
    hash_file: Path,
    wordlist: Path,
    mode: int,
    device_args: list[str],
    rules: list[str],
    result: CrackResult,
    extra_args: list[str],
) -> None:
    out_file = Path(tempfile.mktemp(suffix=".crack.txt"))
    log_file = Path(tempfile.mktemp(suffix=".hclog.txt"))

    cmd = [
        "hashcat",
        "-m", str(mode),
        "-a", "0",
        "--status", "--status-timer=5",
        "--outfile", str(out_file),
        "--outfile-format=2",   # PASSWORD only in outfile
        "--logfile-disable",
        str(hash_file),
        str(wordlist),
    ]
    for r in rules:
        cmd.extend(["-r", r])
    cmd.extend(device_args)
    cmd.extend(extra_args)

    print_info(f"  CMD: {' '.join(cmd)}")
    print_status("  hashcat initializing (CPU mode ~30-60s init)…")

    found_during_run: set[str] = set()

    def _poll_outfile():
        """Background thread: report passwords as soon as they're written."""
        while not _done.is_set():
            if out_file.exists():
                try:
                    for line in out_file.read_text(errors="replace").splitlines():
                        line = line.strip()
                        if line and line not in found_during_run:
                            found_during_run.add(line)
                            result.add_found("?", line, "hashcat")
                except Exception:
                    pass
            time.sleep(1)


    _done = threading.Event()
    poller = threading.Thread(target=_poll_outfile, daemon=True)
    poller.start()

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=0,
        )
        # Read and parse output; hashcat mixes \r and \n
        buf = ""
        while True:
            ch = proc.stdout.read(1)
            if not ch:
                break
            if ch in ("\n", "\r"):
                line = buf.strip()
                buf = ""
                if not line:
                    continue
                result.raw_lines.append(line)
                # Status lines
                if any(k in line for k in ("Speed.", "Progress", "Recovered", "Exhausted", "Cracked",
                                            "Status...", "Hash.Mode", "Time.Estimated")):
                    print_info(f"  {line}")
                    if "Exhausted" in line:
                        result.status = "exhausted"
                    elif "Cracked" in line and "0/" not in line:
                        result.status = "finished"
            else:
                buf += ch
        proc.wait()
        if result.status == "running":
            result.status = "exhausted" if proc.returncode != 0 else "finished"
    except FileNotFoundError:
        print_error("hashcat not found in PATH")
        result.status = "error"
    except Exception as exc:
        logger.debug("hashcat run error: %s", exc)
        result.status = "error"
    finally:
        _done.set()
        poller.join(timeout=2)

    # Final check from outfile
    if out_file.exists():
        for line in out_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if line:
                result.add_found("?", line, "hashcat-outfile")
        out_file.unlink(missing_ok=True)

    # Also check potfile
    _show_hashcat_cracked(hash_file, mode, result)


def _run_hashcat_mask_chain(
    hash_path: Path,
    mode: int,
    masks: list[str],
    dev_args: list[str],
    extra_base: list[str],
    mask_runtime: int,
    cooldown_s: int,
    gpu_temp_retain: int,
    result: CrackResult,
    slog: _SessionLog,
    verbose: bool,
) -> None:
    """Run prioritized mask chain with per-mask --runtime (HashCater-style)."""
    if not masks:
        return

    for mask in masks:
        if result.found:
            break

        _wait_gpu_cooldown(gpu_temp_retain, slog)
        extra = list(extra_base)
        if mask_runtime > 0:
            extra.extend(["--runtime", str(mask_runtime)])

        print_status(f"  [MASK] {mask}" + (f" (max {mask_runtime}s)" if mask_runtime > 0 else ""))
        slog.write(f"[MASK] {mask}")

        cmd = [
            "hashcat", "-m", str(mode), "-a", "3",
            "--status", "--status-timer=5",
            "--logfile-disable",
            str(hash_path), mask,
        ] + dev_args + extra

        print_info(f"  CMD: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for line in proc.stdout:
                line = line.rstrip()
                result.raw_lines.append(line)
                if verbose:
                    print_info(f"  {line}")
            proc.wait()
        except FileNotFoundError:
            print_error("hashcat not found in PATH")
            result.status = "error"
            return
        except Exception as exc:
            logger.debug("hashcat mask chain: %s", exc)
            result.status = "error"
            return

        _show_hashcat_cracked(hash_path, mode, result)
        if result.found:
            slog.write(f"[CRACKED-MASK] {mask}")
            break

        temp = _get_gpu_temperature()
        if temp is not None:
            slog.write(f"[GPU] {temp}°C")
        if cooldown_s > 0:
            print_status(f"  [COOLDOWN] {cooldown_s}s entre máscaras…")
            slog.write(f"[COOLDOWN] sleep {cooldown_s}s")
            time.sleep(cooldown_s)


def _show_hashcat_cracked(hash_file: Path, mode: int, result: CrackResult) -> None:
    """Run hashcat --show to read cracked entries from potfile."""
    import os as _os
    # Resolve correct potfile path (especially under sudo)
    sudo_user = _os.environ.get("SUDO_USER", "")
    potfile = ""
    if sudo_user:
        potfile = f"/home/{sudo_user}/.local/share/hashcat/hashcat.potfile"
    else:
        cand = _os.path.expanduser("~/.local/share/hashcat/hashcat.potfile")
        if _os.path.exists(cand):
            potfile = cand

    cmd = ["hashcat", "-m", str(mode)]
    if potfile:
        cmd.extend(["--potfile-path", potfile])
    else:
        cmd.append("--potfile-disable")
    # format 2 = plain password only; format 1 = hash only (no password)
    # Use format 2 and extract ESSID from input hash file directly
    cmd.extend(["--outfile-format=2", "--show", str(hash_file)])

    # Pre-read ESSID from hash file for display
    essid_map: dict = {}
    try:
        for line in hash_file.read_text(errors="replace").splitlines():
            parts = line.strip().split("*")
            if len(parts) > 5:
                try:
                    essid_map[line[:20]] = bytes.fromhex(parts[5]).decode("utf-8", errors="replace")
                except Exception:
                    pass
        default_essid = list(essid_map.values())[0] if essid_map else "?"
    except Exception:
        default_essid = "?"

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            pwd = line.strip()
            # Skip hashcat status/init messages (they start with specific patterns)
            if not pwd or len(pwd) < 8 or len(pwd) > 63:
                continue
            # Skip hashcat header/status lines
            if any(pwd.startswith(p) for p in (
                "hashcat", "Session", "Status", "Hash.Mode", "Hash.Target",
                "Time.", "Speed.", "Recovered", "Progress", "Rejected",
                "Restore.Point", "Restore.Sub", "Candidates", "Hardware",
                "Candidate", "Started", "Stopped", "Initializ", "OpenCL",
                "Device", "Platform", "*", "[", "You have",
            )):
                continue
            result.add_found(default_essid, pwd, "hashcat-potfile")
    except Exception as exc:
        logger.debug("hashcat --show: %s", exc)


