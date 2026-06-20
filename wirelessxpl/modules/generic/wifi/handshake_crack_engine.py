#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""WPA/WPA2/WPA3 Handshake & PMKID Crack Engine.

Multi-backend offline cracking module. The user selects the backend;
the module builds the optimal command, streams output, parses results,
and reports found passwords.

Supported backends:
  hashcat_gpu    hashcat with GPU acceleration (-D 2) — fastest
  hashcat_cpu    hashcat CPU only (-D 1 --force)      — GPU-less machines
  hashcat_auto   hashcat auto-detect device            — default
  aircrack       aircrack-ng (pcap/pcapng directly)   — no conversion needed
  john           John the Ripper (wpapsk format)       — CPU, rule support
  cowpatty       cowpatty (genpmk pre-computation)     — targeted attacks
  auto           Try backends in order: hashcat_gpu → aircrack → john

Input formats accepted:
  - .pcapng / .pcap   (4-way handshake or PMKID capture)
  - .hash             (hcxpcapngtool WPA*02* or WPA*01* format)
  - .hccapx / .22000  (hashcat native format)
  - .cap              (aircrack native)

The module automatically converts formats as needed (hcxpcapngtool).

Version: 1.0.0
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from wirelessxpl.core.exploit import (
    Exploit, OptBool, OptInteger, OptString,
    print_error, print_info, print_status, print_success, print_warning,
)
from wirelessxpl.core.os_guard import OSRequirement, requires_os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Backend definitions
# ---------------------------------------------------------------------------

BACKENDS = {
    "hashcat_gpu": {
        "bin":  "hashcat",
        "desc": "hashcat GPU acceleration (-D 2) — CUDA/OpenCL, fastest",
    },
    "hashcat_cpu": {
        "bin":  "hashcat",
        "desc": "hashcat CPU only (-D 1 --force) — no GPU required",
    },
    "hashcat_auto": {
        "bin":  "hashcat",
        "desc": "hashcat auto device detection — picks best available",
    },
    "aircrack": {
        "bin":  "aircrack-ng",
        "desc": "aircrack-ng — reads pcap/pcapng directly, no conversion",
    },
    "john": {
        "bin":  "john",
        "desc": "John the Ripper — wpapsk format, supports rules/mangling",
    },
    "cowpatty": {
        "bin":  "cowpatty",
        "desc": "cowpatty — direct WPA-PSK attack, genpmk pre-computation",
    },
    "auto": {
        "bin":  None,
        "desc": "Auto: try hashcat_gpu → hashcat_cpu → aircrack → john",
    },
}

# Hashcat modes for WPA
_HASH_MODE_WPA_EAPOL  = 22000   # WPA-EAPOL-PBKDF2 (M1+M2 pair)
_HASH_MODE_WPA_PMKID  = 22001   # WPA-PMKID-PBKDF2
_HASH_MODE_HCCAPX     = 2500    # legacy .hccapx

# ---------------------------------------------------------------------------
# Format detection & conversion
# ---------------------------------------------------------------------------

def _detect_file_type(path: Path) -> str:
    """Return one of: pcap, pcapng, hash22000, hccapx, unknown."""
    suffix = path.suffix.lower()
    if suffix in (".pcap", ".cap"):
        return "pcap"
    if suffix == ".pcapng":
        return "pcapng"
    if suffix in (".hccapx",):
        return "hccapx"
    # Inspect first bytes
    try:
        header = path.read_bytes()[:8]
        if header[:4] == b"\xd4\xc3\xb2\xa1":  # pcap LE
            return "pcap"
        if header[:8] == b"\x0a\x0d\x0d\x0a":  # pcapng
            return "pcapng"
    except Exception:
        pass
    # Check for WPA*02* hash format
    try:
        first_line = path.read_text(errors="replace").splitlines()[0]
        if first_line.startswith("WPA*"):
            return "hash22000"
    except Exception:
        pass
    return "unknown"


def _convert_to_hash22000(
    input_path: Path,
    out_dir: Path,
    essid: str = "",
) -> Optional[Path]:
    """Convert pcap/pcapng to hashcat 22000 format via hcxpcapngtool."""
    if not shutil.which("hcxpcapngtool"):
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    out_hash = out_dir / (input_path.stem + ".22000")
    cmd = ["hcxpcapngtool", "--all", "-o", str(out_hash)]
    if essid:
        pass  # hcxpcapngtool doesn't support --essid filter in this version
    cmd.append(str(input_path))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if out_hash.exists() and out_hash.stat().st_size > 0:
        return out_hash
    # Try without --all
    cmd2 = ["hcxpcapngtool", "-o", str(out_hash), str(input_path)]
    subprocess.run(cmd2, capture_output=True, text=True)
    return out_hash if out_hash.exists() and out_hash.stat().st_size > 0 else None


def _convert_to_hccapx(input_path: Path, out_dir: Path) -> Optional[Path]:
    """Convert pcap/pcapng to .hccapx for legacy hashcat -m 2500."""
    if not shutil.which("hcxpcapngtool"):
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    out_hccapx = out_dir / (input_path.stem + ".hccapx")
    cmd = ["hcxpcapngtool", "--hccapx", str(out_hccapx), str(input_path)]
    subprocess.run(cmd, capture_output=True, text=True)
    return out_hccapx if out_hccapx.exists() and out_hccapx.stat().st_size > 0 else None


def _convert_for_john(input_path: Path, out_dir: Path) -> Optional[Path]:
    """Convert pcap to john wpapsk format via hcxpcapngtool or wpapcap2john."""
    # Try wpapcap2john (part of john-the-ripper extras)
    for tool in ("wpapcap2john", "hccap2john"):
        if shutil.which(tool):
            out_dir.mkdir(parents=True, exist_ok=True)
            out_john = out_dir / (input_path.stem + ".john")
            r = subprocess.run(
                [tool, str(input_path)],
                capture_output=True, text=True,
            )
            if r.stdout.strip():
                out_john.write_text(r.stdout)
                return out_john
    return None


# ---------------------------------------------------------------------------
# Backend runners
# ---------------------------------------------------------------------------

class CrackResult:
    def __init__(self) -> None:
        self.found: List[Tuple[str, str, str]] = []  # (essid, password, source)
        self.progress: str = ""
        self.speed: str = ""
        self.eta: str = ""
        self.status: str = "running"  # running | finished | exhausted | error
        self.raw_lines: List[str] = []

    def add_found(self, essid: str, password: str, source: str) -> None:
        key = (essid, password)
        if key not in [(f[0], f[1]) for f in self.found]:
            self.found.append((essid, password, source))
            print_success(f"  PASSWORD FOUND: '{password}'  (ESSID: {essid})  [{source}]")


def _run_hashcat(
    hash_file: Path,
    wordlist: Path,
    mode: int,
    device_args: List[str],
    rules: List[str],
    result: CrackResult,
    extra_args: List[str],
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

    found_during_run: Set[str] = set()

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


def _show_hashcat_cracked(hash_file: Path, mode: int, result: CrackResult) -> None:
    """Run hashcat --show to read cracked entries."""
    try:
        r = subprocess.run(
            ["hashcat", "-m", str(mode), "--potfile-disable",
             "--outfile-format=2", "--show", str(hash_file)],
            capture_output=True, text=True, timeout=10,
        )
        for line in r.stdout.splitlines():
            line = line.strip()
            if line and ":" in line:
                parts = line.rsplit(":", 1)
                if len(parts) == 2:
                    pwd = parts[1].strip()
                    essid_hex = parts[0].split("*")[4] if "*" in parts[0] else "?"
                    try:
                        essid = bytes.fromhex(essid_hex).decode("utf-8", errors="replace")
                    except Exception:
                        essid = essid_hex
                    if pwd:
                        result.add_found(essid, pwd, "hashcat-potfile")
    except Exception as exc:
        logger.debug("hashcat --show: %s", exc)


def _run_aircrack(
    pcap_file: Path,
    wordlist: Path,
    essid: str,
    result: CrackResult,
) -> None:
    cmd = ["aircrack-ng", "-w", str(wordlist), "-l", "/tmp/wxf_crack_result.txt"]
    if essid:
        cmd.extend(["-e", essid])
    cmd.append(str(pcap_file))
    print_info(f"  CMD: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in proc.stdout:
            line = line.rstrip()
            result.raw_lines.append(line)
            # KEY FOUND
            if "KEY FOUND!" in line:
                m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", line)
                if m:
                    result.add_found(essid or "?", m.group(1), "aircrack-ng")
                    result.status = "finished"
            elif "keys tested" in line.lower():
                result.progress = line.strip()
                print_info(f"  {result.progress}")
            elif "failed" in line.lower():
                result.status = "exhausted"
        proc.wait()
        # Also check output file
        out_f = Path("/tmp/wxf_crack_result.txt")
        if out_f.exists():
            pwd = out_f.read_text().strip()
            if pwd:
                result.add_found(essid or "?", pwd, "aircrack-ng")
            out_f.unlink(missing_ok=True)
    except FileNotFoundError:
        print_error("aircrack-ng not found in PATH")
        result.status = "error"
    except Exception as exc:
        logger.debug("aircrack run: %s", exc)
        result.status = "error"
    if result.status == "running":
        result.status = "exhausted"


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
        for line in proc.stdout:
            line = line.rstrip()
            result.raw_lines.append(line)
            if ":" in line and not line.startswith("Will") and not line.startswith("Loaded"):
                parts = line.split(":")
                if len(parts) >= 2:
                    pwd = parts[0].strip()
                    essid = parts[1].strip() if len(parts) > 1 else "?"
                    if pwd and len(pwd) >= 8:
                        result.add_found(essid, pwd, "john")
            elif "Session completed" in line or "No password hashes left" in line:
                result.status = "exhausted"
            print_info(f"  {line}") if line else None
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


def _run_cowpatty(
    pcap_file: Path,
    wordlist: Path,
    essid: str,
    result: CrackResult,
) -> None:
    if not shutil.which("cowpatty"):
        print_error("cowpatty not found")
        result.status = "error"
        return
    if not essid:
        print_error("cowpatty requires ESSID (set essid option)")
        result.status = "error"
        return
    cmd = ["cowpatty", "-f", str(wordlist), "-r", str(pcap_file), "-s", essid]
    print_info(f"  CMD: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, bufsize=1)
        for line in proc.stdout:
            line = line.rstrip()
            result.raw_lines.append(line)
            if "The PSK is" in line:
                m = re.search(r"The PSK is[:\s]+(.+)", line)
                if m:
                    result.add_found(essid, m.group(1).strip(), "cowpatty")
                    result.status = "finished"
            elif "Unable to identify correct PSK" in line:
                result.status = "exhausted"
            elif "%" in line or "key(s)" in line.lower():
                result.progress = line.strip()
        proc.wait()
    except Exception as exc:
        logger.debug("cowpatty: %s", exc)
        result.status = "error"
    if result.status == "running":
        result.status = "exhausted"


# ---------------------------------------------------------------------------
# WXF Exploit class
# ---------------------------------------------------------------------------

@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """WPA/WPA2 Handshake & PMKID Crack Engine — multi-backend.

    Supported backends:
      hashcat_gpu   GPU cracking via CUDA/OpenCL (fastest — ~5MH/s on RTX)
      hashcat_cpu   CPU cracking via hashcat --force -D 1
      hashcat_auto  hashcat auto-selects best device
      aircrack      aircrack-ng — reads pcap/pcapng natively
      john          John the Ripper — with rule support
      cowpatty      cowpatty — targeted WPA-PSK
      auto          tries hashcat_gpu → aircrack → john in sequence

    Input:
      .pcapng / .pcap    4-way handshake or PMKID capture (auto-converted)
      .hash / .22000     hcxpcapngtool WPA*02* format (hashcat ready)

    Examples:
      set backend hashcat_gpu
      set input_file /tmp/wxf_caps/csa_v3.hash
      set wordlist /usr/share/wordlists/rockyou.txt
      run

      set backend aircrack
      set input_file /tmp/wxf_caps/handshake.pcapng
      set essid TrOll_MaStEr_BLaStEr_2Ghz
      set wordlist /home/mrhenrike/Documentos/Projetos/WordListsForHacking/passwords/wlist_brasil.lst
      run
    """

    __info__ = {
        "name": "WPA Crack Engine (multi-backend)",
        "description": (
            "Offline WPA/WPA2 cracking with multiple backends: hashcat (GPU/CPU), "
            "aircrack-ng, John the Ripper, cowpatty. Auto-converts pcap/pcapng to "
            "the required format for each backend. Parses output and reports "
            "found passwords. Supports custom wordlists, rules, and masks."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2",
            "https://www.aircrack-ng.org/doku.php?id=cracking_wpa",
        ),
        "devices": ("wifi", "WPA2", "WPA3", "offline-crack"),
    }

    backend    = OptString(
        "auto",
        "Backend: auto | hashcat_gpu | hashcat_cpu | hashcat_auto | aircrack | john | cowpatty | list",
    )
    input_file = OptString("", "Path to handshake pcap/pcapng or hash file (.hash/.22000/.hccapx)")
    wordlist   = OptString(
        "/home/mrhenrike/Documentos/Projetos/WordListsForHacking/passwords/wlist_brasil.lst",
        "Path to wordlist file",
    )
    essid      = OptString("", "Target ESSID (required for aircrack/cowpatty, optional for hashcat)")
    rules      = OptString("", "Comma-separated rule files for hashcat (e.g. best64,dive) or 'none'")
    use_rules  = OptBool(False, "Apply best64 rules to wordlist (adds ~64x candidates)")
    masks      = OptString("", "Hashcat mask for brute-force (e.g. ?d?d?d?d?d?d?d?d for 8 digits)")
    potfile    = OptString("", "Hashcat potfile path (empty = use default)")
    timeout_s  = OptInteger(0, "Max cracking time in seconds (0 = unlimited)")
    verbose    = OptBool(False, "Show raw backend output line by line")
    check_only = OptBool(False, "Only check/convert input file and show info, don't crack")

    # ------------------------------------------------------------------

    def check(self) -> str:
        available = [name for name, info in BACKENDS.items()
                     if info["bin"] is None or shutil.which(info["bin"])]
        missing   = [name for name, info in BACKENDS.items()
                     if info["bin"] and not shutil.which(info["bin"])]
        return (
            f"Available backends: {', '.join(available)} | "
            f"Missing: {', '.join(missing) or 'none'}"
        )

    def run(self) -> None:
        backend_id = str(self.backend).strip().lower()

        # ---- list mode ----
        if backend_id == "list":
            self._list_backends()
            return

        input_path = Path(str(self.input_file).strip())
        wordlist_path = Path(str(self.wordlist).strip())

        # Validate input
        if not str(self.input_file).strip():
            print_error("Set input_file to a handshake pcap/pcapng or hash file.")
            self._show_usage()
            return
        if not input_path.exists():
            print_error(f"Input file not found: {input_path}")
            return
        if not wordlist_path.exists() and not bool(self.masks):
            print_warning(f"Wordlist not found: {wordlist_path}")
            print_info("Continuing — will use mask attack if masks is set.")

        # Detect file type
        file_type = _detect_file_type(input_path)
        print_status(f"Input: {input_path.name} ({file_type})")

        # Check-only mode
        if bool(self.check_only):
            self._inspect_input(input_path, file_type)
            return

        # Resolve backend
        if backend_id == "auto":
            backends = self._auto_order()
        else:
            backends = [backend_id]

        for be in backends:
            if be not in BACKENDS:
                print_error(f"Unknown backend {be!r}. Use 'list' to see options.")
                return
            if BACKENDS[be]["bin"] and not shutil.which(BACKENDS[be]["bin"]):
                print_warning(f"Backend {be!r} not available ({BACKENDS[be]['bin']} not found). Skipping.")
                continue
            print_success(f"Backend: {be} — {BACKENDS[be]['desc']}")
            result = CrackResult()
            self._run_backend(be, input_path, wordlist_path, file_type, result)
            self._print_summary(be, result)
            if result.found:
                return  # password found — stop
            if backend_id != "auto":
                break

        if not any([CrackResult().found]):
            pass  # handled in _print_summary

    # ------------------------------------------------------------------
    # Backend dispatcher
    # ------------------------------------------------------------------

    def _run_backend(
        self,
        be: str,
        input_path: Path,
        wordlist: Path,
        file_type: str,
        result: CrackResult,
    ) -> None:
        tmp_dir = Path(tempfile.mkdtemp(prefix="wxf_crack_"))
        essid = str(self.essid).strip()
        timeout = int(self.timeout_s)

        try:
            if be in ("hashcat_gpu", "hashcat_cpu", "hashcat_auto"):
                self._run_hashcat_backend(be, input_path, wordlist, file_type, result, tmp_dir)

            elif be == "aircrack":
                if file_type in ("pcap", "pcapng"):
                    _run_aircrack(input_path, wordlist, essid, result)
                else:
                    print_warning("aircrack-ng works best with pcap/pcapng. Converting not supported for this format.")
                    result.status = "error"

            elif be == "john":
                john_file = _convert_for_john(input_path, tmp_dir) if file_type in ("pcap","pcapng") else input_path
                if john_file is None:
                    # Try via hash22000 conversion + john with direct format
                    hash_f = _convert_to_hash22000(input_path, tmp_dir)
                    john_file = hash_f or input_path
                _run_john(john_file, wordlist, result, rules=bool(self.use_rules))

            elif be == "cowpatty":
                if file_type in ("pcap", "pcapng"):
                    _run_cowpatty(input_path, wordlist, essid, result)
                else:
                    print_warning("cowpatty requires pcap/pcapng input.")
                    result.status = "error"
        finally:
            # Cleanup temp files
            import shutil as _sh
            _sh.rmtree(tmp_dir, ignore_errors=True)

    def _run_hashcat_backend(
        self,
        be: str,
        input_path: Path,
        wordlist: Path,
        file_type: str,
        result: CrackResult,
        tmp_dir: Path,
    ) -> None:
        # Device flags — Intel/AMD GPU require --force to bypass API warnings
        if be == "hashcat_gpu":
            dev_args = ["-D", "2", "--force"]   # D 2 = GPU (Intel Iris Xe, AMD, NVIDIA)
        elif be == "hashcat_cpu":
            dev_args = ["-D", "1", "--force"]
        else:  # hashcat_auto
            dev_args = ["--force"]  # auto-detect best device

        # Extra args
        extra: List[str] = []
        if str(self.potfile).strip():
            extra.extend(["--potfile-path", str(self.potfile)])
        if int(self.timeout_s) > 0:
            extra.extend(["--runtime", str(self.timeout_s)])
        if bool(self.verbose):
            extra.remove("--quiet") if "--quiet" in extra else None

        # Rules
        rule_files: List[str] = []
        rules_raw = str(self.rules).strip()
        if rules_raw and rules_raw.lower() != "none":
            for r in rules_raw.split(","):
                r = r.strip()
                if os.path.exists(r):
                    rule_files.append(r)
                else:
                    # Try standard hashcat rules path
                    for d in ["/usr/share/hashcat/rules", "/usr/local/share/hashcat/rules"]:
                        p = os.path.join(d, r if r.endswith(".rule") else r + ".rule")
                        if os.path.exists(p):
                            rule_files.append(p)
                            break
        if bool(self.use_rules) and not rule_files:
            for d in ["/usr/share/hashcat/rules", "/usr/local/share/hashcat/rules"]:
                p = os.path.join(d, "best64.rule")
                if os.path.exists(p):
                    rule_files.append(p)
                    break

        # Convert input to hashcat format
        hash_path = input_path
        mode = _HASH_MODE_WPA_EAPOL

        if file_type in ("pcap", "pcapng"):
            print_status(f"  Converting {input_path.name} → WPA*02* format via hcxpcapngtool…")
            converted = _convert_to_hash22000(input_path, tmp_dir)
            if converted:
                hash_path = converted
                # Detect PMKID vs EAPOL
                content = converted.read_text(errors="replace")
                if "WPA*01*" in content:
                    mode = _HASH_MODE_WPA_PMKID
                    print_info("  Detected WPA*01* (PMKID) hashes → mode 22001")
                else:
                    mode = _HASH_MODE_WPA_EAPOL
                    print_info("  Detected WPA*02* (EAPOL) hashes → mode 22000")
                n = len([l for l in content.splitlines() if l.strip()])
                print_info(f"  Hashes in file: {n}")
            else:
                print_error("  Conversion failed. Is hcxpcapngtool installed?")
                result.status = "error"
                return
        elif file_type == "hccapx":
            mode = _HASH_MODE_HCCAPX
            print_info(f"  Legacy .hccapx format → mode {mode}")
        elif file_type == "hash22000":
            content = hash_path.read_text(errors="replace")
            if "WPA*01*" in content:
                mode = _HASH_MODE_WPA_PMKID
            elif "WPA*02*" in content:
                mode = _HASH_MODE_WPA_EAPOL
            n = len([l for l in content.splitlines() if l.strip()])
            print_info(f"  Hash mode: {mode} | Hashes: {n}")

        # Mask attack
        mask = str(self.masks).strip()
        if mask:
            print_status(f"  Mask attack: {mask}")
            mask_cmd = [
                "hashcat", "-m", str(mode), "-a", "3",
                "--potfile-disable", "--status", "--status-timer=5",
                "--quiet",
                str(hash_path), mask,
            ] + dev_args + extra
            print_info(f"  CMD: {' '.join(mask_cmd)}")
            try:
                proc = subprocess.Popen(mask_cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True, bufsize=1)
                for line in proc.stdout:
                    line = line.rstrip()
                    result.raw_lines.append(line)
                    if ":" in line and "*" not in line and len(line) < 80:
                        parts = line.rsplit(":", 1)
                        if len(parts) == 2 and parts[1].strip():
                            result.add_found("?", parts[1].strip(), "hashcat-mask")
                    if bool(self.verbose):
                        print_info(f"  {line}")
                proc.wait()
            except Exception as exc:
                logger.debug("hashcat mask: %s", exc)

        # Wordlist attack
        if wordlist.exists():
            _run_hashcat(hash_path, wordlist, mode, dev_args, rule_files, result, extra)
        else:
            print_warning(f"  Wordlist {wordlist} not found — skipping dictionary attack.")

    # ------------------------------------------------------------------
    # Auto-order
    # ------------------------------------------------------------------

    def _auto_order(self) -> List[str]:
        """Return backends in priority order based on what's installed."""
        order = []
        # GPU first
        if shutil.which("hashcat"):
            order.append("hashcat_gpu")
        # Then aircrack (good for direct pcap)
        if shutil.which("aircrack-ng"):
            order.append("aircrack")
        # Then hashcat CPU
        if shutil.which("hashcat") and "hashcat_gpu" in order:
            order.append("hashcat_cpu")
        # Then john
        if shutil.which("john") or shutil.which("/usr/sbin/john"):
            order.append("john")
        return order or ["aircrack"]

    # ------------------------------------------------------------------
    # Inspect
    # ------------------------------------------------------------------

    def _inspect_input(self, path: Path, file_type: str) -> None:
        print_status(f"File: {path}")
        print_info(f"  Size:   {path.stat().st_size:,} bytes")
        print_info(f"  Type:   {file_type}")
        if file_type in ("pcap", "pcapng") and shutil.which("hcxpcapngtool"):
            r = subprocess.run(
                ["hcxpcapngtool", path],
                capture_output=True, text=True,
            )
            for line in (r.stdout + r.stderr).splitlines():
                if any(k in line for k in ("EAPOL", "PMKID", "BEACON", "ESSID", "BSSID", "handshake")):
                    print_info(f"  {line.strip()}")
        elif file_type == "hash22000":
            lines = [l for l in path.read_text(errors="replace").splitlines() if l.strip()]
            print_info(f"  Hashes: {len(lines)}")
            for l in lines[:3]:
                parts = l.split("*")
                # WPA*02/01 * MIC(2) * AP_MAC(3) * CLIENT_MAC(4) * ESSID_HEX(5) * ANONCE(6) * EAPOL(7) * MSGPAIR(8)
                if len(parts) > 5:
                    try:
                        essid = bytes.fromhex(parts[5]).decode("utf-8", errors="replace")
                        ap_hex = parts[3]
                        ap_mac = ":".join(ap_hex[i:i+2] for i in range(0, min(12, len(ap_hex)), 2))
                        cl_hex = parts[4]
                        cl_mac = ":".join(cl_hex[i:i+2] for i in range(0, min(12, len(cl_hex)), 2))
                        mode_type = "22001 (PMKID)" if "WPA*01*" in l else "22000 (EAPOL)"
                        print_info(f"    ESSID={essid!r:35} AP={ap_mac}  CLIENT={cl_mac}  mode={mode_type}")
                    except Exception:
                        print_info(f"    {l[:80]}…")

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _list_backends(self) -> None:
        print_status("Available cracking backends:")
        print_info(f"  {'BACKEND':<16} {'INSTALLED':<12} DESCRIPTION")
        print_info(f"  {'-'*70}")
        for name, info in BACKENDS.items():
            installed = "✓" if (info["bin"] is None or shutil.which(info["bin"])) else "✗ (missing)"
            print_info(f"  {name:<16} {installed:<12} {info['desc']}")
        print_info("")
        print_info("  Usage: set backend <name>")
        print_info("         set input_file /path/to/handshake.pcapng")
        print_info("         set wordlist /path/to/wordlist.txt")
        print_info("         run")
        print_info("")
        print_info("  Rules: set use_rules true  (applies best64 — 64x more candidates)")
        print_info("  Mask:  set masks '?d?d?d?d?d?d?d?d'  (8-digit brute-force)")

    def _show_usage(self) -> None:
        print_info("Quick usage:")
        print_info("  set backend hashcat_gpu")
        print_info("  set input_file /tmp/wxf_caps/csa_v3.hash")
        print_info("  set wordlist /path/to/rockyou.txt")
        print_info("  run")

    def _print_summary(self, be: str, result: CrackResult) -> None:
        print_info("")
        print_info("=" * 60)
        print_info(f"  Backend: {be} | Status: {result.status}")
        if result.found:
            print_success(f"  PASSWORDS FOUND: {len(result.found)}")
            for essid, pwd, src in result.found:
                print_success(f"    ESSID: {essid!r:30}  KEY: {pwd!r}  [{src}]")
        else:
            print_warning("  No password found with this wordlist/backend.")
            print_info("  Tips:")
            print_info("    - Try a larger wordlist (rockyou.txt, wlist_brasil.lst)")
            print_info("    - Enable rules:  set use_rules true")
            print_info("    - Try mask:       set masks '?d?d?d?d?d?d?d?d'")
            print_info("    - Try other backend: set backend aircrack")
        print_info("=" * 60)
