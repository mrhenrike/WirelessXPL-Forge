"""Aircrack, john, cowpatty, Exploit."""
from __future__ import annotations
import logging, os, re, shutil, subprocess, time
from dataclasses import dataclass, field
from pathlib import Path
log = logging.getLogger(__name__)
from ._common import _SessionLog
from ._convert import _collect_input_paths, _detect_file_type, _convert_to_hash22000, _convert_to_hccapx, _convert_for_john, _prepare_wordlist, _batch_convert_directory
from ._hashcat import CrackResult, _run_hashcat, _run_hashcat_mask_chain, _show_hashcat_cracked

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


