"""Format conversion."""
from __future__ import annotations
import logging, os, re, shutil, subprocess
from pathlib import Path
log = logging.getLogger(__name__)
from ._common import _SessionLog

def _resolve_mask_list(essid: str, masks_opt: str, smart_masks: bool) -> list[str]:
    manual = [m.strip() for m in masks_opt.split(",") if m.strip()]
    if manual:
        return manual
    if smart_masks and essid:
        return _generate_smart_masks(essid)
    return []


def _batch_convert_directory(
    dir_path: Path,
    skip_existing: bool = True,
    slog: _SessionLog | None = None,
) -> dict[str, int]:
    """Cap2Hash-style batch PCAP/CAP → .hc22000 with skip and cleanup."""
    stats = {"total": 0, "converted": 0, "skipped": 0, "failed": 0}
    if not shutil.which("hcxpcapngtool"):
        print_error("hcxpcapngtool not found — install hcxtools.")
        return stats

    files: list[Path] = []
    for pat in _CAPTURE_GLOBS:
        files.extend(sorted(dir_path.glob(pat)))
    stats["total"] = len(files)
    if not files:
        print_warning(f"Nenhum .pcap/.cap/.pcapng em {dir_path}")
        return stats

    print_status(f"[Cap2Hash] {len(files)} captura(s) em {dir_path}")
    for cap in files:
        out_hash = cap.with_suffix(".hc22000")
        if skip_existing and out_hash.exists() and out_hash.stat().st_size > 0:
            print_info(f"  [SKIP] {out_hash.name} já existe")
            stats["skipped"] += 1
            if slog:
                slog.write(f"[SKIP] {out_hash}")
            continue

        print_status(f"  [*] Convertendo: {cap.name}")
        r = subprocess.run(
            ["hcxpcapngtool", "-o", str(out_hash), str(cap)],
            capture_output=True, text=True,
        )
        if r.returncode == 0 and out_hash.exists() and out_hash.stat().st_size > 0:
            print_success(f"  [+] {cap.name} → {out_hash.name}")
            stats["converted"] += 1
            if slog:
                slog.write(f"[+] {cap.name} -> {out_hash.name}")
        else:
            print_error(f"  [!] Falha: {cap.name}")
            out_hash.unlink(missing_ok=True)
            stats["failed"] += 1
            if slog:
                slog.write(f"[!] failed {cap.name}")

    print_info("=" * 44)
    print_success(f"  Convertidos: {stats['converted']} | Pulados: {stats['skipped']} | Falhas: {stats['failed']}")
    print_info("=" * 44)
    return stats


def _collect_input_paths(input_file: str, input_dir: str) -> list[Path]:
    """Resolve single file or batch directory inputs."""
    dir_raw = input_dir.strip()
    if dir_raw:
        d = Path(dir_raw).expanduser()
        if not d.is_dir():
            raise FileNotFoundError(f"input_dir not found: {d}")
        paths: list[Path] = []
        for pat in _CAPTURE_GLOBS + _HASH_GLOBS + ("*.hccapx",):
            paths.extend(sorted(d.glob(pat)))
        return list(dict.fromkeys(paths))  # dedupe, preserve order

    file_raw = input_file.strip()
    if not file_raw:
        return []
    p = Path(file_raw).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"input_file not found: {p}")
    return [p]

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
    if suffix in (".hc22000", ".22000", ".hash"):
        return "hash22000"
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
) -> Path | None:
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


def _convert_to_hccapx(input_path: Path, out_dir: Path) -> Path | None:
    """Convert pcap/pcapng to .hccapx for legacy hashcat -m 2500."""
    if not shutil.which("hcxpcapngtool"):
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    out_hccapx = out_dir / (input_path.stem + ".hccapx")
    cmd = ["hcxpcapngtool", "--hccapx", str(out_hccapx), str(input_path)]
    subprocess.run(cmd, capture_output=True, text=True)
    return out_hccapx if out_hccapx.exists() and out_hccapx.stat().st_size > 0 else None


def _convert_for_john(input_path: Path, out_dir: Path) -> Path | None:
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
# Wordlist order preparation
# ---------------------------------------------------------------------------

def _prepare_wordlist(wordlist_path: Path, order: str) -> Path:
    """Prepare wordlist according to scan order.

    Args:
        wordlist_path: Original wordlist file.
        order: 'random' (default) | 'forward' | 'reverse'

    Returns:
        Path to wordlist to use (original or shuffled/reversed temp copy).
    """
    import random as _random
    order = order.strip().lower()

    if order in ("forward", "fwd"):
        print_info("  Wordlist order: FORWARD (1ª → última linha)")
        return wordlist_path

    if order in ("reverse", "rev", "inverted"):
        print_status("  Wordlist order: REVERSE (última → 1ª linha) — preparando…")
        lines = wordlist_path.read_bytes().split(b"\n")
        lines.reverse()
        tmp = Path(tempfile.mktemp(suffix="_rev.lst"))
        tmp.write_bytes(b"\n".join(lines))
        print_success(f"  Reversed wordlist: {tmp.name} ({len(lines):,} linhas)")
        return tmp

    # random (default) — embaralha toda a lista para ordem dinâmica imprevisível
    print_status("  Wordlist order: RANDOM (dinâmico, embaralhado) — preparando…")
    lines = wordlist_path.read_bytes().split(b"\n")
    _random.shuffle(lines)
    tmp = Path(tempfile.mktemp(suffix="_rnd.lst"))
    tmp.write_bytes(b"\n".join(lines))
    print_success(f"  Shuffled wordlist: {tmp.name} ({len(lines):,} linhas)")
    return tmp


# ---------------------------------------------------------------------------
# Backend runners
# ---------------------------------------------------------------------------

