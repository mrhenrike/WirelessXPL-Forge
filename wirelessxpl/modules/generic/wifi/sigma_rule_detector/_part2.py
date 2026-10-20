def match_rules(
    rules: list[dict[str, Any]],
    log_entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Run Sigma rules against log entries and return matches.

    Args:
        rules: List of parsed Sigma rule dicts.
        log_entries: List of log record dicts (field: value).

    Returns:
        List of match dicts: {rule, entry, entry_index}.
    """
    matches = []
    for idx, entry in enumerate(log_entries):
        for rule in rules:
            detection = rule.get("detection", {})
            if _evaluate_detection(entry, detection):
                matches.append({
                    "rule_title": rule.get("title", "Unknown"),
                    "rule_id": rule.get("id", ""),
                    "severity": rule.get("level", "medium"),
                    "tags": rule.get("tags", []),
                    "entry_index": idx,
                    "matched_entry": entry,
                    "source_path": rule.get("_source_path", ""),
                })
    return matches


def parse_syslog_line(line: str) -> dict[str, Any] | None:
    """Parse a basic syslog/firewall log line into a field dict.

    Handles common patterns:
        - Plain syslog: DATE HOST PROGRAM[PID]: MSG
        - Cisco ACL: dst_port, dst_ip, src_ip, action keyword extraction
        - Key=value pairs embedded in message

    Returns:
        Dict of parsed fields or None if line is empty.
    """
    line = line.strip()
    if not line:
        return None

    entry: dict[str, Any] = {"_raw": line}

    # Extract key=value pairs
    for m in re.finditer(r'(\w[\w_-]*)=([^\s,;"]+)', line):
        entry[m.group(1).lower()] = _coerce(m.group(2))

    # Common port pattern: port 80, :80, dport=80
    m = re.search(r'\b(?:dport|dst_port|d?port)\s*[=:]\s*(\d+)', line, re.IGNORECASE)
    if m and "dst_port" not in entry:
        entry["dst_port"] = int(m.group(1))

    # Action keyword extraction (permit/deny/allow/block/forward/accept)
    m = re.search(r'\b(permit|deny|allow|block|forward|accept|drop|reject)\b', line, re.IGNORECASE)
    if m and "action" not in entry:
        entry["action"] = m.group(1).lower()

    # Protocol extraction
    m = re.search(r'\b(tcp|udp|icmp|http|ftp|telnet|ssh|smtp)\b', line, re.IGNORECASE)
    if m and "protocol" not in entry:
        entry["protocol"] = m.group(1).lower()

    return entry


class Exploit(Exploit):
    """Native Sigma rule detector for network/firewall log analysis.

    Applies Sigma detection rules from the sigma submodule against
    structured or raw syslog/firewall log files. No external Sigma tooling
    or SIEM required - pure Python matching engine.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    """

    __info__ = {
        "name": "Sigma Rule Detector (Network/Firewall)",
        "description": (
            "Parses Sigma rules from submodules/FraudDetection/sigma/rules/network/ "
            "and matches them against log files in syslog, key=value, or JSON format. "
            "No external sigma-cli or SIEM required."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "submodules/FraudDetection/sigma/rules/network/",
            "https://github.com/SigmaHQ/sigma",
        ),
        "devices": ("wifi", "network"),
        "platform": ("linux", "macos", "windows"),
    }

    log_file = OptString("", "Path to log file to analyse (syslog, JSON lines, or key=value)")
    rules_dir = OptString("", "Sigma rules directory (auto-discovers sigma submodule if empty)")
    min_severity = OptString("low", "Minimum severity to report: low/medium/high/critical")
    max_lines = OptInteger(50_000, "Maximum log lines to read")
    dry_run = OptBool(False, "Load and count rules without matching")

    def _find_sigma_rules_dir(self) -> Path | None:
        """Auto-discover the Sigma network rules directory."""
        # Common locations relative to WXF package root
        wxf_root = Path(__file__).resolve().parents[5]
        candidates = [
            wxf_root / "FraudDetection" / "sigma" / "rules" / "network",
            wxf_root.parent / "FraudDetection" / "sigma" / "rules" / "network",
        ]
        for c in candidates:
            if c.is_dir():
                return c
        return None

    def check(self) -> bool:
        """Verify log file and rules directory exist."""
        log = str(self.log_file).strip()
        if not log:
            logger.error("Set log_file to a log file path.")
            return False
        if not Path(log).exists():
            logger.error("Log file not found: %s", log)
            return False

        rules_dir = str(self.rules_dir).strip()
        if rules_dir and not Path(rules_dir).is_dir():
            logger.error("Rules directory not found: %s", rules_dir)
            return False

        return True

    def run(self) -> None:
        """Match Sigma rules against the provided log file."""
        from wirelessxpl.modules.generic.wifi._disclaimer import require_authorised_lab
        require_authorised_lab(self)

        # Resolve rules directory
        rules_dir = str(self.rules_dir).strip()
        if not rules_dir:
            found = self._find_sigma_rules_dir()
            if found:
                rules_dir = str(found)
                logger.info("Auto-discovered Sigma rules at: %s", rules_dir)
            else:
                logger.error(
                    "Sigma rules not found. Set rules_dir or initialise: "
                    "git submodule update --init submodules/FraudDetection/sigma"
                )
                return

        rules = load_sigma_rules(rules_dir)
        if not rules:
            logger.error("No Sigma rules loaded from: %s", rules_dir)
            return

        logger.info("Loaded %d Sigma rules", len(rules))

        if self.dry_run:
            print(f"[dry-run] Loaded {len(rules)} rules from {rules_dir}")
            for r in sorted(rules, key=lambda x: x.get("title", "")):
                print(f"  [{r.get('level','?')}] {r.get('title','?')}")
            return

        # Read and parse log file
        log_path = Path(str(self.log_file).strip())
        max_l = int(self.max_lines)
        entries: list[dict[str, Any]] = []
        raw_lines: list[str] = []

        with open(log_path, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= max_l:
                    break
                line = line.rstrip()
                if not line:
                    continue
                raw_lines.append(line)

                # Try JSON first, then syslog
                try:
                    entry = json.loads(line)
                    if isinstance(entry, dict):
                        entries.append(entry)
                        continue
                except ValueError:
                    pass

                parsed = parse_syslog_line(line)
                if parsed:
                    entries.append(parsed)

        logger.info("Parsed %d log entries from %d lines", len(entries), len(raw_lines))

        # Run matching
        min_sev = _SEV_ORDER.get(str(self.min_severity).lower(), 1)
        matches = match_rules(rules, entries)

        # Filter by severity
        filtered = [
            m for m in matches
            if _SEV_ORDER.get(m["severity"].lower(), 1) >= min_sev
        ]
        filtered.sort(key=lambda m: _SEV_ORDER.get(m["severity"].lower(), 0), reverse=True)

        # Output
        print()
        print("=" * 64)
        print(f"  Sigma Rule Detector - {log_path.name}")
        print(f"  Rules loaded: {len(rules)}  Log entries: {len(entries)}")
        print("=" * 64)
        print()

        if not filtered:
            print("[+] No rule matches found above configured threshold.")
            return

        print(f"Matches ({len(filtered)}):")
        print("-" * 64)
        for m in filtered:
            print(f"  [{m['severity'].upper()}] {m['rule_title']}")
            if m.get("tags"):
                print(f"         Tags: {', '.join(m['tags'][:4])}")
            print(f"         Line #{m['entry_index']}: {str(m['matched_entry'].get('_raw', ''))[:120]}")
            print()

        counts = collections.Counter(m["severity"] for m in filtered)
        parts = [f"{sev.upper()}={counts[sev]}" for sev in ["critical", "high", "medium", "low"] if sev in counts]
        print(f"Summary: {', '.join(parts)}")
        print()


import collections
