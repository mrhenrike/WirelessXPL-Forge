#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""Native Sigma rule detector for wireless/network log analysis.

Parses a subset of the Sigma rule format (YAML) and applies matching logic
to log entries in common formats. Designed for passive detection of network
anomalies relevant to wireless security contexts.

Supported Sigma detection conditions: simple field matching (selection/filter),
  list values (any match), all/1of/any aggregations.

Sigma rules sourced from:
    submodules/FraudDetection/sigma/rules/network/

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""


import glob
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)

__version__ = "1.0.0"

# Severity ordering for sorting
_SEV_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _yaml_load_simple(text: str) -> dict[str, Any]:
    """Minimal YAML-subset parser for Sigma rules.

    Handles: scalar key:value, nested dicts (indented), lists (- item),
    multi-line scalars (|). Does NOT handle anchors, tags, flow syntax,
    or complex Sigma aggregate conditions.

    This avoids a PyYAML dependency in the WXF wheel.

    Args:
        text: Raw YAML text of a Sigma rule.

    Returns:
        Parsed dict, best-effort. Empty dict on parse failure.
    """
    # Prefer PyYAML if available (more robust), fall back to manual parser
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except ImportError:
        pass

    result: dict[str, Any] = {}
    try:
        _yaml_parse_block(text.splitlines(), result)
    except Exception as exc:
        logger.debug("YAML parse error: %s", exc)
    return result


def _yaml_parse_block(lines: list[str], container: dict[str, Any], base_indent: int = 0) -> None:
    """Recursive block parser for YAML subset used by Sigma rules."""
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        i += 1

        if not stripped or stripped.startswith("#"):
            continue

        indent = len(raw) - len(raw.lstrip(" "))
        if indent < base_indent:
            break

        # Skip lines at deeper indent than expected at top-level (handled by recursion)
        if indent > base_indent and not container:
            continue

        if ":" in stripped and not stripped.startswith("-"):
            sep = stripped.index(":")
            key = stripped[:sep].strip()
            value_raw = stripped[sep + 1:].strip()

            if value_raw == "|":
                # Multiline block scalar - collect until dedent
                ml_lines = []
                while i < len(lines):
                    nxt = lines[i]
                    nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                    if nxt.strip() and nxt_indent <= indent:
                        break
                    ml_lines.append(nxt.strip())
                    i += 1
                container[key] = " ".join(ml_lines).strip()

            elif value_raw == "" or value_raw == ">":
                # Could be a nested dict OR a list - peek ahead
                child_lines = []
                while i < len(lines):
                    nxt = lines[i]
                    nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                    if nxt.strip() and nxt_indent <= indent:
                        break
                    child_lines.append(nxt)
                    i += 1

                # Determine: list or dict?
                first_content = next((l.strip() for l in child_lines if l.strip() and not l.strip().startswith("#")), "")
                if first_content.startswith("- "):
                    # It's a list
                    lst: list[Any] = []
                    for cl in child_lines:
                        cs = cl.strip()
                        if not cs or cs.startswith("#"):
                            continue
                        if cs.startswith("- "):
                            lst.append(_coerce(cs[2:].strip()))
                    container[key] = lst
                else:
                    # It's a nested dict
                    nested: dict[str, Any] = {}
                    container[key] = nested
                    _yaml_parse_block(child_lines, nested, indent + 1)

            elif value_raw.startswith("[") and value_raw.endswith("]"):
                items = [_coerce(v.strip().strip("'\"")) for v in value_raw[1:-1].split(",") if v.strip()]
                container[key] = items
            else:
                container[key] = _coerce(value_raw)


def _coerce(value: str) -> Any:
    """Coerce a YAML scalar string to int/bool/None/str."""
    if value in ("true", "True", "yes"):
        return True
    if value in ("false", "False", "no"):
        return False
    if value in ("null", "~", ""):
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value.strip("'\"")


def load_sigma_rules(rules_dir: str) -> list[dict[str, Any]]:
    """Load all Sigma rules from a directory tree.

    Args:
        rules_dir: Root directory containing .yml Sigma rule files.

    Returns:
        List of parsed rule dicts with only non-empty detection sections.
    """
    rules = []
    pattern = str(Path(rules_dir) / "**" / "*.yml")
    for path in glob.glob(pattern, recursive=True):
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            rule = _yaml_load_simple(text)
            if not rule.get("title") or not rule.get("detection"):
                continue
            rule["_source_path"] = path
            rules.append(rule)
        except Exception as exc:
            logger.debug("Failed to load rule %s: %s", path, exc)
    return rules


def _match_field(log_entry: dict[str, Any], field: str, expected: Any) -> bool:
    """Check if log_entry[field] matches expected value(s).

    Supports:
        - Exact match (scalar)
        - List match (any item in list)
        - Wildcard (*) patterns
        - Numeric comparison (int)
    """
    actual = log_entry.get(field)
    if actual is None:
        # Try case-insensitive key lookup
        actual = next((v for k, v in log_entry.items() if k.lower() == field.lower()), None)
    if actual is None:
        return False

    if isinstance(expected, list):
        return any(_match_scalar(actual, e) for e in expected)
    return _match_scalar(actual, expected)


def _match_scalar(actual: Any, expected: Any) -> bool:
    """Match a single actual value against a single expected value."""
    if expected is None:
        return actual is None
    # Convert for comparison
    actual_str = str(actual).lower()
    expected_str = str(expected).lower()

    if "*" in expected_str:
        pattern = re.escape(expected_str).replace(r"\*", ".*")
        return bool(re.search(pattern, actual_str))

    return actual_str == expected_str


def _evaluate_selection(log_entry: dict[str, Any], selection: dict[str, Any]) -> bool:
    """Evaluate a single Sigma selection block against a log entry.

    All fields in the selection must match (AND logic within a selection).
    """
    if not isinstance(selection, dict):
        return False
    for field, expected in selection.items():
        if not _match_field(log_entry, field, expected):
            return False
    return True


def _evaluate_detection(log_entry: dict[str, Any], detection: Any) -> bool:
    """Evaluate the full Sigma detection section.

    Handles simple condition strings: 'selection', 'selection and filter',
    'selection or filter', '1 of selection*', 'all of selection*'.

    Args:
        log_entry: Dict of log fields.
        detection: The parsed detection section of a Sigma rule.

    Returns:
        True if the rule matches the log entry.
    """
    if not isinstance(detection, dict):
        return False

    condition = str(detection.get("condition", "selection")).lower().strip()
    named_blocks = {k: v for k, v in detection.items() if k != "condition"}

    def eval_block(name: str) -> bool:
        block = named_blocks.get(name)
        if block is None:
            return False
        if isinstance(block, dict):
            return _evaluate_selection(log_entry, block)
        return False

    def eval_glob_blocks(prefix: str, require_all: bool) -> bool:
        matching = [k for k in named_blocks if k.startswith(prefix)]
        if not matching:
            return False
        results = [eval_block(k) for k in matching]
        return all(results) if require_all else any(results)

    # Handle '1 of selection*' / 'all of selection*'
    if "1 of " in condition:
        prefix = condition.replace("1 of ", "").rstrip("*").strip()
        return eval_glob_blocks(prefix, require_all=False)
    if "all of " in condition:
        prefix = condition.replace("all of ", "").rstrip("*").strip()
        return eval_glob_blocks(prefix, require_all=True)

    # Handle compound conditions: 'selection and 1 of selection_allow*'
    if " and " in condition:
        parts = [p.strip() for p in condition.split(" and ")]
        for part in parts:
            if "1 of " in part:
                prefix = part.replace("1 of ", "").rstrip("*").strip()
                if not eval_glob_blocks(prefix, require_all=False):
                    return False
            elif "not " in part:
                inner = part.replace("not ", "").strip()
                if eval_block(inner):
                    return False
            else:
                if not eval_block(part):
                    return False
        return True

    if " or " in condition:
        parts = [p.strip() for p in condition.split(" or ")]
        return any(eval_block(p) for p in parts)

    if condition.startswith("not "):
        return not eval_block(condition[4:].strip())

    # Simple: just a block name
    return eval_block(condition)


