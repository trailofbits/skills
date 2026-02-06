# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Merge and filter SARIF files to include only triaged true positives.

Usage:
    uv run merge_triaged_sarif.py OUTPUT_DIR

Reads *-triage.json and *.sarif files from OUTPUT_DIR, produces
OUTPUT_DIR/findings-triaged.sarif containing only true positives.

Attempts to use SARIF Multitool for merging if available, falls back to
pure Python implementation.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def load_true_positives(triage_dir: Path) -> set[tuple[str, str, int]]:
    """Load true positives from all triage files as (rule_id, file, line) tuples."""
    true_positives: set[tuple[str, str, int]] = set()

    for triage_file in triage_dir.glob("*-triage.json"):
        try:
            data = json.loads(triage_file.read_text())
        except json.JSONDecodeError as e:
            print(f"Warning: Failed to parse {triage_file}: {e}", file=sys.stderr)
            continue

        for tp in data.get("true_positives", []):
            rule = tp.get("rule", "")
            file_path = tp.get("file", "")
            line = tp.get("line", 0)
            if rule and file_path and line:
                true_positives.add((rule, file_path, line))

    return true_positives


def extract_result_key(result: dict) -> tuple[str, str, int] | None:
    """Extract (rule_id, file, line) from a SARIF result."""
    rule_id = result.get("ruleId", "")
    locations = result.get("locations", [])
    if not locations:
        return None

    phys_loc = locations[0].get("physicalLocation", {})
    artifact_loc = phys_loc.get("artifactLocation", {})
    uri = artifact_loc.get("uri", "")
    region = phys_loc.get("region", {})
    line = region.get("startLine", 0)

    if not (rule_id and uri and line):
        return None

    return (rule_id, uri, line)


def normalize_file_path(uri: str) -> str:
    """Normalize file path for matching (handle relative vs absolute)."""
    if uri.startswith("file://"):
        uri = uri[7:]
    return uri.lstrip("./")


def has_sarif_multitool() -> bool:
    """Check if SARIF Multitool is pre-installed via npx."""
    if not shutil.which("npx"):
        return False
    try:
        result = subprocess.run(
            ["npx", "--no-install", "@microsoft/sarif-multitool", "--version"],
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def merge_with_multitool(sarif_dir: Path) -> dict | None:
    """Use SARIF Multitool to merge SARIF files. Returns merged SARIF or None."""
    sarif_files = list(sarif_dir.glob("*.sarif"))
    if not sarif_files:
        return None

    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        cmd = [
            "npx",
            "--no-install",
            "@microsoft/sarif-multitool",
            "merge",
            *[str(f) for f in sarif_files],
            "--output-file",
            str(tmp_path),
            "--force",
        ]
        result = subprocess.run(cmd, capture_output=True, timeout=120)
        if result.returncode != 0:
            print(f"SARIF Multitool merge failed: {result.stderr.decode()}", file=sys.stderr)
            return None

        return json.loads(tmp_path.read_text())
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        print(f"SARIF Multitool error: {e}", file=sys.stderr)
        return None
    finally:
        tmp_path.unlink(missing_ok=True)


def merge_sarif_pure_python(sarif_dir: Path) -> dict:
    """Pure Python SARIF merge (fallback)."""
    merged = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [],
    }

    seen_rules: dict[str, dict] = {}
    all_results: list[dict] = []
    tool_info: dict | None = None

    for sarif_file in sarif_dir.glob("*.sarif"):
        try:
            data = json.loads(sarif_file.read_text())
        except json.JSONDecodeError as e:
            print(f"Warning: Failed to parse {sarif_file}: {e}", file=sys.stderr)
            continue

        for run in data.get("runs", []):
            if tool_info is None and run.get("tool"):
                tool_info = run["tool"]

            driver = run.get("tool", {}).get("driver", {})
            for rule in driver.get("rules", []):
                rule_id = rule.get("id", "")
                if rule_id and rule_id not in seen_rules:
                    seen_rules[rule_id] = rule

            all_results.extend(run.get("results", []))

    if all_results:
        merged_run = {
            "tool": tool_info or {"driver": {"name": "semgrep", "rules": []}},
            "results": all_results,
        }
        merged_run["tool"]["driver"]["rules"] = list(seen_rules.values())
        merged["runs"].append(merged_run)

    return merged


def filter_sarif_by_triage(sarif: dict, true_positives: set[tuple[str, str, int]]) -> dict:
    """Filter SARIF results to include only triaged true positives."""
    normalized_tps: set[tuple[str, str, int]] = set()
    for rule, file_path, line in true_positives:
        normalized_tps.add((rule, normalize_file_path(file_path), line))

    filtered = {
        "version": sarif.get("version", "2.1.0"),
        "$schema": sarif.get("$schema", "https://json.schemastore.org/sarif-2.1.0.json"),
        "runs": [],
    }

    for run in sarif.get("runs", []):
        filtered_results = []
        for result in run.get("results", []):
            key = extract_result_key(result)
            if key is None:
                continue

            rule_id, uri, line = key
            normalized_key = (rule_id, normalize_file_path(uri), line)

            if normalized_key in normalized_tps:
                filtered_results.append(result)

        if filtered_results:
            result_rule_ids = {r.get("ruleId") for r in filtered_results}
            driver = run.get("tool", {}).get("driver", {})
            filtered_rules = [r for r in driver.get("rules", []) if r.get("id") in result_rule_ids]

            filtered_run = {
                "tool": {
                    "driver": {
                        **driver,
                        "rules": filtered_rules,
                    }
                },
                "results": filtered_results,
            }
            filtered["runs"].append(filtered_run)

    return filtered


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} OUTPUT_DIR", file=sys.stderr)
        return 1

    output_dir = Path(sys.argv[1])
    if not output_dir.is_dir():
        print(f"Error: {output_dir} is not a directory", file=sys.stderr)
        return 1

    # Load true positives from triage files
    true_positives = load_true_positives(output_dir)
    if not true_positives:
        print("Warning: No true positives found in triage files", file=sys.stderr)

    print(f"Found {len(true_positives)} true positives from triage")

    # Try SARIF Multitool first, fall back to pure Python
    merged: dict | None = None
    if has_sarif_multitool():
        print("Using SARIF Multitool for merge...")
        merged = merge_with_multitool(output_dir)
        if merged:
            print("SARIF Multitool merge successful")

    if merged is None:
        print("Using pure Python merge (SARIF Multitool not available or failed)")
        merged = merge_sarif_pure_python(output_dir)

    # Filter to true positives only
    filtered = filter_sarif_by_triage(merged, true_positives)

    result_count = sum(len(run.get("results", [])) for run in filtered.get("runs", []))
    print(f"Filtered SARIF contains {result_count} true positives")

    # Write output
    output_file = output_dir / "findings-triaged.sarif"
    output_file.write_text(json.dumps(filtered, indent=2))
    print(f"Written to {output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
