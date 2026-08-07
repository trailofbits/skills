# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Merge SARIF files into a single consolidated output.

Usage:
    uv run merge_sarif.py RAW_DIR OUTPUT_FILE [--important] [--scans scans.json]

Reads *.sarif files from RAW_DIR (e.g., $OUTPUT_DIR/raw), produces
OUTPUT_FILE (e.g., $OUTPUT_DIR/results/results.sarif) containing all
findings merged and deduplicated.

--scans names the scans.json run-scans.sh wrote, and drops the SARIF files
belonging to scans recorded under .failed. Those files exist because a scan
that died part-way may still have written one, so without this a single dead
scan takes the whole run's deliverable with it: under --important its output
has no post-filter beside it, and that is an error rather than an empty
filter. Pass it whenever scans.json exists.

--important restricts the merged output to the findings that survived the
important-only post-filter. That filter reads semgrep's JSON metadata
(category/confidence/impact), which SARIF does not carry, so it cannot be
re-run against SARIF. Finding identity can be matched across the two formats
though, and that is what this flag does. Without it the merged SARIF in
important-only mode keeps every finding the mode exists to exclude.

The merge is pure Python and shells out to nothing. It used to try
`npx @microsoft/sarif-multitool` first, which made the output depend on
whether that package happened to be in the npx cache: the two backends do not
agree. Only this one dedups results on (ruleId, uri, startLine), which is the
identity --important matches against and the reason the report is told to
count from the merged file rather than sum per-scan totals. Multitool also
normalizes artifactLocation.uri, which would leave --important matching
nothing and blaming a semgrep format change that never happened.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

Key = tuple[str, str, int]


def sarif_key(result: dict) -> Key:
    """Identity of one SARIF result: rule, file, line.

    The same triple in semgrep's JSON is (check_id, path, start.line), verified
    field-for-field against semgrep output. Both the merge dedup and the
    --important filter read it from here so the two cannot drift apart. The
    filter is only correct while its keys are the keys the merge produced.
    """
    locations = result.get("locations", [])
    uri = ""
    start_line = 0
    if locations:
        phys = locations[0].get("physicalLocation", {})
        uri = phys.get("artifactLocation", {}).get("uri", "")
        start_line = phys.get("region", {}).get("startLine", 0)
    return (result.get("ruleId", ""), uri, start_line)


def json_key(result: dict) -> Key:
    """The same identity read out of a semgrep JSON result."""
    return (
        result.get("check_id", ""),
        result.get("path", ""),
        result.get("start", {}).get("line", 0),
    )


def failed_sarifs(scans_json: Path) -> set[Path]:
    """Resolved paths of the SARIF files belonging to scans that did not succeed.

    run-scans.sh records a failed scan carrying the same paths a success does, because a scan
    that crashed part-way may still have written a file. What it wrote is not a scan result:
    it is whatever semgrep produced before it stopped. Those files must not be held to the
    post-filter requirement, or one dead process denies every healthy scan a deliverable.
    """
    data = json.loads(scans_json.read_text())
    failed = data.get("failed")
    if not isinstance(failed, list):
        raise ValueError(
            f"{scans_json} has no .failed array; it is not a scans.json written by run-scans.sh"
        )
    return {
        Path(entry["sarif"]).resolve()
        for entry in failed
        if isinstance(entry, dict) and entry.get("sarif")
    }


def surviving_keys(sarif_files: list[Path]) -> set[Key]:
    """Keys kept by the important-only post-filter, one *-important.json per SARIF.

    Derived from the SARIF files going into the merge rather than by globbing
    *-important.json, so a post-filter that ran on only some of them is an error
    here instead of a merged SARIF quietly missing whole rulesets.

    Raises ValueError when a filter file is missing or unreadable. Filtering
    against a partial key set drops real findings from the primary deliverable
    and there is nothing downstream that could notice. That is stricter than
    the merge itself, which warns and skips a SARIF file it cannot parse: an
    unparseable SARIF contributes no findings either way, while an unparseable
    filter file silently removes findings the SARIF does contain.
    """
    keys: set[Key] = set()
    missing: list[str] = []
    for sarif_file in sarif_files:
        filtered = sarif_file.with_name(f"{sarif_file.stem}-important.json")
        if not filtered.is_file():
            missing.append(filtered.name)
            continue
        try:
            data = json.loads(filtered.read_text())
        except json.JSONDecodeError as e:
            raise ValueError(f"{filtered} is not valid JSON: {e}") from e
        results = data.get("results")
        if not isinstance(results, list):
            raise ValueError(
                f"{filtered} has no .results array; it is not a filtered semgrep result file"
            )
        for result in results:
            keys.add(json_key(result))

    if missing:
        raise ValueError(
            f"{len(missing)} of {len(sarif_files)} scans have no post-filtered JSON "
            f"({', '.join(sorted(missing)[:5])}"
            f"{', ...' if len(missing) > 5 else ''}). Run the important-only post-filter "
            "over every file in the raw directory first."
        )
    return keys


def filter_to_keys(merged: dict, keys: set[Key]) -> tuple[int, int]:
    """Keep only results whose identity survived the post-filter. Returns (kept, dropped)."""
    kept = 0
    dropped = 0
    for run in merged.get("runs", []):
        keeping = []
        for result in run.get("results", []):
            if sarif_key(result) in keys:
                keeping.append(result)
                kept += 1
            else:
                dropped += 1
        run["results"] = keeping
    return kept, dropped


def merge_sarif_pure_python(sarif_files: list[Path]) -> tuple[dict, list[str]]:
    """Merge every SARIF into one run, deduplicating results by sarif_key.

    Returns (merged, unparseable). The unparseable list is returned rather than just
    warned about: a scan can exit 0, write a valid .json that puts it in .scans with a
    finding count, and still leave a truncated .sarif. Dropping that file silently makes
    results.sarif short by exactly those findings with nothing anywhere pointing at it.

    The dedup is what makes the merged total meaningful: one finding flagged by two
    rulesets is one row here and two in a sum of per-scan counts.
    """
    merged = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [],
    }

    seen_rules: dict[str, dict] = {}
    all_results: list[dict] = []
    seen_results: set[Key] = set()
    tool_info: dict | None = None
    skipped_files: list[str] = []

    for sarif_file in sorted(sarif_files):
        try:
            data = json.loads(sarif_file.read_text())
        except json.JSONDecodeError as e:
            print(f"Warning: Failed to parse {sarif_file}: {e}", file=sys.stderr)
            skipped_files.append(str(sarif_file))
            continue

        for run in data.get("runs", []):
            if tool_info is None and run.get("tool"):
                tool_info = run["tool"]

            driver = run.get("tool", {}).get("driver", {})
            for rule in driver.get("rules", []):
                rule_id = rule.get("id", "")
                if rule_id and rule_id not in seen_rules:
                    seen_rules[rule_id] = rule

            for result in run.get("results", []):
                dedup_key = sarif_key(result)
                if dedup_key in seen_results:
                    continue
                seen_results.add(dedup_key)
                all_results.append(result)

    if all_results:
        merged_run = {
            "tool": tool_info or {"driver": {"name": "semgrep", "rules": []}},
            "results": all_results,
        }
        merged_run["tool"]["driver"]["rules"] = list(seen_rules.values())
        merged["runs"].append(merged_run)

    return merged, skipped_files


def main() -> int:
    argv = sys.argv[1:]
    important = "--important" in argv
    argv = [a for a in argv if a != "--important"]

    scans_json: Path | None = None
    if "--scans" in argv:
        i = argv.index("--scans")
        if i + 1 >= len(argv):
            print("--scans needs the path to scans.json", file=sys.stderr)
            return 1
        scans_json = Path(argv[i + 1])
        del argv[i : i + 2]

    if len(argv) != 2:
        print(
            f"Usage: {sys.argv[0]} RAW_DIR OUTPUT_FILE [--important] [--scans scans.json]",
            file=sys.stderr,
        )
        return 1

    raw_dir = Path(argv[0])
    output_file = Path(argv[1])

    if not raw_dir.is_dir():
        print(f"Error: {raw_dir} is not a directory", file=sys.stderr)
        return 1

    # Collect SARIF files from raw directory only
    sarif_files = sorted(raw_dir.glob("*.sarif"))
    print(f"Found {len(sarif_files)} SARIF files to merge in {raw_dir}")

    if not sarif_files:
        print("No SARIF files found, nothing to merge", file=sys.stderr)
        return 1

    # Before the post-filter requirement below, so a dead scan is dropped rather than held to it.
    if scans_json is not None:
        try:
            excluded = failed_sarifs(scans_json)
        except (OSError, json.JSONDecodeError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        kept = [p for p in sarif_files if p.resolve() not in excluded]
        if len(kept) != len(sarif_files):
            names = sorted(p.name for p in sarif_files if p.resolve() in excluded)
            print(
                f"excluding {len(sarif_files) - len(kept)} SARIF file(s) from failed scans: "
                f"{', '.join(names)}"
            )
        sarif_files = kept
        # Every scan failed. Writing an empty merge here would report a clean run over nothing.
        if not sarif_files:
            print(
                f"Error: every scan in {scans_json} failed, so there is nothing to merge",
                file=sys.stderr,
            )
            return 1

    # Resolved before the merge, not after: a post-filter that did not run is a broken run,
    # and finding that out first costs nothing while finding it out afterwards means either
    # a wrong results.sarif on disk or a merge thrown away.
    keys: set[Key] = set()
    if important:
        try:
            keys = surviving_keys(sarif_files)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        print(f"important-only: {len(keys)} findings survived the post-filter")

    # Ensure output directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    merged, unparseable = merge_sarif_pure_python(sarif_files)
    if unparseable:
        # stdout, alongside the --scans exclusions, because that is the stream the Report phase
        # reads and it must give these their own section. On stderr this was invisible to the
        # summary: the scan sits in .scans as a success carrying its finding count, so nothing
        # in scans.json or results.sarif shows that those findings went missing.
        names = ", ".join(sorted(Path(p).name for p in unparseable))
        print(
            f"unparseable: {len(unparseable)} of {len(sarif_files)} SARIF files could not be "
            f"parsed and are missing from the merge: {names}"
        )
    # Nothing was read at all, so "0 findings" would be a clean run rather than a broken one.
    if unparseable and len(unparseable) == len(sarif_files):
        print(
            f"Error: none of the {len(sarif_files)} SARIF files could be parsed; "
            "there is nothing to merge",
            file=sys.stderr,
        )
        return 1

    if important:
        before = sum(len(run.get("results", [])) for run in merged.get("runs", []))
        kept, dropped = filter_to_keys(merged, keys)
        print(f"important-only: kept {kept} of {before} merged findings, dropped {dropped}")
        # Unreachable while the two formats agree: every key came from the *-important.json
        # sibling of a SARIF in this merge, so at least one must match something. Reaching it
        # means sarif_key and json_key are no longer reading one identity out of two shapes —
        # semgrep changed an output format — and every finding was dropped for that reason
        # rather than by the filter. Writing anyway ships an empty results.sarif that reads as
        # a clean important-only run, which is the failure this whole flag exists to prevent.
        # Guarded on keys: a filter that legitimately kept nothing is a real zero, not drift.
        if keys and before and not kept:
            print(
                f"Error: the post-filter kept {len(keys)} findings and the merge read {before}, "
                "but none of them matched. The JSON and SARIF records of a finding no longer "
                "reduce to the same (rule, file, line), so refusing to write a zero-finding "
                f"{output_file}. Compare a raw *.json against its *.sarif in {raw_dir}.",
                file=sys.stderr,
            )
            return 1

    result_count = sum(len(run.get("results", [])) for run in merged.get("runs", []))
    print(f"Merged SARIF contains {result_count} findings")

    # Write output
    output_file.write_text(json.dumps(merged, indent=2))
    print(f"Written to {output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
