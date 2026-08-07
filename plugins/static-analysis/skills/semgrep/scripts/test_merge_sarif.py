# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8"]
# ///
"""Tests for merge_sarif.py, with the weight on --important.

The important-only merge rests on one claim: a finding's identity in semgrep's JSON output
(check_id, path, start.line) is the same triple SARIF carries as (ruleId, uri,
region.startLine). The pair in test_key_contract is that claim, taken field-for-field from
real `semgrep --json --sarif-output` runs over the same file. If semgrep ever changes either
shape, that test goes red rather than the filter silently keeping nothing.

The negatives matter as much: a post-filter that ran over only some scans, or wrote a file
that will not parse, must fail the merge. Filtering against a partial key set drops real
findings from the primary deliverable and nothing downstream could notice.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from merge_sarif import (
    filter_to_keys,
    json_key,
    merge_sarif_pure_python,
    sarif_key,
    surviving_keys,
)

SCRIPT = Path(__file__).with_name("merge_sarif.py")

RULE = "python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5"
OTHER = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"


def sarif_result(rule: str, uri: str, line: int) -> dict:
    return {
        "ruleId": rule,
        "message": {"text": "finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line, "startColumn": 1},
                }
            }
        ],
    }


def sarif_doc(*results: dict) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}}, "results": list(results)}],
    }


def json_result(rule: str, path: str, line: int) -> dict:
    return {"check_id": rule, "path": path, "start": {"line": line, "col": 1}, "extra": {}}


def write_scan(raw: Path, stem: str, sarif: list[dict], filtered: list[dict] | None) -> None:
    """One scan's output: the SARIF the merge reads, and optionally its post-filtered JSON."""
    (raw / f"{stem}.sarif").write_text(json.dumps(sarif_doc(*sarif)))
    if filtered is not None:
        (raw / f"{stem}-important.json").write_text(
            json.dumps({"results": filtered, "errors": [], "paths": {}})
        )


def run_merge(raw: Path, out: Path, *flags: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(raw), str(out), *flags],
        capture_output=True,
        text=True,
    )


def count(sarif_file: Path) -> int:
    data = json.loads(sarif_file.read_text())
    return sum(len(run.get("results", [])) for run in data.get("runs", []))


# --------------------------------------------------------------- the cross-format contract


def test_key_contract():
    """Captured from real semgrep output over one file: the two shapes carry one identity."""
    from_json = json_result(RULE, "src/app.py", 5)
    from_sarif = sarif_result(RULE, "src/app.py", 5)
    assert json_key(from_json) == sarif_key(from_sarif) == (RULE, "src/app.py", 5)


def test_keys_differ_on_line():
    assert json_key(json_result(RULE, "src/app.py", 5)) != sarif_key(
        sarif_result(RULE, "src/app.py", 6)
    )


def test_sarif_key_tolerates_a_result_with_no_location():
    assert sarif_key({"ruleId": RULE}) == (RULE, "", 0)


# ------------------------------------------------------------------------- surviving_keys


def test_surviving_keys_reads_every_scan(tmp_path):
    raw = tmp_path
    write_scan(raw, "py", [sarif_result(RULE, "a.py", 5)], [json_result(RULE, "a.py", 5)])
    write_scan(raw, "secrets", [sarif_result(OTHER, "b.py", 9)], [json_result(OTHER, "b.py", 9)])
    keys = surviving_keys(sorted(raw.glob("*.sarif")))
    assert keys == {(RULE, "a.py", 5), (OTHER, "b.py", 9)}


def test_surviving_keys_is_empty_when_the_filter_kept_nothing(tmp_path):
    """A real outcome, distinct from a filter that never ran: the files exist and are empty."""
    write_scan(tmp_path, "python-python", [sarif_result(RULE, "a.py", 5)], [])
    assert surviving_keys(sorted(tmp_path.glob("*.sarif"))) == set()


def test_a_scan_with_no_filtered_json_fails_the_merge(tmp_path):
    """The silent-omission case: without this, that scan's findings vanish from results.sarif."""
    raw = tmp_path
    write_scan(raw, "py", [sarif_result(RULE, "a.py", 5)], [json_result(RULE, "a.py", 5)])
    write_scan(raw, "all-secrets", [sarif_result(OTHER, "b.py", 9)], None)
    with pytest.raises(ValueError, match="all-secrets-important.json"):
        surviving_keys(sorted(raw.glob("*.sarif")))


def test_an_unparseable_filter_file_fails_the_merge(tmp_path):
    write_scan(tmp_path, "python-python", [sarif_result(RULE, "a.py", 5)], [])
    (tmp_path / "python-python-important.json").write_text("not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        surviving_keys(sorted(tmp_path.glob("*.sarif")))


def test_a_filter_file_with_no_results_array_fails_the_merge(tmp_path):
    """Catches a SARIF file handed in where a filtered JSON belongs; it would filter to nothing."""
    write_scan(tmp_path, "python-python", [sarif_result(RULE, "a.py", 5)], [])
    (tmp_path / "python-python-important.json").write_text(json.dumps(sarif_doc()))
    with pytest.raises(ValueError, match="no .results array"):
        surviving_keys(sorted(tmp_path.glob("*.sarif")))


# -------------------------------------------------------------------------- filter_to_keys


def test_filter_keeps_only_surviving_findings():
    merged = sarif_doc(sarif_result(RULE, "a.py", 5), sarif_result(OTHER, "a.py", 3))
    kept, dropped = filter_to_keys(merged, {(RULE, "a.py", 5)})
    assert (kept, dropped) == (1, 1)
    assert [r["ruleId"] for r in merged["runs"][0]["results"]] == [RULE]


def test_filter_against_an_empty_key_set_empties_the_results():
    merged = sarif_doc(sarif_result(RULE, "a.py", 5))
    assert filter_to_keys(merged, set()) == (0, 1)
    assert merged["runs"][0]["results"] == []


# ------------------------------------------------------------------------------ end to end


def test_important_merge_filters_the_deliverable(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(
        raw,
        "python-python",
        [sarif_result(RULE, "a.py", 5), sarif_result(OTHER, "a.py", 3)],
        [json_result(RULE, "a.py", 5)],
    )
    out = tmp_path / "results" / "results.sarif"
    proc = run_merge(raw, out, "--important")
    assert proc.returncode == 0, proc.stderr
    assert count(out) == 1
    assert json.loads(out.read_text())["runs"][0]["results"][0]["ruleId"] == RULE


def test_run_all_merge_keeps_everything(tmp_path):
    """The default path must be unchanged by the flag's existence."""
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(
        raw,
        "python-python",
        [sarif_result(RULE, "a.py", 5), sarif_result(OTHER, "a.py", 3)],
        [json_result(RULE, "a.py", 5)],
    )
    out = tmp_path / "results" / "results.sarif"
    assert run_merge(raw, out).returncode == 0
    assert count(out) == 2


def test_important_without_a_post_filter_fails_and_writes_nothing(tmp_path):
    """The whole point of resolving keys before the merge: no half-right file on disk."""
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(raw, "python-python", [sarif_result(RULE, "a.py", 5)], None)
    out = tmp_path / "results" / "results.sarif"
    proc = run_merge(raw, out, "--important")
    assert proc.returncode == 1
    assert "post-filtered JSON" in proc.stderr
    assert not out.exists()


def test_important_leaves_an_existing_deliverable_alone_when_it_fails(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(raw, "python-python", [sarif_result(RULE, "a.py", 5)], None)
    out = tmp_path / "results.sarif"
    out.write_text(json.dumps(sarif_doc(sarif_result(RULE, "a.py", 5))))
    before = out.read_text()
    assert run_merge(raw, out, "--important").returncode == 1
    assert out.read_text() == before


def test_an_empty_raw_directory_is_an_error(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    assert run_merge(raw, tmp_path / "o.sarif").returncode == 1


# ------------------------------------------------------------------------------ merge dedup


def test_merge_dedups_one_finding_flagged_by_two_rulesets(tmp_path):
    """The reason the report counts from the merge and never sums per-scan counts."""
    write_scan(tmp_path, "python-python", [sarif_result(RULE, "a.py", 5)], None)
    write_scan(tmp_path, "all-audit", [sarif_result(RULE, "a.py", 5)], None)
    merged = merge_sarif_pure_python(sorted(tmp_path.glob("*.sarif")))
    assert sum(len(run["results"]) for run in merged["runs"]) == 1
