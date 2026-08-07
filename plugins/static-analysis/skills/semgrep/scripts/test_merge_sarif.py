# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8"]
# ///
"""Tests for merge_sarif.py, with the weight on --important.

The important-only merge rests on one claim: a finding's identity in semgrep's JSON output
(check_id, path, start.line) is the same triple SARIF carries as (ruleId, uri,
region.startLine). test_key_contract pins the field names this script reads, but builds both
halves itself, so only test_key_contract_against_real_semgrep can notice semgrep changing
either shape. That one runs semgrep and compares the two records of one real finding.

The negatives matter as much: a post-filter that ran over only some scans, or wrote a file
that will not parse, must fail the merge. Filtering against a partial key set drops real
findings from the primary deliverable and nothing downstream could notice. The exception is a
scan recorded under .failed in scans.json, whose output is whatever a dying process wrote:
--scans drops those, so one crashed scan cannot deny every healthy scan a deliverable.
"""

from __future__ import annotations

import json
import shutil
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
    """The shapes this script expects, pinned.

    Both halves are built by this file from one literal path, so this fixes the field names
    `sarif_key` and `json_key` read and nothing more. It cannot notice semgrep changing either
    output — test_key_contract_against_real_semgrep below is the one that can.
    """
    from_json = json_result(RULE, "src/app.py", 5)
    from_sarif = sarif_result(RULE, "src/app.py", 5)
    assert json_key(from_json) == sarif_key(from_sarif) == (RULE, "src/app.py", 5)


MD5_RULE = """\
rules:
  - id: insecure-md5
    pattern: hashlib.md5(...)
    message: md5 is insecure
    languages: [python]
    severity: WARNING
"""


def semgrep_bin() -> str:
    """Fail rather than skip, the same reason run_workflow_tests.sh fails without node.

    A skip here reads as a clean run while the only check that could catch cross-format drift
    silently did not execute. semgrep is this plugin's own dependency and CI installs it.
    """
    found = shutil.which("semgrep")
    if not found:
        raise AssertionError(
            "semgrep is not installed, so the JSON/SARIF contract went unverified. "
            "Install it (pip install semgrep) — this suite must not pass without it."
        )
    return found


@pytest.mark.parametrize("absolute", [True, False])
def test_key_contract_against_real_semgrep(tmp_path, absolute):
    """The contract read out of semgrep itself, over one real finding.

    --important rests entirely on the claim that (check_id, path, start.line) in the JSON is
    (ruleId, uri, region.startLine) in the SARIF. Only this test can see that claim break: if
    semgrep changes either shape, the keys stop matching, every finding is dropped and the
    deliverable goes empty. run-scans.sh always passes an absolute target; the relative case is
    parametrized because a path shape is exactly where the two formats would diverge first.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(
        "import hashlib\ndef f(x):\n    return hashlib.md5(x).hexdigest()\n"
    )
    rule = tmp_path / "md5.yaml"
    rule.write_text(MD5_RULE)
    json_out = tmp_path / "out.json"
    sarif_out = tmp_path / "out.sarif"

    proc = subprocess.run(
        [
            semgrep_bin(),
            "--metrics=off",
            "--config",
            str(rule),
            "--json",
            "-o",
            str(json_out),
            f"--sarif-output={sarif_out}",
            str(src) if absolute else "src",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert json_out.is_file(), f"semgrep wrote no JSON: {proc.stderr}"
    assert sarif_out.is_file(), f"semgrep wrote no SARIF: {proc.stderr}"

    json_results = json.loads(json_out.read_text())["results"]
    sarif_results = json.loads(sarif_out.read_text())["runs"][0]["results"]
    assert len(json_results) == 1, f"expected one JSON finding, got {len(json_results)}"
    assert len(sarif_results) == 1, f"expected one SARIF finding, got {len(sarif_results)}"

    # The whole contract in one line. A mismatch here is the empty-deliverable bug, found at
    # its source rather than as a zero-finding results.sarif nobody can explain.
    assert json_key(json_results[0]) == sarif_key(sarif_results[0])


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


def test_a_total_key_mismatch_fails_the_merge(tmp_path):
    """Cross-format drift, forced: the filter kept a finding no merged result matches.

    Without the guard this writes a zero-finding results.sarif and exits 0, so important-only
    reports a clean run that found nothing while the JSON side has findings.
    """
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(
        raw,
        "python-python",
        [sarif_result(RULE, "src/app.py", 5)],
        [json_result(RULE, "/abs/proj/src/app.py", 5)],
    )
    out = tmp_path / "results" / "results.sarif"
    proc = run_merge(raw, out, "--important")
    assert proc.returncode == 1, proc.stdout
    assert "none of them matched" in proc.stderr
    assert not out.exists()


def test_a_filter_that_kept_nothing_is_not_a_mismatch(tmp_path):
    """The guard is conditioned on the key set, not on the kept count.

    A post-filter that legitimately excluded every finding is a real zero. If this goes red,
    important-only can no longer report an honest empty result.
    """
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(raw, "python-python", [sarif_result(RULE, "a.py", 5)], [])
    out = tmp_path / "results" / "results.sarif"
    proc = run_merge(raw, out, "--important")
    assert proc.returncode == 0, proc.stderr
    assert count(out) == 0


def test_a_partial_key_mismatch_still_merges(tmp_path):
    """One matching key is enough to prove the formats still agree; the rest is the filter."""
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(
        raw,
        "python-python",
        [sarif_result(RULE, "a.py", 5), sarif_result(OTHER, "a.py", 3)],
        [json_result(RULE, "a.py", 5), json_result(OTHER, "/elsewhere/a.py", 3)],
    )
    out = tmp_path / "results" / "results.sarif"
    proc = run_merge(raw, out, "--important")
    assert proc.returncode == 0, proc.stderr
    assert count(out) == 1


def test_important_leaves_an_existing_deliverable_alone_when_it_fails(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(raw, "python-python", [sarif_result(RULE, "a.py", 5)], None)
    out = tmp_path / "results.sarif"
    out.write_text(json.dumps(sarif_doc(sarif_result(RULE, "a.py", 5))))
    before = out.read_text()
    assert run_merge(raw, out, "--important").returncode == 1
    assert out.read_text() == before


# --------------------------------------------------------------------- unparseable SARIF


def test_an_unparseable_sarif_is_named_on_stdout(tmp_path):
    """The silent-omission case this whole flag set exists to prevent.

    A scan can exit 0, write a valid .json — so it lands in .scans with a finding count — and
    still leave a truncated .sarif. The merge drops it and the total is short by exactly those
    findings. On stderr that was invisible to the report; it has to be in the same stream the
    Report phase reads, and named, or the run presents as clean.
    """
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(raw, "python-python", [sarif_result(RULE, "a.py", 5)], None)
    (raw / "python-broken.sarif").write_text('{"runs":[{"results":[')
    out = tmp_path / "results.sarif"
    proc = run_merge(raw, out)
    assert proc.returncode == 0, proc.stderr
    assert count(out) == 1, "the healthy scan must still merge"
    assert "unparseable" in proc.stdout
    assert "python-broken.sarif" in proc.stdout, "the file must be named, not just counted"


def test_every_sarif_unparseable_is_an_error(tmp_path):
    """Zero findings from zero readable files is a broken run, not a clean one."""
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "python-broken.sarif").write_text('{"runs":[{"results":[')
    out = tmp_path / "results.sarif"
    proc = run_merge(raw, out)
    assert proc.returncode == 1
    assert "nothing to merge" in proc.stderr
    assert not out.exists()


def test_the_merge_returns_what_it_could_not_read(tmp_path):
    """The list is a return value, so a caller cannot forget to look at it."""
    write_scan(tmp_path, "ok", [sarif_result(RULE, "a.py", 5)], None)
    (tmp_path / "bad.sarif").write_text("{{{")
    merged, unparseable = merge_sarif_pure_python(sorted(tmp_path.glob("*.sarif")))
    assert [Path(p).name for p in unparseable] == ["bad.sarif"]
    assert sum(len(r["results"]) for r in merged["runs"]) == 1


# ------------------------------------------------------------------------- one merge backend


def test_the_merge_shells_out_to_nothing(tmp_path):
    """Run with an empty PATH, so any external merge tool is unreachable.

    The merge used to try `npx @microsoft/sarif-multitool` first and fall back to Python, which
    made the result depend on whether that package sat in the npx cache. Only the Python merge
    dedups on sarif_key, and multitool rewrites artifactLocation.uri, so on a machine that had
    it cached --important would match nothing and blame a semgrep format change. One backend,
    same answer everywhere.
    """
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(
        raw, "python-python", [sarif_result(RULE, "a.py", 5)], [json_result(RULE, "a.py", 5)]
    )
    out = tmp_path / "results.sarif"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(raw), str(out), "--important"],
        capture_output=True,
        text=True,
        env={"PATH": "", "HOME": str(tmp_path)},
    )
    assert proc.returncode == 0, proc.stderr
    assert count(out) == 1
    assert "multitool" not in proc.stdout.lower(), "no external merge tool may be consulted"

    # The empty PATH above proves the merge survives without a backend, not that it stopped
    # looking for one: a reintroduced optional branch would just fall back and pass. This is
    # the assertion that fails if one comes back.
    assert "import subprocess" not in SCRIPT.read_text(), (
        "merge_sarif.py must not shell out; a second merge backend disagrees with this one "
        "on dedup and on artifactLocation.uri, and which one runs would depend on the machine"
    )


# ------------------------------------------------------------------------------------ --scans


def write_scans_json(path: Path, succeeded: list[Path], failed: list[Path]) -> Path:
    """A scans.json in run-scans.sh's shape. Both lists carry the same `sarif` key."""
    path.write_text(
        json.dumps(
            {
                "scans": [
                    {"lang": "python", "ruleset": "p/python", "sarif": str(p)} for p in succeeded
                ],
                "failed": [
                    {"lang": "python", "ruleset": "p/x", "sarif": str(p), "error": "exited 7"}
                    for p in failed
                ],
                "skipped": [],
            }
        )
    )
    return path


def dead_scan(raw: Path, stem: str) -> Path:
    """A scan recorded under .failed: its SARIF is on disk with no post-filter beside it."""
    sarif = raw / f"{stem}.sarif"
    sarif.write_text(json.dumps(sarif_doc(sarif_result(OTHER, "b.py", 9))))
    return sarif


def test_a_failed_scan_no_longer_denies_every_other_scan_a_deliverable(tmp_path):
    """The point of the flag: one dead scan must not take the whole important-only merge."""
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(
        raw, "python-python", [sarif_result(RULE, "a.py", 5)], [json_result(RULE, "a.py", 5)]
    )
    dead = dead_scan(raw, "python-broken")
    scans = write_scans_json(tmp_path / "scans.json", [raw / "python-python.sarif"], [dead])
    out = tmp_path / "results.sarif"
    proc = run_merge(raw, out, "--important", "--scans", str(scans))
    assert proc.returncode == 0, proc.stderr
    assert count(out) == 1
    assert "python-broken.sarif" in proc.stdout, "the excluded file must be named for the report"


def test_the_same_run_without_scans_json_still_fails(tmp_path):
    """Pins that the flag is what makes it survivable, not a change in the merge's strictness."""
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(
        raw, "python-python", [sarif_result(RULE, "a.py", 5)], [json_result(RULE, "a.py", 5)]
    )
    dead_scan(raw, "python-broken")
    out = tmp_path / "results.sarif"
    assert run_merge(raw, out, "--important").returncode == 1
    assert not out.exists()


def test_a_succeeded_scan_missing_its_filter_still_fails(tmp_path):
    """Only failed scans are exempt.

    A healthy scan with no post-filter beside it still aborts the merge: its findings are real,
    and filtering against a key set that never saw them drops them from the deliverable with
    nothing downstream able to notice.
    """
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(
        raw, "python-python", [sarif_result(RULE, "a.py", 5)], [json_result(RULE, "a.py", 5)]
    )
    healthy = dead_scan(raw, "python-other")  # same shape, but recorded as a success below
    scans = write_scans_json(tmp_path / "scans.json", [raw / "python-python.sarif", healthy], [])
    out = tmp_path / "results.sarif"
    proc = run_merge(raw, out, "--important", "--scans", str(scans))
    assert proc.returncode == 1
    assert "python-other-important.json" in proc.stderr
    assert not out.exists()


def test_run_all_also_drops_a_failed_scan_output(tmp_path):
    """A dead process's file is not a scan result in either mode."""
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(raw, "python-python", [sarif_result(RULE, "a.py", 5)], None)
    dead = dead_scan(raw, "python-broken")
    scans = write_scans_json(tmp_path / "scans.json", [raw / "python-python.sarif"], [dead])
    out = tmp_path / "results.sarif"
    proc = run_merge(raw, out, "--scans", str(scans))
    assert proc.returncode == 0, proc.stderr
    assert count(out) == 1, "the failed scan's finding must not reach the merge"


def test_every_scan_failed_is_an_error_not_an_empty_merge(tmp_path):
    """Excluding everything would otherwise write an empty SARIF and report a clean run."""
    raw = tmp_path / "raw"
    raw.mkdir()
    dead = dead_scan(raw, "python-broken")
    scans = write_scans_json(tmp_path / "scans.json", [], [dead])
    out = tmp_path / "results.sarif"
    proc = run_merge(raw, out, "--scans", str(scans))
    assert proc.returncode == 1
    assert "nothing to merge" in proc.stderr
    assert not out.exists()


def test_a_scans_json_with_no_failed_array_is_rejected(tmp_path):
    """Catches the wrong file being passed; treating it as 'nothing failed' would be silent."""
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(
        raw, "python-python", [sarif_result(RULE, "a.py", 5)], [json_result(RULE, "a.py", 5)]
    )
    bad = tmp_path / "scans.json"
    bad.write_text(json.dumps({"scans": []}))
    out = tmp_path / "results.sarif"
    proc = run_merge(raw, out, "--important", "--scans", str(bad))
    assert proc.returncode == 1
    assert "not a scans.json" in proc.stderr
    assert not out.exists()


def test_scans_flag_without_a_path_is_rejected(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    write_scan(raw, "python-python", [sarif_result(RULE, "a.py", 5)], None)
    proc = run_merge(raw, tmp_path / "results.sarif", "--scans")
    assert proc.returncode == 1
    assert "--scans needs" in proc.stderr


def test_an_empty_raw_directory_is_an_error(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    assert run_merge(raw, tmp_path / "o.sarif").returncode == 1


# ------------------------------------------------------------------------------ merge dedup


def test_merge_dedups_one_finding_flagged_by_two_rulesets(tmp_path):
    """The reason the report counts from the merge and never sums per-scan counts."""
    write_scan(tmp_path, "python-python", [sarif_result(RULE, "a.py", 5)], None)
    write_scan(tmp_path, "all-audit", [sarif_result(RULE, "a.py", 5)], None)
    merged, _ = merge_sarif_pure_python(sorted(tmp_path.glob("*.sarif")))
    assert sum(len(run["results"]) for run in merged["runs"]) == 1
