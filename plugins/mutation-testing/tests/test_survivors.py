"""Exercise scripts/survivors.py on the captured vault campaign and on malformed input."""

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

PLUGIN = Path(__file__).resolve().parent.parent
SCRIPT = PLUGIN / "skills" / "mutation-testing" / "scripts" / "survivors.py"
FIXTURE = PLUGIN / "evals" / "weak-suite-analysis" / "fixture"


def survivors(*args: str, cwd: Path | None = None, env: dict | None = None):
    return subprocess.run(
        ["uv", "run", "--no-project", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
    )


def fixture_args(*extra: str) -> list[str]:
    return [
        "--results",
        str(FIXTURE / "mewt-results.json"),
        "--status",
        str(FIXTURE / "mewt-status.txt"),
        *extra,
    ]


def test_lists_every_survivor_with_one_based_lines():
    proc = survivors(*fixture_args())
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "survivors: 8 uncaught mutants" in out
    assert "29 total, 24 tested, 0 untested, 16 caught, 8 uncaught, 0 timeout, 5 skipped" in out
    # mewt's line_offset is 0-based; the guard on source line 24 has line_offset 23.
    for mutant_id, where in [
        (6, "CR line 24-26"),
        (11, "IF line 24:"),
        (7, "CR line 27-29"),
        (12, "IF line 27:"),
        (9, "CR line 31:"),
        (25, "COS line 37: `>` -> `!=`"),
        (28, "COS line 37: `>` -> `>=`"),
        (10, "CR line 41:"),
    ]:
        assert f"#{mutant_id} {where}" in out
    assert "37 |     balance > 0" in out
    assert "24 |     if !is_admin {" in out
    assert "admin_can_withdraw, reports_available_funds" in out
    assert "test files: tests/vault.rs" in out
    assert "## test file tests/vault.rs (whole file)" in out
    assert "fn admin_can_withdraw()" in out


def test_test_files_respect_the_line_budget():
    out = survivors(*fixture_args("--test-lines", "0")).stdout
    assert "tests/vault.rs (not shown)" in out and "## test file" not in out


def test_json_output_matches_the_results_file():
    proc = survivors(*fixture_args("--json"))
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    raw = json.loads((FIXTURE / "mewt-results.json").read_text())["results"]
    got = {s["id"]: s for s in report["files"]["src/lib.rs"]["survivors"]}
    assert set(got) == {r["mutant"]["id"] for r in raw}
    for r in raw:
        s = got[r["mutant"]["id"]]
        assert s["line"] == r["mutant"]["line_offset"] + 1
        assert (s["old_text"], s["new_text"]) == (r["mutant"]["old_text"], r["mutant"]["new_text"])
    assert report["campaign"]["skipped"] == 5
    assert "note" not in report["files"]["src/lib.rs"]


def test_windows_merge_and_respect_context():
    proc = survivors(*fixture_args("--json", "--context", "0"))
    windows = json.loads(proc.stdout)["files"]["src/lib.rs"]["source"]
    assert [(w["start"], w["end"]) for w in windows] == [(24, 29), (31, 31), (37, 37), (41, 41)]


def copy_fixture(tmp_path: Path) -> Path:
    dest = tmp_path / "campaign with space"
    shutil.copytree(FIXTURE, dest)
    return dest


def test_flags_stale_and_missing_sources(tmp_path):
    campaign = copy_fixture(tmp_path)
    lib = campaign / "src" / "lib.rs"
    lib.write_text(lib.read_text() + "\n// edited after the campaign\n")
    captured = (FIXTURE / "mewt-results.json").read_text()
    assert hashlib.sha256(lib.read_bytes()).hexdigest() not in captured
    stale = survivors("--results", str(campaign / "mewt-results.json"))
    assert stale.returncode == 0 and "source changed since the campaign ran" in stale.stdout
    lib.unlink()
    missing = survivors("--results", str(campaign / "mewt-results.json"))
    assert missing.returncode == 0 and "source not found" in missing.stdout


def test_zero_survivors_is_not_an_error(tmp_path):
    results = tmp_path / "r.json"
    results.write_text(json.dumps({"results": []}))
    proc = survivors("--results", str(results))
    assert proc.returncode == 0 and "no uncaught mutants" in proc.stdout


def test_only_uncaught_outcomes_are_listed(tmp_path):
    raw = json.loads((FIXTURE / "mewt-results.json").read_text())
    raw["results"][0]["outcome"]["status"] = "TestFail"
    raw["results"][1]["outcome"]["status"] = "Timeout"
    campaign = copy_fixture(tmp_path)
    (campaign / "mewt-results.json").write_text(json.dumps(raw))
    proc = survivors("--results", str(campaign / "mewt-results.json"))
    assert proc.returncode == 0 and "survivors: 6 uncaught mutants" in proc.stdout


def test_rejects_malformed_or_missing_input(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert survivors("--results", str(bad)).returncode == 2
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"mutants": []}))
    proc = survivors("--results", str(wrong))
    assert proc.returncode == 2 and '"results" list' in proc.stderr
    assert survivors("--results", str(tmp_path / "absent.json")).returncode == 2
    assert survivors(*fixture_args("--context", "-1")).returncode == 2


def test_without_results_requires_the_tool(tmp_path):
    uv = shutil.which("uv")
    assert uv is not None
    env = {**os.environ, "PATH": str(Path(uv).parent)}
    if shutil.which("mewt", path=env["PATH"]):
        return  # mewt lives next to uv here; the PATH trick cannot hide it
    proc = survivors(cwd=tmp_path, env=env)
    assert proc.returncode == 2 and "mewt is not on PATH" in proc.stderr
