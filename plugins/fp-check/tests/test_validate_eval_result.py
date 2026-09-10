"""Tests for the eval-result gate.

`validate_eval_result.py` is the only thing standing between a green-looking
eval JSON and a claim in a PR. It shipped with no tests, and the consequence was
the bug pinned by `test_a_one_run_eval_is_rejected`: it read `runs`/`runCount`,
the CLI emits `runsPerCase`, so the minimum-runs loop inspected nothing and a
1-run eval passed.

Every case here is driven from the checked-in real result
(`fixtures/eval-result-2026-07-30.json`) rather than a hand-built dict, so a
schema change breaks these tests rather than quietly making them vacuous.

Run:
    uv run --with pytest --no-project \
        pytest plugins/fp-check/tests/test_validate_eval_result.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
VALIDATOR = HERE / "validate_eval_result.py"
REAL_RESULT = HERE / "fixtures" / "eval-result-2026-07-30.json"


def run_validator(payload: dict, tmp_path: Path) -> subprocess.CompletedProcess:
    target = tmp_path / "result.json"
    target.write_text(json.dumps(payload))
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture(scope="module")
def real() -> dict:
    assert REAL_RESULT.exists(), f"{REAL_RESULT} is missing; these tests would test nothing"
    return json.loads(REAL_RESULT.read_text())


def validator():
    """The validator module, loaded from the script it actually ships as."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("validate_eval_result", VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def case_suites() -> dict[str, set[str]]:
    """`CASE_SUITES` as the validator actually defines it.

    Read out of the script rather than duplicated here: the two are the same
    list, and a second copy is the thing that let the first one go stale.
    """
    m = re.search(r"CASE_SUITES = \{(.*?)\n\}", VALIDATOR.read_text(), re.S)
    assert m, "CASE_SUITES not found in the validator"
    suites = {
        name: set(re.findall(r'"([^"]+)"', body))
        for name, body in re.findall(r'"(\w+)":\s*\{(.*?)\},', m.group(1), re.S)
    }
    assert suites, "CASE_SUITES is empty; refusing to report success"
    for name, names in suites.items():
        assert names, f"CASE_SUITES[{name!r}] is empty; refusing to report success"
    return suites


def expected_cases() -> set[str]:
    return {name for names in case_suites().values() for name in names}


def test_expected_cases_matches_the_cases_on_disk():
    """The validator's case list must not drift from evals/.

    It did: the list named three cases while five existed, so a run that
    silently skipped `integration-cap` and `already-fixed` — the only two that
    reach Phases 4-6 — passed the gate that exists to catch exactly that.
    """
    on_disk = {p.parent.name for p in (HERE.parents[0] / "evals").glob("*/case.yaml")}
    assert on_disk, "no eval cases found on disk; refusing to report success"
    assert expected_cases() == on_disk, (
        f"validate_eval_result.py expects {sorted(expected_cases())} but evals/ holds "
        f"{sorted(on_disk)}; a run skipping the difference would validate clean"
    )


def test_the_validator_suites_match_the_tags_on_disk():
    """The split is declared in two places and both are load-bearing.

    `--tag` is what the operator actually runs; `CASE_SUITES` is what decides
    whether the resulting JSON is complete. If they disagree, the validator
    demands a case the tag never selected — or, worse, accepts a static sweep
    that silently lost one.
    """
    suites = case_suites()
    by_tag: dict[str, set[str]] = {name: set() for name in suites}
    for path in (HERE.parents[0] / "evals").glob("*/case.yaml"):
        tags = set(yaml.safe_load(path.read_text()).get("tags") or [])
        for name in suites:
            if name in tags:
                by_tag[name].add(path.parent.name)
    assert by_tag == suites, (
        f"validate_eval_result.py splits the cases {ns(suites)} but the tags on disk split "
        f"them {ns(by_tag)}. `--tag` and the completeness check must select the same sets."
    )
    overlap = suites["static"] & suites["online"]
    assert not overlap, f"{sorted(overlap)} is in both suites, so no result can be complete"


def ns(d: dict[str, set[str]]) -> dict[str, list[str]]:
    return {k: sorted(v) for k, v in d.items()}


def test_a_result_mixing_the_two_suites_is_rejected(tmp_path: Path, passing: dict):
    """The failure the tag split exists to prevent, asserted rather than assumed.

    Stage 2's ground truth is public record and the static cases' is authored
    here; a mean over both answers no question. `claude plugin eval` runs every
    case it finds, so producing this JSON takes nothing more than forgetting
    `--tag` — and the resulting number would look entirely ordinary.
    """
    template = json.loads(json.dumps(passing["cases"][0]))
    template["name"] = sorted(case_suites()["online"])[0]
    passing["cases"].append(template)
    passing["aggregates"]["casesTotal"] = len(passing["cases"])
    passing["aggregates"]["casesPassed"] = len(passing["cases"])
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "must never be averaged" in proc.stderr


def test_an_unrecognised_case_is_reported_rather_than_ignored(tmp_path: Path, passing: dict):
    """A case the validator has never heard of is checked against nothing.

    Silently ignoring it is how the list went stale the first time: a renamed
    case disappears from the expectations and its absence stops being detectable.
    """
    template = json.loads(json.dumps(passing["cases"][0]))
    template["name"] = "some-case-nobody-registered"
    passing["cases"].append(template)
    passing["aggregates"]["casesTotal"] = len(passing["cases"])
    passing["aggregates"]["casesPassed"] = len(passing["cases"])
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "some-case-nobody-registered" in proc.stderr


def _trace(tmp_path: Path, name: str, plugins: list[dict], skills: list[str] | None = None) -> str:
    """A minimal trace file carrying one session-init record.

    `skills` is a flat list of names, which is the shape a real init record has —
    see fixtures/run.stream.jsonl. Built-ins are bare, plugin skills namespaced.
    """
    return _multi_init_trace(tmp_path, name, [(plugins, skills or [])])


def _multi_init_trace(tmp_path: Path, name: str, sessions: list[tuple]) -> str:
    """A trace carrying one init record per session, as a run with subagents has."""
    path = tmp_path / f"{name}.jsonl"
    path.write_text(
        "".join(
            json.dumps({"type": "system", "subtype": "init", "plugins": p, "skills": s}) + "\n"
            for p, s in sessions
        )
    )
    return str(path)


def _one_case(with_trace: str, without_trace: str) -> dict:
    return {
        "cases": [
            {
                "name": "c",
                "arms": {
                    "with": [{"tracePath": with_trace}],
                    "without": [{"tracePath": without_trace}],
                },
            }
        ]
    }


def isolation(result: dict) -> tuple[int, list[str]]:
    """Total sessions inspected, for the cases that only care how many there were.

    The per-arm breakdown the validator actually returns is asserted directly by
    `test_the_inspected_sessions_are_counted_per_arm`; summing here keeps the
    older cases reading as the session counts they were written as.
    """
    counts, problems = isolation_counts(result)
    return sum(counts.values()), problems


def isolation_counts(result: dict) -> tuple[dict, list[str]]:
    problems: list[str] = []
    return validator().check_ablation_isolation(result, problems), problems


def test_a_case_with_a_null_name_fails_cleanly_rather_than_crashing(tmp_path: Path):
    """`_get` returns the value of a present key, so `"name": null` is None.

    A set mixing None and str raises TypeError inside `sorted()`, so a malformed
    result produced a traceback instead of the clean failure message this whole
    script exists to print. Caught by a type checker, not by any test.
    """
    payload = {"partial": False, "cases": [{"name": None}], "aggregates": {"casesTotal": 1}}
    path = tmp_path / "r.json"
    path.write_text(json.dumps(payload))
    proc = run_validator(payload, tmp_path)
    assert proc.returncode == 1, "a malformed result must fail, not crash"
    assert "Traceback" not in proc.stderr, f"crashed instead of reporting: {proc.stderr}"
    assert "no known case ran" in proc.stderr


def test_a_clean_ablation_passes_isolation(tmp_path: Path):
    result = _one_case(
        _trace(tmp_path, "w", [{"name": "fp-check", "version": "2.0.0"}]),
        _trace(tmp_path, "b", []),
    )
    checked, problems = isolation(result)
    assert checked == 2, "both runs must be inspected"
    assert problems == []


# The failure c-review built a Docker container to prevent: its host cells ran
# with 20 plugins reaching every arm, including its own skill leaking into the
# baseline, which voided a real run. `claude plugin eval` scopes plugins already —
# this is the assertion that proves it still does.
def test_a_contaminated_baseline_is_rejected(tmp_path: Path):
    result = _one_case(
        _trace(tmp_path, "w", [{"name": "fp-check"}]),
        _trace(tmp_path, "b", [{"name": "concept-prover"}]),
    )
    _checked, problems = isolation(result)
    assert problems, "a baseline arm carrying a plugin must be reported"
    assert "concept-prover" in problems[0]


# The leak c-review actually suffered, and the one the plugins-only check could not
# see: `plugins` is empty in the baseline — `claude plugin eval` did scope those —
# while the plugin under test's own SKILL is loaded anyway, from ~/.claude/skills or
# a globally installed copy. Before this, the run below returned checked=2 with no
# problems and the CLI printed `isolation verified`, certifying a delta measured
# against a baseline that had the thing being measured.
def test_a_baseline_carrying_the_plugins_own_skill_is_rejected(tmp_path: Path):
    result = _one_case(
        _trace(tmp_path, "w", [{"name": "fp-check"}], ["fp-check:fp-check"]),
        _trace(tmp_path, "b", [], ["fp-check:fp-check", "c-review:c-review"]),
    )
    _checked, problems = isolation(result)
    assert problems, "a baseline arm carrying a plugin's skill must be reported"
    assert "fp-check:fp-check" in problems[0]
    assert "c-review:c-review" in problems[0]


# The other direction, so the skill check cannot be satisfied by rejecting every
# arm: the baseline legitimately carries Claude Code's built-ins (14 of them in
# sweep251), which are bare names owned by no plugin.
def test_builtin_skills_do_not_trip_the_skill_check(tmp_path: Path):
    builtins = ["deep-research", "dataviz", "code-review", "run"]
    result = _one_case(
        _trace(tmp_path, "w", [{"name": "fp-check"}], [*builtins, "fp-check:fp-check"]),
        _trace(tmp_path, "b", [], builtins),
    )
    checked, problems = isolation(result)
    assert checked == 2
    assert problems == []


def test_the_plugin_arm_rejects_a_foreign_plugins_skill(tmp_path: Path):
    """One plugin loaded is not enough if a second plugin's skill got in anyway."""
    result = _one_case(
        _trace(tmp_path, "w", [{"name": "fp-check"}], ["fp-check:fp-check", "contrarian:x"]),
        _trace(tmp_path, "b", []),
    )
    _checked, problems = isolation(result)
    assert problems, "a foreign skill in the plugin arm must be reported"
    assert "contrarian:x" in problems[0]


# A run that dispatches subagents writes one init record per session, and the
# subagent sessions are half of what c-review measured its leak in. The reader used
# to `break` after the first, so a clean driving session hid every contaminated
# subagent behind it.
def test_every_session_in_a_trace_is_inspected_not_just_the_first(tmp_path: Path):
    result = _one_case(
        _trace(tmp_path, "w", [{"name": "fp-check"}], ["fp-check:fp-check"]),
        _multi_init_trace(
            tmp_path,
            "b",
            [([], ["deep-research"]), ([], ["c-review:c-review"])],
        ),
    )
    checked, problems = isolation(result)
    assert checked == 3, "one record per session, not one per run"
    assert problems, "a subagent session's leak must be reported"
    assert "c-review:c-review" in problems[0]


def test_a_plugin_arm_with_the_wrong_plugin_count_is_rejected(tmp_path: Path):
    for plugins in ([], [{"name": "fp-check"}, {"name": "contrarian"}]):
        result = _one_case(
            _trace(tmp_path, f"w{len(plugins)}", plugins),
            _trace(tmp_path, f"b{len(plugins)}", []),
        )
        _checked, problems = isolation(result)
        assert problems, f"plugin arm with {len(plugins)} plugin(s) must be reported"


# Absent traces are a legitimate state — without --keep-temp the temp dir is gone.
# Reporting that as VERIFIED is the conflation this whole file exists to prevent,
# so the count must be zero and the caller must say so.
def test_a_missing_trace_is_unverified_not_passed(tmp_path: Path):
    missing = str(tmp_path / "gone.jsonl")
    result = {"cases": [{"name": "c", "arms": {"with": [{"tracePath": missing}]}}]}
    checked, problems = isolation(result)
    assert checked == 0
    assert problems == []


# The count has to be per arm, because the caller decides "verified" from it and
# the two arms are not interchangeable: the baseline is the only one this check
# exists to police. A scalar total made a surviving `with` trace speak for a
# baseline nobody opened — see the CLI test below.
def test_the_inspected_sessions_are_counted_per_arm(tmp_path: Path):
    result = _one_case(
        _multi_init_trace(
            tmp_path, "w", [([{"name": "fp-check"}], []), ([{"name": "fp-check"}], [])]
        ),
        _trace(tmp_path, "b", []),
    )
    counts, problems = isolation_counts(result)
    assert problems == []
    assert dict(counts) == {"plugin": 2, "baseline": 1}


def test_a_baseline_with_no_surviving_trace_is_not_counted(tmp_path: Path):
    """The half-reaped sweep: the plugin arm kept a trace, the baseline did not."""
    result = _one_case(_trace(tmp_path, "w", [{"name": "fp-check"}]), str(tmp_path / "gone.jsonl"))
    counts, problems = isolation_counts(result)
    assert problems == [], "a baseline that was never read is unverified, not a failure"
    assert counts["plugin"] == 1
    assert counts["baseline"] == 0, "an unread baseline must not borrow the other arm's count"


# The tests above call check_ablation_isolation() directly, which leaves the
# one thing the shipping validator actually runs — the call site in main() — with
# no coverage at all. Measured: replacing `isolation_checked =
# check_ablation_isolation(result, problems)` with `isolation_checked = 0` left
# all of them green, and the mutation-gate entry for this check reddens on the
# function BODY, which the direct calls still reach. Unwired, the gate would print
# `ablation isolation NOT verified` on every run forever and report a contaminated
# baseline as clean. The three tests below go through the CLI, so they are the ones
# that die if the call is dropped.
def _point_first_runs_at(case: dict, with_trace: str, without_trace: str) -> None:
    """Give the first run of each arm a trace that exists.

    Only the first: the remaining runs keep the recorded temp paths, which are
    long gone, so they are skipped and the verified count is exactly 2. That
    makes the count itself assertable rather than a function of the fixture.
    """
    case["arms"]["with"][0]["tracePath"] = with_trace
    case["arms"]["without"][0]["tracePath"] = without_trace


def test_the_cli_reports_a_contaminated_baseline(tmp_path: Path, passing: dict):
    """The wiring test: contamination reaches the exit code, not just the helper."""
    _point_first_runs_at(
        passing["cases"][0],
        _trace(tmp_path, "cli-w", [{"name": "fp-check"}]),
        _trace(tmp_path, "cli-b", [{"name": "concept-prover"}]),
    )
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1, f"a contaminated baseline must fail the CLI:\n{proc.stdout}"
    assert "concept-prover" in proc.stderr


def test_the_cli_reports_a_clean_ablation_as_verified(tmp_path: Path, passing: dict):
    """And the other direction, so the check cannot be satisfied by rejecting all."""
    _point_first_runs_at(
        passing["cases"][0],
        _trace(tmp_path, "ok-w", [{"name": "fp-check"}]),
        _trace(tmp_path, "ok-b", []),
    )
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 0, proc.stderr
    # "session(s)", not "run(s)": the count is of init records, and a run with
    # subagents contributes more than one.
    assert "isolation verified on 2 session(s)" in proc.stdout, proc.stdout


def test_the_cli_reports_a_baseline_carrying_the_plugins_skill(tmp_path: Path, passing: dict):
    """The reviewer's exact case: `plugins: []` in the baseline, the skill loaded anyway.

    This run exited 0 printing `ablation isolation verified` before the skill check
    existed, so it is the one that must reach the exit code.
    """
    _point_first_runs_at(
        passing["cases"][0],
        _trace(tmp_path, "skill-w", [{"name": "fp-check"}], ["fp-check:fp-check"]),
        _trace(tmp_path, "skill-b", [], ["fp-check:fp-check"]),
    )
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1, f"a baseline carrying the plugin's skill must fail:\n{proc.stdout}"
    assert "fp-check:fp-check" in proc.stderr


def test_the_cli_says_unverified_when_no_trace_survives(tmp_path: Path, passing: dict):
    """Without --keep-temp every tracePath is dead, and that must not read as pass."""
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "isolation NOT verified" in proc.stdout, proc.stdout


# Half a sweep surviving is the ordinary state, not a contrived one: traces are
# reaped per temp dir. With a scalar count, `if isolation_checked:` read the one
# surviving `with` trace as proof and printed `ablation isolation verified on 1
# session(s)` for an ablation whose no-plugin arm was never opened — measured on
# this exact payload before the per-arm count. A contaminated baseline in that run
# is reported as clean.
def test_the_cli_says_unverified_when_only_the_plugin_arm_has_a_trace(
    tmp_path: Path, passing: dict
):
    passing["cases"][0]["arms"]["with"][0]["tracePath"] = _trace(
        tmp_path, "half-w", [{"name": "fp-check"}], ["fp-check:fp-check"]
    )
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "isolation NOT verified" in proc.stdout, proc.stdout
    # The phrase, not the bare word: the boilerplate that follows says
    # "a contaminated baseline would not have been detected" on every unread arm,
    # so asserting `"baseline" in stdout` would hold no matter which arm was read.
    assert "for the baseline arm(s)" in proc.stdout, "the message must name the unread arm"
    assert "verified on" not in proc.stdout, proc.stdout


def test_the_cli_says_unverified_when_only_the_baseline_arm_has_a_trace(
    tmp_path: Path, passing: dict
):
    """And the mirror: an unread plugin arm means its one-plugin rule went unchecked."""
    passing["cases"][0]["arms"]["without"][0]["tracePath"] = _trace(tmp_path, "half-b", [])
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "isolation NOT verified" in proc.stdout, proc.stdout
    assert "for the plugin arm(s)" in proc.stdout, "the message must name the unread arm"


@pytest.fixture
def passing(real: dict) -> dict:
    """The real result, edited to the shape a *good* run would have.

    The recorded run genuinely failed (delta -0.056), so a passing payload has
    to be constructed. It is built by editing the real one, so it keeps every
    key the CLI actually emits.

    The recorded run predates two cases, so the case list is topped up from the
    STATIC suite rather than hardcoded — otherwise adding a case makes this
    fixture, and every assertion built on it, silently wrong.

    The static suite specifically, not every known case: the recorded run is a
    static sweep, and topping it up from the union built a result spanning both
    suites, which the validator now rejects as the un-averageable mix it is.
    """
    payload = json.loads(json.dumps(real))
    payload["partial"] = False
    template = payload["cases"][0]
    static = case_suites()["static"]
    payload["cases"] = [c for c in payload["cases"] if c.get("name", c.get("case")) in static]
    seen = {c.get("name", c.get("case")) for c in payload["cases"]}
    for name in sorted(static - seen):
        extra = json.loads(json.dumps(template))
        extra["name"] = name
        payload["cases"].append(extra)
    agg = payload["aggregates"]
    agg["casesTotal"] = len(payload["cases"])
    agg["casesPassed"] = agg["casesTotal"]
    agg["overallScore"] = 1
    agg["meanDelta"] = 0.5
    return payload


def test_the_recorded_real_result_is_rejected(tmp_path: Path, real: dict):
    """The one run that exists scored a negative delta and must not validate."""
    proc = run_validator(real, tmp_path)
    assert proc.returncode == 1, "a negative-delta run must be rejected"
    assert "ablation delta" in proc.stderr


def test_a_constructed_good_result_is_accepted(tmp_path: Path, passing: dict):
    """Guards against the opposite failure: a validator that rejects everything.

    Without this, every assertion below would pass on a validator hard-coded to
    return 1.
    """
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 0, f"a good result must be accepted:\n{proc.stderr}"
    assert "OK:" in proc.stdout


def test_a_one_run_eval_is_rejected(tmp_path: Path, passing: dict):
    """The bug: the CLI emits `runsPerCase`, the validator read `runs`."""
    for case in passing["cases"]:
        case["runsPerCase"] = 1
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1, "a 1-run eval must not pass; a pass RATE needs 3"
    assert "ran 1 time(s)" in proc.stderr


def test_a_result_with_an_errored_run_is_rejected(tmp_path: Path, passing: dict):
    """A dead run is scored 0, so a dead ARM reads as an arm that answered badly.

    The 2026-08-04 sweep lost 22 of 30 runs to `exit 1: (no stderr)` at turn 1
    for $0.00 each — a usage limit reached mid-sweep. `partial` was still false,
    every case still reported `runsPerCase: 3`, and blocked-attack-path showed a
    +0.47 delta purely because all three no-plugin runs were dead while two
    with-plugin runs had completed before the wall. Every other check in the
    validator was satisfied.
    """
    first = passing["cases"][0]["arms"]["with"][0]
    first["error"] = "exit 1: (no stderr)"
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1, "a result containing an errored run must not pass"
    assert "errored" in proc.stderr, proc.stderr


def test_the_real_result_carries_the_error_key_the_validator_reads(real: dict):
    """Zero guard for the check above: if runs never carry `error`, it inspects
    nothing and a sweep full of dead runs sails through."""
    runs = [r for c in real["cases"] for arm in c["arms"].values() for r in arm]
    assert runs, "no runs in the recorded result"
    assert all("error" in r for r in runs), (
        "recorded runs have no `error` key, so the errored-run guard reads nothing. "
        f"Keys present: {sorted(runs[0])}"
    )


def test_the_real_result_uses_the_key_the_validator_reads(real: dict):
    """Pins the schema assumption itself, so a rename fails loudly here."""
    assert real["cases"], "no cases in the recorded result"
    for case in real["cases"]:
        assert "runsPerCase" in case, (
            f"case {case.get('name')} has no runsPerCase; the validator reads that key "
            f"and would silently check nothing. Keys present: {sorted(case)}"
        )


def test_a_case_with_no_run_count_is_rejected_not_skipped(tmp_path: Path, passing: dict):
    """A missing count means "unknown", which must not read as "fine"."""
    for case in passing["cases"]:
        case.pop("runsPerCase", None)
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "no run count" in proc.stderr


def test_a_missing_score_is_rejected_not_skipped(tmp_path: Path, passing: dict):
    """`score is not None and score != 1` read a renamed key as full marks.

    Measured: renaming `overallScore` to `meanScore` in the passing fixture and
    setting it to 0.6 gave `exit 0` and `OK: 5/5 cases passed`. Every sibling
    reader in the same function — casesTotal, runsPerCase, meanDelta — records a
    problem when its key is absent; this one treated absence as fine, on a
    schema the file's own comments note has moved before.
    """
    agg = passing["aggregates"]
    agg.pop("overallScore", None)
    agg["meanScore"] = 0.6
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1, "a result with no readable score must not pass"
    assert "no overall score" in proc.stderr


def test_the_real_result_carries_the_score_key_the_validator_reads(real: dict):
    """Pins the schema assumption, so a rename fails loudly here rather than
    silently retiring the score check."""
    agg = real["aggregates"]
    assert "overallScore" in agg or "score" in agg, (
        f"the recorded result has no overallScore/score; the validator reads those two "
        f"keys and a rename would make its score check dead. Keys present: {sorted(agg)}"
    )


def test_zero_cases_is_rejected(tmp_path: Path, passing: dict):
    passing["cases"] = []
    passing["aggregates"]["casesTotal"] = 0
    passing["aggregates"]["casesPassed"] = 0
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "zero cases" in proc.stderr


def test_a_missing_case_is_reported_by_name(tmp_path: Path, passing: dict):
    passing["cases"] = [c for c in passing["cases"] if c.get("name") != "should-not-fire"]
    passing["aggregates"]["casesTotal"] = len(passing["cases"])
    passing["aggregates"]["casesPassed"] = len(passing["cases"])
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "should-not-fire" in proc.stderr


def test_a_partial_run_is_rejected(tmp_path: Path, passing: dict):
    passing["partial"] = True
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "partial" in proc.stderr


@pytest.mark.parametrize("delta", [0, -0.1, -1])
def test_a_non_positive_delta_is_rejected(tmp_path: Path, passing: dict, delta: float):
    """A plugin that does not beat its baseline is not doing anything."""
    passing["aggregates"]["meanDelta"] = delta
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "did not beat" in proc.stderr


def test_a_missing_delta_is_rejected_with_the_flag_that_causes_it(tmp_path: Path, passing: dict):
    passing["aggregates"].pop("meanDelta", None)
    proc = run_validator(passing, tmp_path)
    assert proc.returncode == 1
    assert "--ablation with-without" in proc.stderr, (
        "the message must name the flag; for a PATH target it silently defaults to none"
    )


def test_an_unreadable_file_is_an_error_not_a_pass(tmp_path: Path):
    proc = subprocess.run(
        [sys.executable, str(VALIDATOR), str(tmp_path / "nope.json")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "cannot read" in proc.stderr


def test_no_arguments_is_a_usage_error():
    proc = subprocess.run(
        [sys.executable, str(VALIDATOR)], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 2
