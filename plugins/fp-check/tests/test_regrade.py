"""Layer 3 regrade: re-score a recorded run offline, no model call.

This is the loop you actually iterate. `capture-run.sh` costs money once; every
run of this file is free.

All format knowledge lives in `stream.py`. Nothing here indexes a raw event dict.

**What the recorded run showed, which the fixture design originally got wrong:**
under `claude -p`, the Workflow tool returns as soon as the run backgrounds. The
session ends at `num_turns: 1` and the workflow's *result* never reaches the
stream. So the stream is asserted for the launch (namespaced name, no error,
argument shape) and the per-stage results come from the run's `journal.jsonl`.

**The checked-in capture is a recording of concept-prover, the plugin fp-check
was merged FROM.** It dispatched `concept-prover:verify-attack-path`, and its
per-stage verdicts were validated against that script's schemas. Neither exists
here: Stage 1 is `fp-check:triage-static`, with a brocard pre-gate and an
already-fixed search the recording never ran. So every assertion below grades a
plugin that is gone, and this module skips until a capture is taken against the
merged plugin — which costs a paid run, and is recorded debt rather than a gap
nobody knows about.

The skip is CONDITIONAL on the capture's own recorded workflow name, not
unconditional, and `test_the_capture_is_stale_and_the_skip_is_still_earned` fails
the build the moment a capture of the current plugin is promoted. A skip that
cannot expire is how a whole layer quietly stops running.

`test_scrub.py` is unaffected and still runs: it grades the scrubber, which must
not destroy `file:line` evidence, and that is independent of which plugin was
recorded.

Run:
    uv run --with pytest --with jsonschema --no-project \
        pytest plugins/fp-check/tests/test_regrade.py
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from stream import Capture, StreamFormatError, load_run_meta
from test_workflow_contract import schema_literals

HERE = Path(__file__).resolve().parent
WORKFLOWS = HERE.parent / "workflows"

# The plugin the CAPTURE was recorded against, which is not the plugin this
# directory now tests. Keep both: the first is what the fixture is evidence of,
# the second is what a re-capture will have to produce.
CAPTURED_PLUGIN = "concept-prover"
PLUGIN_NAME = "fp-check"
CAPTURED_WORKFLOW_SCRIPT = "verify-attack-path.js"


@pytest.fixture(scope="module")
def fixtures_dir(pytestconfig) -> Path:
    """tests/fixtures by default; --fixtures-dir regrades one run of a batch."""
    chosen = pytestconfig.getoption("--fixtures-dir")
    return Path(chosen).resolve() if chosen else HERE / "fixtures"


# Expected values for the recorded fixture (eval case 2). The payload is blocked
# two validation layers above the apparent sink, so the run must halt with no PoC.
EXPECTED_WORKFLOW = f"{CAPTURED_PLUGIN}:verify-attack-path"
EXPECTED_LAYER_AGENTS = 2
EXPECTED_TOTAL_AGENTS = 4  # 2 layers + recovery + threat model

# The checked-in capture was recorded against an EARLIER search.py, whose longer
# docstrings put the same two guards at :20 and :27. That evidence is frozen
# provenance: renumbering a recorded run to agree with today's source destroys
# the only thing it is evidence of (see tests/README.md). So this constant stays
# where the recording put it, and a run captured NOW is graded against the source
# as it stands now — see expected_blocking_lines below.
EXPECTED_BLOCKING_LINES = {"search.py:20", "search.py:27"}

# The condition: the script the capture dispatched is not shipped here any more.
# Written as a check on the filesystem rather than as a bare `skip` so that
# restoring the script, or promoting a new capture, re-arms the whole module.
_CAPTURE_IS_STALE = not (WORKFLOWS / CAPTURED_WORKFLOW_SCRIPT).is_file()

pytestmark = pytest.mark.skipif(
    _CAPTURE_IS_STALE,
    reason=(
        f"the checked-in capture recorded {EXPECTED_WORKFLOW}, and "
        f"{CAPTURED_WORKFLOW_SCRIPT} is not shipped by this plugin. Re-capture "
        f"against fp-check:triage-static (tests/capture-runs.sh, one paid run) and "
        f"re-point the constants in this file; see tests/README.md, Layer 3."
    ),
)

SEARCH_PY = HERE.parent / "evals" / "fixtures" / "case2_search" / "search.py"

# The two validation layers, located by the code that implements them rather
# than by line number. Hardcoding the numbers is what broke: commit 853d4ea0
# rewrote the target's comments, moving both guards up six lines, and this
# constant stayed on the old numbering while capture-runs.sh went on copying the
# CURRENT fixtures into the throwaway worktree. Every run of a fresh batch would
# have been graded against lines that are now docstrings — a guaranteed FAIL for
# each of RUNS x $CAPTURE_BUDGET_USD, discovered only after paying for it.
BLOCKING_GUARDS = (r"ALLOWED_TERM\.match\(", r"any\(ch in term")


def guard_lines(source: Path = SEARCH_PY) -> set[str]:
    """`{"search.py:14", "search.py:21"}` for the target as it stands now.

    Each pattern must match exactly one line. Zero matches would return a
    smaller set, and `found >= EXPECTED` is vacuously true against an empty one —
    the assertion would pass having required nothing.
    """
    numbered = list(enumerate(source.read_text().splitlines(), 1))
    located = set()
    for pattern in BLOCKING_GUARDS:
        rx = re.compile(pattern)
        hits = [n for n, line in numbered if rx.search(line)]
        assert len(hits) == 1, (
            f"{pattern!r} matches {len(hits)} line(s) in {source}; the blocking guard cannot "
            f"be located, so the expected set would be incomplete and the superset assertion "
            f"below would pass having required less than it should"
        )
        located.add(f"{source.name}:{hits[0]}")
    return located


# The vocabulary OF THE RECORDED RUN, which is a capture of
# concept-prover:verify-attack-path. It is deliberately NOT fp-check 2.0.0's
# vocabulary: fp-check renamed these to PAYLOAD_REACHES_SINK /
# PAYLOAD_STOPPED_HERE (and the deep-route proofs to FINDING_SURVIVES /
# FINDING_REFUTED) after a probe caught an agent returning `BLOCKS` with the
# reason "I labeled this BLOCKS meaning the payload is NOT blocked".
#
# Rewriting these to the new names would falsify the recording — the capture
# genuinely contains the old ones. **When tests/capture-runs.sh is finally run
# against fp-check:triage-static, this set moves with it**, and so do the two
# deferred mutations that name BLOCKS. Until then this module skips, which is
# why the rename could not be caught here.
LAYER_VERDICTS = {"PASSES", "BLOCKS", "UNCERTAIN"}
SCOPE_VALUES = {"YES", "NO", "UNCERTAIN"}


@pytest.fixture(scope="module")
def expected_blocking_lines(fixtures_dir: Path) -> set[str]:
    """Which line numbers this run's evidence should carry.

    The checked-in fixture is frozen provenance and keeps the numbering of the
    search.py it was recorded against. Anything regraded through
    `--fixtures-dir` — which is how capture-runs.sh scores every run of a paid
    batch — was produced against the fixtures as they are on disk today, so its
    expectation is derived from them.
    """
    if fixtures_dir == HERE / "fixtures":
        return EXPECTED_BLOCKING_LINES
    return guard_lines()


@pytest.fixture(scope="module")
def capture(fixtures_dir: Path) -> Capture:
    return Capture.load(fixtures_dir / "run.stream.jsonl")


@pytest.fixture(scope="module")
def journal(fixtures_dir: Path) -> list[dict]:
    return Capture.journal_returns(fixtures_dir / "run.journal.jsonl")


@pytest.fixture(scope="module")
def meta(fixtures_dir: Path) -> dict:
    return load_run_meta(fixtures_dir / "run.meta.json")


def agent_results(journal: list[dict]) -> list[dict]:
    """The structured value each agent returned."""
    return [
        r["result"]
        for r in journal
        if r.get("type") == "result" and isinstance(r.get("result"), dict)
    ]


# --------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------


def test_run_metadata_records_model_effort_and_cli_version(meta: dict):
    for field in ("cli_version", "model", "effort", "runs", "synthetic"):
        assert field in meta, f"run.meta.json is missing {field!r}; results are not reproducible"


def test_fixture_is_a_real_run_not_a_synthetic_one(meta: dict):
    assert meta.get("synthetic") is False, (
        "the fixture is synthetic; it proves the assertions fire, not that the workflow works"
    )
    assert meta.get("runs", 0) >= 1
    # A recorded rate, not just a recorded run: 1-of-3 must not read as success.
    assert meta.get("passed") == meta.get("runs"), (
        f"run.meta.json records {meta.get('passed')}/{meta.get('runs')} passing; the fixture "
        f"must come from a batch where every run passed, or the expected values below are "
        f"asserting against a run that failed"
    )


# --------------------------------------------------------------------------
# The launch. Status alone is not evidence the workflow ran.
# --------------------------------------------------------------------------


def test_the_skill_was_actually_invoked(capture: Capture):
    """Reading SKILL.md is not invoking the skill.

    On the first recorded attempt the Skill tool was denied, the model read
    SKILL.md by hand, and then correctly refused to dispatch a workflow — the
    Workflow opt-in exemption is "the user invoked a skill whose instructions
    tell you to call Workflow", and no skill had been invoked.
    """
    skills = capture.skill_invocations()
    assert any(s.startswith(f"{PLUGIN_NAME}:") for s in skills), (
        f"the concept-prover skill was never invoked (skills seen: {skills}). Reading "
        f"SKILL.md by hand is not invoking it, and the Workflow opt-in exemption is "
        f"'the user invoked a skill whose instructions tell you to call Workflow'."
    )


def test_a_workflow_was_launched(capture: Capture):
    assert capture.workflow_launches(), "no Workflow tool calls; the skill never dispatched"


def test_no_launch_reported_an_error(capture: Capture):
    """A syntax-failed script returns async_launched WITH error set."""
    for launch in capture.workflow_launches():
        assert launch.started, (
            f"workflow {launch.name!r} came back with error={launch.error!r}; "
            f"status {launch.status!r} alone would have looked like success"
        )


def test_launched_by_namespaced_name(capture: Capture):
    names = [ln.name for ln in capture.workflow_launches()]
    assert names, "zero launches discovered"
    assert EXPECTED_WORKFLOW in names, f"expected {EXPECTED_WORKFLOW}, got {names}"


def test_no_poc_workflow_ran_for_a_blocked_finding(capture: Capture):
    names = [ln.name for ln in capture.workflow_launches()]
    assert not any("build-poc" in n for n in names), (
        "build-poc ran despite the attack path being blocked; only PROCEED justifies building"
    )


# --------------------------------------------------------------------------
# The dispatch contract. The bug this layer actually found.
# --------------------------------------------------------------------------

REQUIRED_ARGS = {
    "finding": ("summary", "sink", "component", "claimedImpact"),
    "entryPoint": ("description", "location", "payload"),
}


def test_every_launch_passes_basedir(capture: Capture):
    launches = capture.workflow_launches()
    assert launches, "zero launches discovered"
    for launch in launches:
        assert launch.args.get("baseDir"), f"{launch.name} dispatched without baseDir"


def test_dispatch_used_the_documented_field_names(capture: Capture):
    """Regression for the bug this layer found.

    Before SKILL.md specified the shapes, the orchestrator sent finding.title,
    finding.initialImpactClaim, entryPoint.function, entryPoint.exampleInput and an
    object scope, so the threat-model agent was asked about "Finding: undefined,
    Component: undefined, Declared scope: [object Object]". Confirmed fixed across
    3/3 recorded runs.
    """
    launch = next(ln for ln in capture.workflow_launches() if ln.name == EXPECTED_WORKFLOW)
    wrong = []
    for obj, fields in REQUIRED_ARGS.items():
        got = launch.args.get(obj) or {}
        wrong += [f"{obj}.{f}" for f in fields if not got.get(f)]
    scope = launch.args.get("scope")
    if scope is not None and not isinstance(scope, str):
        wrong.append("scope (must be a string, not an object)")
    assert not wrong, (
        f"dispatch omitted or misnamed {wrong}. These interpolate into prompts as the "
        f"literal text 'undefined'. See the Dispatch contract in SKILL.md."
    )


# --------------------------------------------------------------------------
# Per-stage results, from the journal.
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def verify_schemas() -> dict:
    """The shipped stage schemas, via test_workflow_contract's extractor.

    This file used to carry its own copy of that regex, and its own copy of the
    comment explaining the comment-stripping defect they both had. One
    extractor, evaluated once per module.
    """
    schemas = schema_literals(WORKFLOWS / "verify-attack-path.js")
    assert schemas, "no *_SCHEMA constants found; refusing to report success"
    return schemas


def test_journal_has_a_result_for_every_agent(journal: list[dict]):
    started = sum(1 for r in journal if r.get("type") == "started")
    results = agent_results(journal)
    assert started == EXPECTED_TOTAL_AGENTS, (
        f"expected {EXPECTED_TOTAL_AGENTS} agents, {started} started"
    )
    assert len(results) == started, f"{started} agents started but {len(results)} returned a result"


def test_layer_verdicts_validate_against_the_stage_schema(journal, verify_schemas):
    schema = verify_schemas["LAYER_SCHEMA"]
    validator = Draft202012Validator(schema)
    layers = [r for r in agent_results(journal) if "verdict" in r]
    assert len(layers) == EXPECTED_LAYER_AGENTS, f"expected {EXPECTED_LAYER_AGENTS} layer verdicts"
    for layer in layers:
        errors = sorted(validator.iter_errors(layer), key=str)
        assert not errors, f"layer verdict fails LAYER_SCHEMA: {errors[0].message}"


@pytest.mark.parametrize(
    ("const", "discriminator", "label"),
    [("RECOVERY_SCHEMA", "recoveryExists", "recovery"), ("THREAT_SCHEMA", "inScope", "threat")],
)
def test_single_stage_verdict_validates_against_its_schema(
    journal, verify_schemas, const, discriminator, label
):
    """Recovery and threat-model differ only in which key identifies them."""
    validator = Draft202012Validator(verify_schemas[const])
    found = [r for r in agent_results(journal) if discriminator in r]
    assert found, f"no {label} verdict in the journal"
    for r in found:
        errors = sorted(validator.iter_errors(r), key=str)
        assert not errors, f"{label} fails {const}: {errors[0].message}"


def test_no_unknown_enum_values(journal: list[dict]):
    results = agent_results(journal)
    assert results, "zero agent results; refusing to report success"
    for r in results:
        if "verdict" in r:
            assert r["verdict"] in LAYER_VERDICTS, f"unknown verdict {r['verdict']!r}"
        if "inScope" in r:
            assert r["inScope"] in SCOPE_VALUES, f"unknown inScope {r['inScope']!r}"


# --------------------------------------------------------------------------
# Exact expected values for this fixture.
# --------------------------------------------------------------------------


def test_both_validation_layers_blocked_the_payload(journal: list[dict]):
    verdicts = [r["verdict"] for r in agent_results(journal) if "verdict" in r]
    assert verdicts, "zero layer verdicts"
    assert set(verdicts) == {"BLOCKS"}, f"expected both layers to block, got {verdicts}"


def test_the_guards_can_still_be_located_in_the_current_target():
    """Zero guard for the derivation.

    `found >= expected` is vacuously true against an empty expectation, so a
    search.py rewrite that broke both patterns would turn the assertion below
    into a no-op rather than a failure.
    """
    located = guard_lines()
    assert len(located) == len(BLOCKING_GUARDS), (
        f"located {sorted(located)} for {len(BLOCKING_GUARDS)} guards in {SEARCH_PY}"
    )


def test_the_blocking_layers_are_the_expected_file_lines(
    journal: list[dict], expected_blocking_lines: set[str]
):
    found = set()
    for r in agent_results(journal):
        if r.get("verdict") == "BLOCKS":
            found |= set(re.findall(r"search\.py:\d+", r.get("location", "")))
    assert found >= expected_blocking_lines, (
        f"expected the payload blocked at {sorted(expected_blocking_lines)}, got {sorted(found)}. "
        f"If this is a freshly promoted capture, EXPECTED_BLOCKING_LINES is still frozen at the "
        f"numbering of the search.py the OLD recording was made against — move it to what the "
        f"new capture reports. Do not renumber the capture."
    )


def test_each_blocking_layer_quotes_code_evidence(journal: list[dict]):
    blocking = [r for r in agent_results(journal) if r.get("verdict") == "BLOCKS"]
    assert blocking, "zero blocking verdicts to check"
    for r in blocking:
        evidence = r.get("evidence", "")
        assert len(evidence) > 80, "a BLOCKS verdict must quote the code, not assert"
        # `"term" in evidence` also matched "determine", "terminate", "intermediate".
        assert re.search(r"\bterm\b", evidence), (
            "evidence does not reference the checked value by name"
        )


def test_no_impact_survives_the_block(journal: list[dict]):
    recovery = [r for r in agent_results(journal) if "effectiveImpact" in r]
    assert recovery, "no recovery verdict"
    impact = recovery[0]["effectiveImpact"].lower()
    assert impact.startswith("none") or "no injection impact" in impact, (
        f"expected no surviving impact for a blocked path, got: {impact[:120]}"
    )


# --------------------------------------------------------------------------
# The helper's own guards.
# --------------------------------------------------------------------------


def test_missing_capture_fails_rather_than_skips(tmp_path: Path):
    with pytest.raises(StreamFormatError):
        Capture.load(tmp_path / "absent.jsonl")


def test_empty_capture_fails_rather_than_passes(tmp_path: Path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    with pytest.raises(StreamFormatError):
        Capture.load(empty)


def test_empty_journal_fails_rather_than_passes(tmp_path: Path):
    empty = tmp_path / "journal.jsonl"
    empty.write_text("")
    with pytest.raises(StreamFormatError):
        Capture.journal_returns(empty)


def test_launch_with_error_is_not_started(tmp_path: Path):
    """The exact trap: async_launched WITH error set is a run that never happened."""
    path = tmp_path / "failed.jsonl"
    events = [
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "t1",
                        "name": "Workflow",
                        "input": {"name": EXPECTED_WORKFLOW, "args": {}},
                    }
                ]
            },
        },
        {
            "type": "user",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "t1",
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {"status": "async_launched", "error": "SyntaxError"}
                                ),
                            }
                        ],
                    }
                ]
            },
        },
        {"type": "result", "subtype": "success", "is_error": False},
    ]
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    launch = Capture.load(path).workflow_launches()[0]
    assert launch.status == "async_launched"
    assert not launch.started, "a launch carrying an error must not count as started"


def test_unanswered_launch_is_not_started(tmp_path: Path):
    """One level below the trap above: a tool call with no tool_result at all.

    The payload is then `{}`, so `error` is None and `started` read True — a
    Workflow call that was never answered counted as a workflow that ran.
    """
    path = tmp_path / "unanswered.jsonl"
    events = [
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "t1",
                        "name": "Workflow",
                        "input": {"name": EXPECTED_WORKFLOW, "args": {}},
                    }
                ]
            },
        },
        {"type": "result", "subtype": "success", "is_error": False},
    ]
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    launch = Capture.load(path).workflow_launches()[0]
    assert launch.status is None
    assert launch.error is None
    assert not launch.started, "no result is not the same as no error"


# A skip that cannot expire is how a whole test layer quietly stops running, so
# this one is not covered by `pytestmark` and always executes. It fails as soon as
# the premise for skipping stops holding — either because a capture of the merged
# plugin was promoted, or because the retired script came back.
@pytest.mark.skipif(False, reason="the zero guard; never skipped")
def test_the_capture_is_stale_and_the_skip_is_still_earned():
    meta_path = (HERE / "fixtures") / "run.meta.json"
    assert meta_path.is_file(), (
        "the capture metadata is gone, so nothing above could run even if it were "
        "re-pointed; either restore it or delete this layer deliberately"
    )
    recorded = json.loads(meta_path.read_text())
    plugin = str(recorded.get("plugin", "")) or EXPECTED_WORKFLOW
    assert CAPTURED_PLUGIN in plugin or _CAPTURE_IS_STALE, (
        f"the capture records {plugin!r}, which is no longer the retired plugin, so the "
        f"module-level skip in this file is not earned any more. Re-point "
        f"EXPECTED_WORKFLOW, EXPECTED_LAYER_AGENTS, EXPECTED_TOTAL_AGENTS and "
        f"EXPECTED_BLOCKING_LINES at the new recording and delete the skip."
    )
    assert _CAPTURE_IS_STALE, (
        f"{CAPTURED_WORKFLOW_SCRIPT} is shipped again, so this module is no longer "
        f"grading a plugin that does not exist. Remove the pytestmark skip."
    )
