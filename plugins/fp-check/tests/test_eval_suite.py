"""Structural tests for the eval suite. No model, no cost.

The eval only means something if its invariants hold. These are the ones the
`plugin eval` authoring guidance calls non-negotiable, checked statically so
they cannot rot:

  - at least one case that should NOT fire the plugin
  - every case has at least one outcome grader, not only `tool_used`
  - every LLM grader is paired with a deterministic one
  - runs >= 3
  - no scaffolded target states its own verdict in a comment

Cases use the `case.yaml` form rather than `prompt.md` + `graders/`, because only
`case.yaml` supports `context.scaffold_script`. The eval runs each case in an
empty working directory, so a repo-relative path in a prompt resolves to
nothing — a scaffold has to materialise the target. That was not a guess: the
first full run scored 0 with the agent reporting "the target doesn't exist".
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

EVALS = Path(__file__).resolve().parents[1] / "evals"
# A case is a directory containing case.yaml. Anything else under evals/ —
# fixtures/, and the results/ tree the eval writes — is not a case.
CASES = sorted(p for p in EVALS.iterdir() if p.is_dir() and (p / "case.yaml").is_file())

# From the CLI's own grader schema.
GRADER_TYPES = {"regex", "tool_order", "tool_used", "file_exists", "llm", "baseline"}
DETERMINISTIC = {"regex", "tool_order", "tool_used", "file_exists"}

# `regex` takes `target`, `llm` takes `focus`; both accept the same values.
# Guessing here costs a whole eval invocation: `target: transcript` was rejected
# at load time with "graders.0.target: Invalid input".
GRADER_SCOPES = {"last_message", "trace", "files"}

MIN_RUNS = 3

# Which checked-in fixtures each case's scaffold must reproduce byte-for-byte.
#
# A case is a list of (path the scaffold writes, checked-in fixture) pairs, not
# a single pair: the cases that reach Phase 4 need a small tree — a caller, a
# sink, a dependency — because a one-file target cannot pose the question of
# whether the PoC drove the real caller or a copy of it. Every file a scaffold
# writes belongs here, or it is a file nothing holds to the checked-in copy.
SCAFFOLD_SOURCES = {
    "blocked-attack-path": (("search.py", "fixtures/case2_search/search.py"),),
    "inflated-impact": (("handler.go", "fixtures/case3_handler/handler.go"),),
    "should-not-fire": (("ledger.py", "fixtures/case1_ledger/ledger.py"),),
    "integration-cap": (
        ("billing/charge.py", "fixtures/case4_billing/billing/charge.py"),
        ("billing/ledger.py", "fixtures/case4_billing/billing/ledger.py"),
        ("client/rates.py", "fixtures/case4_billing/client/rates.py"),
    ),
    # The 1.4.0 copies of auth.py and CHANGELOG.md are deliberately absent: the
    # scaffold writes them, commits them, and then overwrites them with these.
    # Only the HEAD tree is what the case is analysed against, and only the HEAD
    # tree can be compared against a file on disk.
    "already-fixed": (
        ("session.py", "fixtures/case5_session/session.py"),
        ("auth.py", "fixtures/case5_session/auth.py"),
        ("CHANGELOG.md", "fixtures/case5_session/CHANGELOG.md"),
    ),
    # The three unreachable-sink cases added 2026-08-04. blocked-attack-path was
    # the only case where the pipeline demonstrably separated from the no-plugin
    # baseline (3/3 baseline runs wrote a working PoC by calling the sink
    # directly), so the delta rested on one case's mechanism. These give that
    # failure mode three more shapes, each unreachable for a DIFFERENT reason:
    # no call path at all, type coercion, and the report naming the wrong sink.
    "dead-route": (
        ("app/router.py", "fixtures/case6_router/app/router.py"),
        ("app/reports.py", "fixtures/case6_router/app/reports.py"),
    ),
    # A third case, `coerced-to-int`, was authored and then dropped — see
    # tests/README.md. SQL concatenation whose value is int()-coerced. It was
    # measured twice: once with int() a line from the sink, and again with the
    # coercion moved behind a shared typed-params helper in a second module. The
    # delta was +0.00 both times, 6 of 6 runs passing in BOTH arms. A plain
    # session follows the value across the module boundary in 8 turns. Type
    # coercion is simply not a failure mode this plugin improves on, and a case
    # that cannot separate the arms costs ~$3 a sweep to measure nothing.
    "wrong-parameter": (("scanner/tasks.py", "fixtures/case8_scanner/scanner/tasks.py"),),
    # The first case whose ground truth is public record rather than authored
    # here: a real bug in a real project, disclosed and fixed upstream. Excerpted
    # from python-dotenv 1.2.1, BSD-3-Clause, attributed in the file header.
    "online-known-duplicate": (("dotenv/main.py", "fixtures/case9_dotenv/dotenv/main.py"),),
    # The first case carrying more than one finding, and the only one whose
    # correct answer is a statement about the PAIR. Neither half is hard alone:
    # the role check that blocks the injection is one grep away, and the cookie
    # that supplies the role is two. What no single-finding pass can produce is
    # the sentence connecting them.
    "chained-findings": (
        ("app/auth.py", "fixtures/case10_maintenance/app/auth.py"),
        ("app/admin.py", "fixtures/case10_maintenance/app/admin.py"),
        ("app/router.py", "fixtures/case10_maintenance/app/router.py"),
    ),
}


def load_case(case: Path) -> dict:
    path = case / "case.yaml"
    assert path.is_file(), f"{case.name}: missing case.yaml"
    return yaml.safe_load(path.read_text())


def graders(case: Path) -> list[dict]:
    return load_case(case).get("graders", [])


# --------------------------------------------------------------- zero guards


def test_eval_cases_exist():
    assert CASES, f"no eval cases under {EVALS}; refusing to report success"


def test_the_old_invalid_formats_are_gone():
    """evals.json was never a format `plugin eval` discovers, so it never ran.

    prompt.md is a real format but cannot carry a scaffold_script, so a case
    left in that form would run against an empty directory.
    """
    assert not (EVALS / "evals.json").exists(), "evals.json is not a discoverable format"
    for case in CASES:
        assert not (case / "prompt.md").exists(), (
            f"{case.name}: prompt.md cannot declare a scaffold_script; the case would run "
            f"against an empty working directory"
        )


@pytest.fixture(params=[c.name for c in CASES])
def case(request) -> Path:
    return EVALS / request.param


# ------------------------------------------------------------------ shape


def test_case_yaml_parses_and_is_named(case: Path):
    doc = load_case(case)
    assert doc.get("name") == case.name, f"{case.name}: case.yaml name must match the directory"
    assert doc.get("schema_version"), f"{case.name}: schema_version is required"


def test_case_has_a_prompt(case: Path):
    prompt = load_case(case).get("execution", {}).get("prompt", "")
    assert prompt.strip(), f"{case.name}: execution.prompt is empty"
    assert "TODO" not in prompt, f"{case.name}: prompt is still a scaffold TODO"


def test_case_runs_at_least_three_times(case: Path):
    runs = load_case(case).get("runs", 0)
    assert runs >= MIN_RUNS, f"{case.name}: runs={runs}; {MIN_RUNS} is the minimum for a rate"


def test_grader_types_are_valid(case: Path):
    for g in graders(case):
        assert g.get("type") in GRADER_TYPES, f"{case.name}: bad grader type {g.get('type')!r}"


def test_grader_names_are_unique(case: Path):
    names = [g.get("name") for g in graders(case)]
    assert len(names) == len(set(names)), f"{case.name}: duplicate grader names {names}"


def test_grader_scopes_are_valid(case: Path):
    """`target`/`focus` outside the enum fails at load and aborts the eval."""
    for g in graders(case):
        for key in ("target", "focus"):
            value = g.get(key)
            if value is None or isinstance(value, dict):
                continue
            assert value in GRADER_SCOPES, (
                f"{case.name}/{g.get('name')}: {key}={value!r} not in {sorted(GRADER_SCOPES)}"
            )


def test_llm_and_regex_use_the_right_scope_key(case: Path):
    for g in graders(case):
        if g.get("type") == "llm":
            assert "target" not in g, f"{g.get('name')}: llm graders use `focus`"
            assert g.get("criteria"), f"{g.get('name')}: llm grader has no criteria"
        if g.get("type") == "regex":
            assert "focus" not in g, f"{g.get('name')}: regex graders use `target`"
            assert g.get("pattern"), f"{g.get('name')}: regex grader has no pattern"


def test_regex_patterns_compile(case: Path):
    for g in graders(case):
        if g.get("type") == "regex":
            try:
                re.compile(g["pattern"])
            except re.error as exc:
                raise AssertionError(f"{g.get('name')}: pattern does not compile: {exc}") from exc


# ------------------------------------------------------------- invariants


def test_case_has_an_outcome_grader_not_only_tool_used(case: Path):
    types = [g.get("type") for g in graders(case)]
    assert types, f"{case.name}: zero graders"
    assert [t for t in types if t != "tool_used"], (
        f"{case.name}: only tool_used graders. A trigger check asks whether the plugin "
        f"fired, not whether it was right, so a run that fired and produced nonsense "
        f"scores full marks."
    )


def test_every_case_pairs_llm_with_deterministic(case: Path):
    """An LLM grader reads the transcript, so alone it passes a run that
    described doing the work instead of doing it."""
    types = [g.get("type") for g in graders(case)]
    if "llm" not in types:
        pytest.skip(f"{case.name} has no LLM grader to pair")
    assert any(t in DETERMINISTIC for t in types), (
        f"{case.name}: LLM grader with no deterministic pairing"
    )


def test_suite_has_a_should_not_fire_case():
    assert (EVALS / "should-not-fire").is_dir(), (
        "no should-NOT-fire case. Without one the eval cannot distinguish a plugin that "
        "helps from one that fires on everything."
    )


def test_should_not_fire_case_actually_allows_the_plugin_to_fire():
    """The negative case is vacuous if the tools are withheld."""
    allowed = load_case(EVALS / "should-not-fire").get("execution", {}).get("allowed_tools", [])
    for tool in ("Skill", "Workflow"):
        assert tool in allowed, (
            f"should-not-fire withholds {tool}, so the plugin could not have fired and the "
            f"case proves nothing"
        )


# `Workflow` refuses to dispatch unless the USER opted into multi-agent
# orchestration. Granting the tool is not opting in — the check is on the
# prompt, and these are the forms the tool's own policy accepts.
WORKFLOW_OPT_IN = re.compile(
    r"use a workflow|run a workflow|fan out|orchestrat\w* (this|it|with)|"
    r"multi-agent orchestration|subagents?\b",
    re.IGNORECASE,
)

# Naming the plugin, the skill or its workflows in a prompt hands the
# with-plugin arm an instruction the baseline arm cannot act on.
PLUGIN_NAMES = re.compile(
    r"fp.check|triage-static|triage-online|triage-poc|concept.prover", re.IGNORECASE
)


def test_every_prompt_opts_into_workflow_orchestration(case: Path):
    """Without an opt-in phrase in the prompt, the pipeline never runs at all.

    This is the defect that made the 2026-08-04 run measure the wrong thing. A
    `--keep-temp` probe of integration-cap was traced call by call: `Skill` was
    invoked, SKILL.md was read in full, and `Workflow` was never called once.
    The model declined, citing a standing instruction of no workflows unless
    asked. Two of the three graded runs said the same in their final answer.

    So every checkpoint gate, the five false-positive challenges and poc-lint
    contributed nothing to the +0.131 delta. The ablation compared
    SKILL.md-as-prose against no plugin.

    `--allow-tools Workflow` does not fix this and did not: the grant was in the
    command that produced that run. It is a policy refusal, not a permission
    denial. The tool exempts "the user invoked a skill whose instructions tell
    you to call Workflow", but here Claude activated the skill from its
    description — the prompt never named it, so autonomous activation is not
    user opt-in and the exemption does not fire.

    should-not-fire needs the phrase as much as the others, and for the same
    reason its `no-workflow-launched` grader needs it: that grader passed 3/3 in
    both arms only because Workflow was uncallable, not because the plugin
    correctly declined to fire.
    """
    prompt = load_case(case).get("execution", {}).get("prompt", "")
    assert WORKFLOW_OPT_IN.search(prompt), (
        f"{case.name}: the prompt does not opt into multi-agent orchestration, so the "
        f"Workflow tool will refuse to dispatch and the plugin's pipeline will not run. "
        f"The eval would still produce a delta — one that measures the skill's prose."
    )


def test_the_workflow_opt_in_is_plugin_neutral(case: Path):
    """The opt-in must be phrased so both ablation arms can act on it.

    The tempting fix for the test above is "use the fp-check skill and run its
    workflows". Both arms get the SAME prompt, and the baseline arm has no
    such skill — so that phrasing hands the with-plugin arm a usable instruction
    and the baseline an impossible one, inflating the delta by construction.
    That is the same defect as a grader that passes in only one arm for reasons
    unrelated to the plugin.

    Neutral phrasing keeps the comparison fair: both arms are allowed to
    orchestrate, both have `Workflow` in allowed_tools, and the plugin's
    advantage has to come from having a designed pipeline rather than from being
    the only arm permitted to fan out.
    """
    prompt = load_case(case).get("execution", {}).get("prompt", "")
    found = PLUGIN_NAMES.findall(prompt)
    assert not found, (
        f"{case.name}: the prompt names the plugin under test ({sorted(set(found))}). "
        f"Both arms receive this prompt and the baseline has no such skill, so it is "
        f"handicapped by an instruction it cannot follow and the delta is inflated."
    )


# The two stage questions, pinned per case. Each pattern matches the answer in a
# form BOTH ablation arms can act on: an instruction to build and run a PoC, or
# not to, is meaningful to a plain session as well as to this plugin.
#
# Six of the seven prompts open with "Write a PoC for this ...", which IS the
# PoC answer, stated the way a real request states it. An earlier draft of this
# table pinned five of them to `no`; that would have put a flat contradiction in
# the prompt, and a contradicted instruction measures neither configuration.
#
# It also makes the harder test. Stage 1 has to refuse to reach the PoC stage
# even though the user asked for one — which is precisely where the baseline
# fails: measured, every no-plugin run on two of these cases built a working
# exploit against the sink and reported a confirmed vulnerability. Cost is
# unaffected, because the PoC stage is gated on a TRUE_POSITIVE and five of the
# six never produce one.
POC_YES = re.compile(
    r"build (a|the) proof of concept|write (a|the|an) (poc|proof of concept|exploit)|prove it by",
    re.I,
)
POC_NO = re.compile(
    r"do not (build|want) a proof of concept|don'?t build a proof of concept|"
    r"do not write (a|an) (poc|exploit)|no proof of concept|"
    r"without (a|building a) proof of concept",
    re.I,
)
ONLINE_YES = re.compile(
    r"go online|check (their|the project'?s) (security )?(policy|advisories)|"
    r"look for duplicates|search upstream",
    re.I,
)
ONLINE_NO = re.compile(
    r"do not go online|don'?t go online|work offline|offline only|"
    r"from the code in front of you",
    re.I,
)


Answers = tuple["re.Match | None", "re.Match | None", "re.Match | None", "re.Match | None"]


def stage_answers(prompt: str) -> Answers:
    r"""(poc_yes, poc_no, online_yes, online_no) for a prompt.

    **The YES patterns are searched with the NO phrases removed first, and that is
    not tidiness.** Every one of the seven prompts says *"do not go online"*, and
    `ONLINE_YES` lists the bare alternative `go online` — which is a substring of
    it. So `ONLINE_YES.search()` matched all seven, in the wrong polarity, and
    the online half of `test_every_prompt_pins_both_stage_answers` was decided by
    a phrase that says the opposite of what the match reports. It never showed up
    because the assertion is `yes or no` and `ONLINE_NO` also matched: the test
    passed for the right reason by luck, while being unable to tell the two
    configurations apart. It also made the symmetric contradiction check
    impossible to add — it would have flagged all seven cases.

    `POC_YES` has the same latent shape one step further out: `POC_NO` contains
    `do not write (a|an) (poc|exploit)` and `POC_YES` contains
    `write (a|the|an) (poc|...|exploit)`, so a prompt phrased *"do not write a
    PoC"* would match BOTH and trip the contradiction assertion on a prompt that
    is not contradictory at all. No case is phrased that way today, which is the
    only reason it has not fired.

    This is the `not_contains` trap from tests/README.md in mirror form: a
    pattern for the presence of a claim, satisfied by its explicit negation.
    """
    poc_no, online_no = POC_NO.search(prompt), ONLINE_NO.search(prompt)
    positive = ONLINE_NO.sub(" ", POC_NO.sub(" ", prompt))
    return POC_YES.search(positive), poc_no, ONLINE_YES.search(positive), online_no


def test_every_prompt_pins_both_stage_answers(case: Path):
    """A prompt that pins neither answer measures Stage 1 and reports all three.

    This is the same failure class as the missing Workflow opt-in above, and it is
    harder to notice. `claude plugin eval` runs non-interactively, so there is
    nobody to answer an AskUserQuestion: the plugin either hangs until the timeout
    or falls through to its default. Both defaults are **no**. So a case that does
    not state the answers silently measures the static stage alone, the sweep
    reports a plausible delta, and nothing in the result says which stages ran.

    Pinning also makes a result attributable. Two toggles are four combinations;
    letting the model pick one means a case's score cannot be compared with the
    same case's score last week.

    Both patterns are checked, not just one: a prompt that says "build a PoC" and
    nothing about the network has pinned half a configuration.

    And both directions cannot be pinned at once. A prompt saying "write a PoC"
    and "do not build a proof of concept" has told the model two things, and
    whichever it follows the case is no longer measuring a known configuration —
    which is exactly what happened on the first attempt at this pinning.
    """
    prompt = load_case(case).get("execution", {}).get("prompt", "")
    yes, no, o_yes, o_no = stage_answers(prompt)
    assert not (yes and no), (
        f"{case.name}: the prompt both asks for a proof of concept ({yes.group(0)!r}) and "
        f"declines one ({no.group(0)!r}). Pick one; a contradicted instruction measures "
        f"neither configuration."
    )
    # The same assertion for the online toggle, which the broken ONLINE_YES made
    # unaddable: it matched the `go online` inside `do not go online`, so every
    # case looked contradictory. See stage_answers().
    assert not (o_yes and o_no), (
        f"{case.name}: the prompt both sends the run online ({o_yes.group(0)!r}) and keeps "
        f"it offline ({o_no.group(0)!r}). Pick one."
    )
    poc = yes or no
    online = o_yes or o_no
    assert poc, (
        f"{case.name}: the prompt does not say whether to build a PoC. Under a "
        f"non-interactive harness there is nobody to ask, so it falls through to the "
        f"default (no) and the case measures the static stage while reading as though "
        f"it measured the PoC stage too."
    )
    assert online, (
        f"{case.name}: the prompt does not say whether to run online checks. Same "
        f"failure as above: it falls through to the default (no) and the online stage "
        f"never runs in any graded run."
    )


def test_online_cases_are_tagged_and_pinned_consistently(case: Path):
    """The two suites must not silently merge into one mean.

    Stage 2 has never run in a graded run, and it cannot be measured by the seven
    static cases: their premise is synthetic code with no public record, and
    Stage 2's own rule is to stop when offline, so its correct behaviour there
    scores zero. The two numbers are therefore never mixed.

    Nothing enforced that. `claude plugin eval <plugin>` runs every case.yaml it
    finds, so adding an online case to evals/ silently changed what the documented
    sweep command measures — and the resulting mean would still have looked
    perfectly plausible, which is this suite's most expensive recurring failure.

    So the tag IS the separation, and it is held to the prompt: `--tag static`
    and `--tag online` select two disjoint suites, and a case whose tag disagrees
    with the answer its prompt pins fails here rather than in a $40 sweep.
    """
    doc = load_case(case)
    tags = set(doc.get("tags") or [])
    prompt = doc.get("execution", {}).get("prompt", "")
    _, _, online_yes, online_no = stage_answers(prompt)

    # Three disjoint suites, not two. `batch` is the third and holds the
    # multi-finding cases: a case whose prompt carries two findings cannot be
    # averaged with the single-finding seven, because its answer is a statement
    # about the pair and nothing in the static suite has one. It is offline, so
    # it is pinned the same way `static` is.
    suite = tags & {"static", "online", "batch"}
    assert len(suite) == 1, (
        f"{case.name}: tags {sorted(tags)} must carry exactly one of 'static', 'online' or "
        f"'batch'. Without it the case joins whichever sweep runs next and the mean stops "
        f"meaning anything."
    )
    if suite == {"online"}:
        assert online_yes and not online_no, (
            f"{case.name}: tagged 'online' but its prompt does not send the run online. "
            f"Stage 2 would never be dispatched and the case would measure the static "
            f"stage under a name that says otherwise."
        )
    else:
        assert online_no and not online_yes, (
            f"{case.name}: tagged 'static' but its prompt sends the run online. Stage 2 "
            f"fails closed without network access, so this either halts or measures "
            f"something the seven-case mean cannot be compared against."
        )


def test_both_suites_are_non_empty():
    """Zero guard for the split above.

    A tag filter that selects nothing exits green having run no case, which reads
    exactly like a passing sweep. Retiring either suite should be a deliberate
    deletion that fails here, not a quiet drift to zero.
    """
    by_tag = {"static": [], "online": [], "batch": []}
    for c in CASES:
        for tag in set(load_case(c).get("tags") or []) & by_tag.keys():
            by_tag[tag].append(c.name)
    for tag, names in by_tag.items():
        assert names, (
            f"no case is tagged '{tag}', so `--tag {tag}` selects nothing and reports a "
            f"clean run having measured nothing"
        )


def test_the_pinned_answers_are_plugin_neutral(case: Path):
    """The same rule as the orchestration opt-in, for the same reason.

    "Run Stage 3" or "dispatch triage-poc" hands the with-plugin arm an
    instruction the baseline cannot follow and inflates the delta by construction.
    "Build a proof of concept and run it" is something a plain session does too.

    PLUGIN_NAMES already covers the whole prompt, so this test exists to state the
    requirement where the pinning is authored, and to fail loudly if someone
    reaches for the stage names when a case stops behaving as they expect.
    """
    prompt = load_case(case).get("execution", {}).get("prompt", "")
    staged = re.findall(r"\bstage\s*[123]\b", prompt, re.IGNORECASE)
    assert not staged, (
        f"{case.name}: the prompt names {sorted(set(staged))}, which only the with-plugin "
        f"arm has stages for. Say what you want done — build a PoC, stay offline — not "
        f"which of this plugin's stages should do it."
    )


def test_at_least_one_case_pins_the_poc_stage_on():
    """Nothing else forces the expensive path to be measured at all.

    Every default is `no`, so a suite that pins `no PoC` everywhere is cheap,
    green, and never exercises the build, the five independent challenges, the
    confidence band or the severity cap in the report — more than half the
    plugin. That is not hypothetical: across seven cases and 42 runs the PoC and
    review phases ran in exactly one, and the confidence band never appeared in
    any final answer.
    """
    on = [
        c.name
        for c in CASES
        if stage_answers(load_case(c).get("execution", {}).get("prompt", ""))[0]
    ]
    assert on, (
        "no case asks for a PoC, so the build stage, the five challenges and the "
        "confidence band are unmeasured end to end however green the suite looks"
    )


# -------------------------------------------------------------- scaffolds


def test_case_declares_a_scaffold(case: Path):
    script = load_case(case).get("context", {}).get("scaffold_script")
    assert script, (
        f"{case.name}: no scaffold_script. The eval runs in an empty working directory, so "
        f"the case would have no target to analyse."
    )
    assert (case / script).is_file(), f"{case.name}: scaffold_script {script!r} does not exist"


def test_scaffold_script_is_a_path_not_a_body(case: Path):
    """`scaffold_script` is opened as a file; a script body fails ENAMETOOLONG."""
    script = load_case(case).get("context", {}).get("scaffold_script", "")
    assert "\n" not in script and len(script) < 256, (
        f"{case.name}: scaffold_script must be a path relative to the case dir, not the "
        f"script body (the harness open()s it: a body fails with ENAMETOOLONG)"
    )


def scaffold_env() -> dict[str, str]:
    """The environment a scaffold runs in: the caller's, minus every `GIT_*`.

    Two of the five scaffolds run `git init`, `git add -A`, `commit` and `tag`.
    `cwd` was redirected to a tmpdir but `env` was not, so an inherited `GIT_DIR`
    aimed that whole sequence at whichever repository owned it. Reproduced on
    git 2.48.1: the victim repository gained a commit deleting every tracked
    file, and an absolute `GIT_INDEX_FILE` left its index unreadable
    (`fatal: unable to read <oid>`).

    Scoped honestly: this is a latent hardening gap, not a live hazard for
    `make check`. Pre-commit hooks, `git rebase --exec` and `git bisect run` do
    **not** export `GIT_DIR` on 2.48.1, and the `GIT_INDEX_FILE` they do export
    is the relative `.git/index`, which resolves inside the tmpdir and is
    harmless. It is closed because it is one line and unambiguously correct.
    """
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def run_scaffold(case: Path, workdir: Path) -> subprocess.CompletedProcess:
    """Run a case's declared scaffold in `workdir`, isolated from the caller's git.

    `check=False` with an explicit returncode assertion at each call site, not
    `check=True`: a broken scaffold should fail carrying its stderr, not as a
    CalledProcessError with the reason swallowed.
    """
    script = (case / load_case(case)["context"]["scaffold_script"]).read_text()
    return subprocess.run(
        ["bash", "-s"],
        input=script,
        cwd=workdir,
        env=scaffold_env(),
        capture_output=True,
        text=True,
        check=False,
    )


def git_scaffold_cases() -> list[Path]:
    """Cases whose scaffold initialises a repository, so they could hijack one.

    Matched on `git ... init` rather than the literal `git init`: both scaffolds
    write `git -c init.defaultBranch=main init -q`, so the literal found nothing
    and parametrizing on it silently produced an empty set — which pytest
    reports as one SKIPPED test, not as a failure.
    """
    initialises = re.compile(r"^\s*git\b.*\binit\b", re.MULTILINE)
    found = []
    for case in CASES:
        script = load_case(case).get("context", {}).get("scaffold_script")
        if script and initialises.search((case / script).read_text()):
            found.append(case)
    return found


def scaffolded_files(case: Path) -> tuple[tuple[str, str], ...]:
    """The (target, fixture) pairs a case's scaffold must produce.

    KeyError rather than a default: a new case with no entry here is a case
    whose targets nothing compares against, and that must fail loudly.
    """
    pairs = SCAFFOLD_SOURCES[case.name]
    assert pairs, f"{case.name}: SCAFFOLD_SOURCES entry is empty; nothing would be checked"
    return pairs


def test_scaffold_fixture_matches_the_checked_in_copy(case: Path, tmp_path: Path):
    """The scaffold runs, writes every target, and each is byte-identical.

    The scaffold inlines the fixtures, so they can drift from evals/fixtures/.
    Layer 3's captures run against the checked-in copy and the eval runs against
    the inlined one. If they diverge the two layers silently test different code.

    Byte-identity subsumes existence, so this is one scaffold run rather than
    two.
    """
    proc = run_scaffold(case, tmp_path)
    assert proc.returncode == 0, f"{case.name}: scaffold failed: {proc.stderr}"
    for target, source in scaffolded_files(case):
        produced = tmp_path / target
        assert produced.is_file(), f"{case.name}: scaffold did not create {target}"
        assert produced.read_text() == (EVALS / source).read_text(), (
            f"{case.name}: the scaffold's inline copy of {target} has drifted from {source}. "
            f"The eval and the Layer 3 captures would be testing different code."
        )


def test_the_scaffold_writes_nothing_that_is_held_to_no_fixture(case: Path, tmp_path: Path):
    """The converse of the byte-identity check above, which nothing enforced.

    `SCAFFOLD_SOURCES`' own comment says "every file a scaffold writes belongs
    here, or it is a file nothing holds to the checked-in copy" — and the keys are
    asserted against the cases on disk, so a whole *case* cannot go unlisted. A
    single extra *file* could: add a fourth module to integration-cap's scaffold
    and forget the pair, and it is inlined in the scaffold, shipped to the eval,
    never compared against anything, and never scanned for a giveaway comment by
    test_target_does_not_state_its_own_verdict. Every other guard in this file
    reads `evals/fixtures/`, so a file that exists only inside a scaffold is
    outside all of them.

    Compared after the scaffold has finished, so `already-fixed` is judged on its
    HEAD tree — it deliberately writes the v1.4.0 copies first, commits them, then
    overwrites them, and only the final state is what the case is analysed against.
    """
    proc = run_scaffold(case, tmp_path)
    assert proc.returncode == 0, f"{case.name}: scaffold failed: {proc.stderr}"
    listed = {target for target, _ in scaffolded_files(case)}
    produced = {
        str(f.relative_to(tmp_path))
        for f in tmp_path.rglob("*")
        if f.is_file() and ".git/" not in str(f.relative_to(tmp_path))
    }
    assert produced, f"{case.name}: scaffold wrote no files at all"
    unheld = sorted(produced - listed)
    assert not unheld, (
        f"{case.name}: the scaffold writes {unheld}, which are in no SCAFFOLD_SOURCES pair. "
        f"Nothing holds them to a checked-in fixture and the verdict-giveaway scan never "
        f"sees them, because that scan reads evals/fixtures/."
    )


def test_prompt_refers_to_the_scaffolded_target(case: Path):
    """A repo-relative path in the prompt resolves to nothing in the scaffold dir."""
    doc = load_case(case)
    prompt = doc["execution"]["prompt"]
    targets = [target for target, _ in scaffolded_files(case)]
    assert any(target in prompt for target in targets), (
        f"{case.name}: prompt names none of the scaffolded files {targets}"
    )
    assert "plugins/fp-check/evals/fixtures" not in prompt, (
        f"{case.name}: prompt uses a repo-relative fixture path, which does not exist in the "
        f"eval's working directory"
    )


def _git(args: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    """git, run with the caller's own GIT_* stripped so the check is not fooled.

    `commit.gpgsign=false` because identity is pinned here but signing was not,
    so this inherited the developer's global config. On a machine with
    `commit.gpgsign=true` and an ssh signer behind 1Password, every commit here
    fails once the vault locks:

        error: 1Password: failed to fill whole buffer
        fatal: failed to write commit object

    That is exit 128 from `git commit`, which `check=True` surfaced as a bare
    CalledProcessError with the reason swallowed — it read as a flaky test, then
    as a real failure, and it is neither. All three committing scaffolds already
    pass this flag; only this helper had been missed. A throwaway victim
    repository has nothing to gain from a signature.
    """
    return subprocess.run(
        [
            "git",
            "-c",
            "user.name=T",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=cwd,
        env=scaffold_env(),
        capture_output=True,
        text=True,
        check=check,
    )


def test_at_least_one_scaffold_initialises_a_repository():
    """Zero guard for the parametrization below.

    If no scaffold ran `git init`, that test would collect nothing and report
    green while the `GIT_*` strip was enforced by nothing at all.
    """
    assert git_scaffold_cases(), (
        "no scaffold runs `git init`; test_a_scaffold_cannot_commit_into_an_inherited_"
        "repository collects zero cases and proves nothing"
    )


@pytest.mark.parametrize("case", git_scaffold_cases(), ids=lambda p: p.name)
def test_a_scaffold_cannot_commit_into_an_inherited_repository(
    case: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """`cwd` was redirected for the scaffold runner; `env` was not.

    Two scaffolds run `git init` / `add -A` / `commit` / `tag`. With `GIT_DIR`
    inherited from the caller, all of those operated on the caller's repository
    instead. Reproduced on git 2.48.1: the victim gained a commit deleting every
    tracked file, and an absolute `GIT_INDEX_FILE` left its index unreadable.

    The victim here is a throwaway repository under `tmp_path`, so the test can
    only damage its own fixture.
    """
    victim = tmp_path / "victim"
    victim.mkdir()
    _git(["-c", "init.defaultBranch=main", "init", "-q"], victim)
    (victim / "important.txt").write_text("do not delete me\n")
    _git(["add", "-A"], victim)
    _git(["commit", "-q", "-m", "victim baseline"], victim)
    before = _git(["rev-parse", "HEAD"], victim).stdout

    workdir = tmp_path / "work"
    workdir.mkdir()
    # Set on this process, so run_scaffold's strip is exercised rather than
    # described: scaffold_env() reads os.environ when it is called.
    monkeypatch.setenv("GIT_DIR", str(victim / ".git"))
    monkeypatch.setenv("GIT_INDEX_FILE", str(victim / ".git" / "index"))
    proc = run_scaffold(case, workdir)

    assert proc.returncode == 0, f"{case.name}: scaffold failed: {proc.stderr}"
    assert _git(["rev-parse", "HEAD"], victim).stdout == before, (
        f"{case.name}: the scaffold committed into the caller's repository"
    )
    tracked = _git(["ls-tree", "-r", "--name-only", "HEAD"], victim).stdout.split()
    assert tracked == ["important.txt"], (
        f"{case.name}: the caller's tree was rewritten to {tracked}"
    )
    assert not _git(["tag"], victim).stdout.strip(), f"{case.name}: the scaffold tagged the caller"

    # GIT_INDEX_FILE is the half the three assertions above cannot see. Measured
    # with only it inherited (no GIT_DIR): HEAD, the tree at HEAD and the tag
    # list were all untouched, and `git status` came back
    # `fatal: unable to read <oid>` — the scaffold had written its own blobs into
    # the victim's index, referring to objects the victim's store does not have.
    # check=False so that surfaces as this assertion rather than as a
    # CalledProcessError with the message buried.
    status = _git(["status", "--porcelain"], victim, check=False)
    assert status.returncode == 0 and status.stdout == "", (
        f"{case.name}: the caller's index or worktree was disturbed "
        f"(exit {status.returncode}): {status.stdout}{status.stderr}"
    )


# --------------------------------------------------------------------------
# A target that states its own verdict grades reading comprehension.
# --------------------------------------------------------------------------

# Every fixture the scaffolds materialise, deduplicated: two cases may
# legitimately share a target.
FIXTURE_SOURCES = sorted({source for pairs in SCAFFOLD_SOURCES.values() for _, source in pairs})

# Phrases that hand the model its answer. All three targets shipped with some of
# these. ledger.py opened "Minimal ledger with a genuine, reachable bug" — in the
# case whose whole point is that no security review should start. search.py cited
# "Checkpoint 2.2". handler.go stated "The correct write-up is a Low/Medium
# availability issue ... not a Critical DoS". A comment like that is the answer
# key: both ablation arms score it by reading rather than by analysis, which is
# the largest single reason the plugin measured no delta.
#
# Two groups, and the distinction is what keeps the list short:
#
#   1. The plugin's own machinery. A target naming checkpoints, layers or
#      challenges teaches the no-plugin arm the method the plugin exists to
#      supply — precisely what the ablation subtracts.
#   2. The verdict. Is the bug real, is the path reachable, what is the
#      severity: those are the three questions the cases ask. A target that
#      answers any of them in a comment has graded itself.
#
# Deliberately NOT on the list: a bare "LOOKS", which was the tell in search.py.
# Case-insensitively it also matches ordinary prose ("looks up the row"), and the
# sentence it belonged to — "LOOKS injectable but is not reachable" — is already
# caught by `reachable`. A marker that fires on normal comments gets suppressed,
# and a suppressed marker catches nothing.
GIVEAWAY_MARKERS = (
    # 1. the plugin's machinery
    r"\bcheckpoint\b",
    r"\bchallenge \d",
    r"\bfp-check\b",
    r"\bconcept-prover\b",
    r"\bvalidation layers?\b",
    r"\blayer \d\b",
    r"\bfalse positive\b",
    r"\bproof.of.concept\b",
    r"\bPoC\b",
    # 2. the verdict: real or not, reachable or not, and how bad
    r"\b(?:un)?reachable\b",
    r"\bexploitable\b",
    r"\bgenuine",
    r"\breal bug\b",
    r"\bnot a bug\b",
    r"\boverstat",
    r"\bcorrect write.?up\b",
    r"\bapparent sink\b",
    r"\bseverity\b",
    r"\bcritical\b",
    r"\blow/medium\b",
    r"\bdenial of service\b",
    r"\bDoS\b",
)

_GIVEAWAY_RE = [re.compile(p, re.IGNORECASE) for p in GIVEAWAY_MARKERS]


def giveaways(text: str) -> list[str]:
    r"""Every giveaway phrase in `text`, deduplicated and sorted.

    Scanned over the whole file rather than over extracted comments,
    deliberately: a comment extractor is one more thing that can silently stop
    matching, and every marker here is a prose phrase. The `\b` boundaries mean
    none of them fires on a snake_case or camelCase identifier (`is_reachable`,
    `dosLimiter`), so scanning the code as well costs nothing.
    """
    return sorted({m.group(0) for rx in _GIVEAWAY_RE for m in rx.finditer(text)})


# The three targets as they were before this guard existed, verbatim. A checker
# that has quietly stopped matching reports a clean repo forever; this one has to
# prove it still fires on the exact text it was written for.
PRE_GUARD_GIVEAWAYS = {
    "ledger.py": '"""Minimal ledger with a genuine, reachable bug.',
    "search.py": "Checkpoint 2.2 exists for exactly this shape. A reader that skims the layers",
    "handler.go": "// a Low/Medium availability issue for a single request, not a Critical DoS.",
}


def test_every_scaffolded_target_has_a_checked_in_fixture():
    """Zero guard: both scans below parametrize over FIXTURE_SOURCES.

    An empty list would collect no tests and report green, which is the failure
    mode this whole suite exists to avoid.
    """
    assert FIXTURE_SOURCES, "no scaffolded targets to scan; refusing to report success"
    missing = [s for s in FIXTURE_SOURCES if not (EVALS / s).is_file()]
    assert not missing, f"SCAFFOLD_SOURCES names fixtures that do not exist: {missing}"
    # A renamed or added case whose key never reaches SCAFFOLD_SOURCES has its
    # targets held to nothing, and every scan below silently stops covering it.
    assert set(SCAFFOLD_SOURCES) == {c.name for c in CASES}, (
        f"SCAFFOLD_SOURCES keys {sorted(SCAFFOLD_SOURCES)} do not match the cases on disk "
        f"{sorted(c.name for c in CASES)}"
    )


@pytest.mark.parametrize("source", FIXTURE_SOURCES)
def test_target_does_not_state_its_own_verdict(source: str):
    """A target that announces the answer is graded by reading, not by analysis.

    The comments in a target should be the ones a developer would have written:
    what the function does, why a check is there. They must not say whether the
    reported bug is real, what its severity is, or name anything belonging to
    this plugin — that is the conclusion the case is paying a model to reach.

    Only the checked-in copy is scanned. The scaffold's inlined copy is held
    byte-identical to it by test_scaffold_fixture_matches_the_checked_in_copy,
    so one scan covers both.
    """
    hits = giveaways((EVALS / source).read_text())
    assert not hits, (
        f"{source} states its own verdict or names this plugin's machinery: {hits}. "
        f"Both ablation arms then score the case by reading the comment, so the case "
        f"cannot separate them. Describe the code, not the finding."
    )


@pytest.mark.parametrize("target", sorted(PRE_GUARD_GIVEAWAYS))
def test_the_giveaway_scan_still_catches_what_it_was_written_for(target: str):
    assert giveaways(PRE_GUARD_GIVEAWAYS[target]), (
        f"the giveaway scan no longer flags the pre-fix {target} header, so it is "
        f"passing the fixtures vacuously: {PRE_GUARD_GIVEAWAYS[target]!r}"
    )


# ---------------------------------------------------- grader traps, paid for


def test_tool_used_max_zero_also_sets_min_zero(case: Path):
    """`min` defaults to 1, so `max: 0` alone is the impossible range 1..0.

    Cost a full eval run to find: the plugin correctly called Workflow zero
    times and the grader reported "Workflow called 0x (expected 1..0)" — a
    failure, in both arms, for the behaviour the case exists to reward.
    """
    for g in graders(case):
        if g.get("type") == "tool_used" and g.get("max") == 0:
            assert g.get("min") == 0, (
                f"{case.name}/{g.get('name')}: max=0 without min=0 asserts the range 1..0, "
                f"which nothing can satisfy"
            )


def test_not_contains_patterns_are_not_negatable_phrases(case: Path):
    """A `not_contains` on a phrase the correct answer must NAME always fails.

    "This is NOT a process crash" contains "process crash". The grader punished
    the right answer for refuting the claim explicitly. Assert the positive fact
    instead.
    """
    suspicious = re.compile(r"crash|vulnerab|exploit|denial of service", re.I)
    for g in graders(case):
        if g.get("type") == "regex" and g.get("match") == "not_contains":
            assert not suspicious.search(g.get("pattern", "")), (
                f"{case.name}/{g.get('name')}: not_contains on {g['pattern']!r} — a correct "
                f"answer that refutes this claim has to name it, so the grader fails the very "
                f"response it should reward. Assert the positive outcome instead."
            )


def test_cases_requiring_execution_declare_the_gated_tools(case: Path):
    """The plugin gates on executed output, which needs Bash and Write.

    `allowed_tools` in the case is not sufficient: Bash/Write/Edit are gated and
    need the operator's `--allow-tools` grant on the command line. Without it
    the with-plugin arm refuses to finish and the judge scores the refusal as a
    failure — which is what produced a negative ablation delta that measured the
    harness, not the plugin.
    """
    allowed = load_case(case).get("execution", {}).get("allowed_tools", [])
    if "Workflow" not in allowed:
        pytest.skip(f"{case.name} does not exercise the workflow pipeline")
    for tool in ("Bash", "Write"):
        assert tool in allowed, (
            f"{case.name}: declares Workflow but not {tool}; the PoC pipeline gates on "
            f"executed output and cannot finish without it"
        )


# --------------------------------------------------------------------------
# A grader that the scaffold alone satisfies measures nothing.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=lambda p: p.name)
def test_no_regex_grader_is_satisfied_by_the_scaffold_alone(case: Path):
    """A `target: trace` pattern that already matches the scaffolded source
    grades "did you open the file", not "did you reach the conclusion".

    Both regex graders in this suite were written that way and both passed 6/6
    across the with- and without-plugin arms of the one completed run,
    contributing exactly zero to the ablation delta:

      - cites-blocking-layer matched ALLOWED_TERM and _dispatch_search, which
        are literal identifiers in the scaffolded search.py
      - names-the-recovery matched conn.serve and "net/http ... recover", which
        were in handler.go's own header comment until that comment was removed
        for stating the case's verdict

    The trace carries tool results, so reading the target satisfied both. Over
    `last_message` the same patterns are real assertions about the answer.

    cites-blocking-layer is the one that still exercises this check: its
    identifiers are code, so they survive any comment rewrite. names-the-recovery
    no longer would, because nothing in handler.go names the recovery any more —
    which is the point of test_target_does_not_state_its_own_verdict.
    """
    # The DECLARED scaffold, not a hardcoded "scaffold.sh", and no skip. Every
    # case happens to name scaffold.sh today, so a hardcoded path worked — but a
    # case declaring any other filename would have silently skipped, retiring
    # the check that this test's own mutation (-k satisfied_by_the_scaffold)
    # depends on. test_case_declares_a_scaffold already asserts the file exists,
    # so there is nothing here a skip could legitimately cover.
    declared = load_case(case).get("context", {}).get("scaffold_script")
    assert declared, f"{case.name}: no scaffold_script declared"
    scaffold = case / declared
    assert scaffold.is_file(), f"{case.name}: declared scaffold {declared!r} does not exist"
    scaffold_text = scaffold.read_text()

    checked = 0
    vacuous = []
    for grader in graders(case):
        if grader.get("type") != "regex":
            continue
        if grader.get("target") != "trace":
            continue
        checked += 1
        flags = re.IGNORECASE if "i" in str(grader.get("flags", "")) else 0
        if re.search(grader["pattern"], scaffold_text, flags):
            vacuous.append(f"{grader.get('name')} ({grader['pattern']})")

    assert not vacuous, (
        f"{case.name}: regex grader(s) over the trace whose pattern already matches the "
        f"scaffolded target: {vacuous}. Reading the file satisfies them, so they pass in "
        f"both ablation arms and measure nothing. Target `last_message` instead, so the "
        f"assertion is about the conclusion rather than about which files were opened."
    )
    # `checked` is deliberately allowed to be zero: a suite whose regex graders
    # all target last_message has nothing to check here, which is the state this
    # test exists to push it into. The zero-item guard that matters is
    # test_every_case_pairs_llm_with_deterministic.


def grader_flags(grader: dict) -> int:
    return re.IGNORECASE if "i" in str(grader.get("flags", "")) else 0


def regex_graders() -> list[tuple[Path, dict]]:
    return [(c, g) for c in CASES for g in graders(c) if g.get("type") == "regex"]


@pytest.mark.parametrize("case", CASES, ids=lambda p: p.name)
def test_no_regex_grader_is_satisfied_by_the_prompt_alone(case: Path):
    """The `last_message` twin of the scaffold check above, and the live gap.

    That check only inspects `target: trace` graders, and every regex grader in
    this suite now targets `last_message` — so it inspects **zero graders** and is
    green by having nothing to look at. Its own comment says so and calls that the
    state it exists to push the suite into. Fine as far as it goes, but it leaves
    the equivalent trap uncovered: a pattern over the final answer that the
    *prompt* already contains grades whether the model echoed the brief.

    Nothing enforced it, and two case comments are entirely about it —
    integration-cap's records that `upstream` is deliberately absent because the
    prompt says "Unvalidated upstream value", and that `attacker` alone stays
    unmatched so "An attacker mints balance" cannot satisfy it. Both were reasoned
    out by hand and neither was checkable. The inflated-impact prompt is the
    sharpest case: it asserts "An attacker can crash the server process remotely",
    which is the exact claim its grader exists to see refuted.
    """
    prompt = load_case(case).get("execution", {}).get("prompt", "")
    assert prompt, f"{case.name}: no prompt"
    echoes = []
    for g in graders(case):
        # `not_contains` is inverted: a pattern the prompt contains punishes an
        # answer for restating the brief rather than rewarding it. Different
        # defect, and test_not_contains_patterns_are_not_negatable_phrases owns it.
        if g.get("type") != "regex" or g.get("match") == "not_contains":
            continue
        m = re.search(g["pattern"], prompt, grader_flags(g))
        if m:
            echoes.append(f"{g.get('name')} matches {m.group(0)!r} in the prompt")
    assert not echoes, (
        f"{case.name}: {echoes}. A run can satisfy that by restating the brief, so it "
        f"passes in both ablation arms and grades nothing about the conclusion."
    )


# --------------------------------------------------------------------------
# Every regex grader must be shown to accept a right answer and reject a wrong
# one. Nothing else in this suite can establish either half.
# --------------------------------------------------------------------------
#
# This exists because the two most expensive defects in this suite's history were
# both invisible to every check above:
#
#   - `downgrades-to-a-500` demanded a fact that is not true, so it could never
#     pass. 0/3 in both arms.
#   - its replacement, `downgrades-to-connection-scoped`, was fitted to five
#     recorded phrasings and failed 6/6 on the next two sweeps, capping the case
#     at 0.667 regardless of the answer.
#   - the two deleted `file_exists` graders could never fail. 6/6 in both arms.
#
# A regex compiles, has a valid target, and is absent from the prompt and the
# scaffold in all three of those cases. The only thing that separates a working
# grader from any of them is behaviour on text, so the text is checked in.
#
# `must_match` is real recorded model output from tests/fixtures/eval-result-*.json
# wherever one exists — the point is the phrasings the graders actually met, not
# phrasings invented to fit. `must_not_match` is a wrong verdict of the kind the
# case exists to catch, plus (where it bites) an answer that reaches the right
# conclusion without the evidence the grader requires.
GRADER_PROBES: dict[tuple[str, str], dict[str, tuple[str, ...]]] = {
    ("online-known-duplicate", "cites-the-published-advisory"): {
        "must_match": (
            "Do not file this. It is already public as GHSA-mf9w-mj56-hr94, fixed in 1.2.2.",
            "This is CVE-2026-28684 — reported in April and patched upstream.",
            # Lowercase, because `flags: i` is on the grader and a run that
            # writes the id in prose rather than as a heading is not wrong.
            "already reported: ghsa-mf9w-mj56-hr94",
        ),
        "must_not_match": (
            # The exact shape the case exists to catch: correct on the code,
            # confident, and it never went and looked. Everything here is
            # reachable by guessing that a popular library's bug is probably
            # known — which is why the bare words are not accepted.
            "Confirmed: rewrite() follows the symlink and shutil.move copies across "
            "filesystems. File it upstream.",
            "This looks like a known issue — it is probably already reported as a duplicate "
            "in the project's advisory database.",
            # A neighbouring identifier from the same project must not pass: the
            # grader has to key on THIS advisory, not on the shape of an id.
            "Reported upstream as GHSA-mf9w-mj56-0000.",
            "See CVE-2026-28685 for the related issue.",
        ),
    },
    ("already-fixed", "cites-the-fix"): {
        "must_match": (
            'Commit `99a4704` ("fix(auth): constant-time token comparison", PR #412, released '
            "as v1.4.1 on 2026-05-02 per `CHANGELOG.md`) introduced the HMAC-pepper wrapper.",
            "The CHANGELOG entry for 1.4.1 names #412 as the fix.",
        ),
        "must_not_match": (
            # The criteria call this a failure in as many words: asserting the
            # finding is fixed without naming the deciding evidence.
            "This is already fixed at HEAD — auth.py digests both operands before the "
            "comparison, so the timing oracle does not exist. Do not pay the bounty.",
            "Confirmed for v1.4.0 and still live at HEAD. Recommend paying the bounty.",
        ),
    },
    ("blocked-attack-path", "cites-blocking-layer"): {
        "must_match": (
            "Attacker input cannot reach run_query: the anchored allowlist ALLOWED_TERM in "
            "handle_search rejects every metacharacter injection needs.",
            "Blocked at search.py:14 and again at search.py:21.",
        ),
        "must_not_match": (
            # The measured baseline failure: a working PoC against the sink,
            # reached by calling it directly.
            "Confirmed SQL injection. poc_search_sqli.py calls run_query() directly with a "
            "UNION payload and dumps admin:5f4dcc3b from the seeded users table.",
            "The concatenation at search.py:28 is injectable, so I am reporting this as High.",
        ),
    },
    ("dead-route", "cites-the-missing-route"): {
        "must_match": (
            "app/router.py maps exactly two paths and render_pdf appears in neither; nothing "
            "in scope calls it.",
            "There is no route for /reports/render and no caller for render_pdf.",
        ),
        "must_not_match": (
            # All three measured baseline runs did exactly this.
            "Confirmed command injection: I invoked render_pdf({'source': 'x; touch "
            "/tmp/poc_evidence'}) and the file was created despite wkhtmltopdf being absent.",
            "The shell interpolation is real and unauthenticated. Severity High.",
        ),
    },
    ("wrong-parameter", "distinguishes-the-two-call-sites"): {
        "must_match": (
            "`host` flows into _run_argv, which hands subprocess.run a list, so no shell "
            "interprets it.",
            "The only shell=True call is refresh_tool_cache(), which takes no parameters.",
        ),
        "must_not_match": (
            "Confirmed RCE. POST /scan with host=';id' appends the attacker's own command to "
            "the subprocess call, which runs with shell=True.",
            "Reachable and unauthenticated; I am reporting it at a lowered severity of Medium.",
        ),
    },
    ("integration-cap", "credited-amount"): {
        "must_match": (
            "balance after:  12500 minor units",
            "a qty=125 order billed at rate=-1.00 minted 12500 minor units (+125.00 USD)",
        ),
        "must_not_match": (
            # Reasoned but never executed: the number can only come from running
            # or computing the attack, which is the whole point of the grader.
            "A negative rate inverts the debit into a credit of unbounded size. I did not "
            "execute the PoC, so this is source analysis only.",
            "charge() multiplies qty by the unvalidated rate and passes the result to "
            "ledger.debit, which subtracts it. Severity Critical.",
        ),
    },
    ("integration-cap", "names-the-integration-root-cause"): {
        "must_match": (
            # Recorded, 2026-08-06 with-plugin run 2. The old pattern failed it.
            "an internal dependency misbehaving or being compromised, not a value the "
            "attacker supplies directly through the order (`qty`)",
            # Recorded, 2026-08-04. The old pattern failed this too: emphasis.
            "the rate value is *not* attacker-reachable from the order path in this codebase",
            "there is no path from any attacker-supplied input to the malicious value",
            # capSeverity's own note, relayed. Accepted -- it attributes.
            "severity lowered from Critical to Medium: a integration root cause requires an "
            "external failure to trigger (checkpoints.md 2.4b)",
        ),
        "must_not_match": (
            # Recorded Critical verdicts. Each states the upstream precondition as
            # an ENABLING claim, which is not a root-cause attribution.
            "Any actor who can influence the rate service's response (compromise, MITM "
            "without TLS pinning, or a bug in that upstream service) can mint arbitrary "
            "balance for any user. Severity: Critical.",
            "Chain: upstream rate service (untrusted input) -> fetch_rate (no validation) -> "
            "charge -> ledger.debit -> attacker-controlled balance increase. Critical.",
            # A bare `integration` token was the whole first alternative of the old
            # pattern, and this is what that bought.
            "Verdict: Critical. I added an integration test that drives charge() end to end.",
            "Severity: Critical. fetch_rate pulls the rate from an HTTP response with no "
            "validation before it crosses the upstream trust boundary into the ledger path.",
            "Verdict: Critical. Nothing under test was modified; only the external "
            "dependency was faked, per your local-only scope.",
        ),
    },
    ("inflated-impact", "downgrades-to-connection-scoped"): {
        # The five recorded near-misses that made the old pattern fail 6/6, kept
        # verbatim. If a future edit reintroduces literal matching, these fail.
        "must_match": (
            "The server **process stays alive** (pid confirmed still running) and immediately "
            "serves a follow-up request correctly.",
            "and only *that one connection* is torn down",
            "So `GET /items?range=abc` will not crash the process.",
            "- The **process does not die**",
            "**the server process itself does not die**",
            "a single malformed request does **not** crash the whole process",
            "not a single-shot process kill",
            "the server kept accepting and correctly answering new requests",
            "a handler panic tears down that one connection and the accept loop keeps running",
        ),
        "must_not_match": (
            "An attacker can crash the server process remotely.",
            "Confirmed: the server keeps crashing. Severity Critical.",
            "The process crashes and the service goes down. Remote DoS confirmed.",
            "**Verdict: CONFIRMED.** A single malformed request panics parseRange and crashes "
            "the server process. The whole process dies and every client loses service.",
            "This is **not** a false positive: the attacker crashes the server process.",
            "Because nothing recovers the panic, the process does not survive a single "
            "malformed request and the whole server dies.",
            # `only ... connection` without a demonstrative is what the ATTACKER
            # needs, not what is damaged. A looser draft passed this.
            "The attacker needs only a single TCP connection to crash the server process.",
            "The process crash is not just theoretical: I reproduced it and the server died.",
        ),
    },
    ("chained-findings", "names-the-composition"): {
        "must_match": (
            "BUG-1 is not exploitable as reported: /admin/rotate is behind "
            'require_role(session, "admin") in dispatch(). Chained with BUG-2, which lets a '
            "caller present role=admin in the cookie, it becomes unauthenticated command "
            "execution.",
            "Taken together the two compose: the cookie-supplied role defeats the admin role "
            "check that is the only thing stopping the injection.",
            "The admin role check in app/router.py blocks BUG-1 on its own, but BUG-2 chains "
            "straight past it.",
        ),
        "must_not_match": (
            # The two failures the case measures, each of which is a correct
            # per-finding answer reported side by side with no connection made.
            "BUG-1: confirmed command injection in rotate_logs, severity Critical. BUG-2: "
            "confirmed privilege escalation in load_session, severity High. Both should be "
            "fixed.",
            "BUG-1 is a false positive: /admin/rotate requires the admin role and rotate_logs "
            "cannot be driven by an ordinary caller. BUG-2 is real and should be fixed.",
        ),
    },
    ("inflated-impact", "names-the-recovery"): {
        "must_match": (
            "Go's `net/http` server wraps every request in `conn.serve`'s deferred recover().",
            "net/http installs a per-connection recover",
        ),
        "must_not_match": (
            "The panic is unhandled, so it propagates out of the handler and kills the "
            "process. Severity Critical.",
            "The process survives, but I did not establish why.",
        ),
    },
}


def test_every_regex_grader_has_probes():
    """Zero guard. A new regex grader with no entry would be checked by nothing.

    Keyed on (case, grader) and compared against the graders on disk, so this
    fails on an addition, a rename and a deletion alike — the same reason
    SCAFFOLD_SOURCES' keys are compared against the case directories.
    """
    on_disk = {(c.name, g["name"]) for c, g in regex_graders()}
    assert on_disk, "no regex graders found; refusing to report success"
    assert set(GRADER_PROBES) == on_disk, (
        f"GRADER_PROBES does not cover the regex graders on disk.\n"
        f"  missing probes: {sorted(on_disk - set(GRADER_PROBES))}\n"
        f"  stale probes:   {sorted(set(GRADER_PROBES) - on_disk)}"
    )
    for key, probes in GRADER_PROBES.items():
        assert probes.get("must_match"), f"{key}: no must_match probe; cannot show it can pass"
        assert probes.get("must_not_match"), (
            f"{key}: no must_not_match probe; cannot show it can fail"
        )


@pytest.mark.parametrize(("case_name", "grader_name"), sorted(GRADER_PROBES), ids=lambda v: str(v))
def test_regex_graders_accept_the_right_answer_and_reject_the_wrong_one(
    case_name: str, grader_name: str
):
    grader = next(g for c, g in regex_graders() if c.name == case_name and g["name"] == grader_name)
    rx = re.compile(grader["pattern"], grader_flags(grader))
    probes = GRADER_PROBES[(case_name, grader_name)]

    missed = [p for p in probes["must_match"] if not rx.search(p)]
    assert not missed, (
        f"{case_name}/{grader_name} rejects an answer it must accept — this grader cannot "
        f"pass on real output: {missed}"
    )
    accepted = [
        f"{p!r} via {rx.search(p).group(0)!r}" for p in probes["must_not_match"] if rx.search(p)
    ]
    assert not accepted, (
        f"{case_name}/{grader_name} accepts an answer it must reject — this grader cannot "
        f"fail: {accepted}"
    )


def test_the_deterministic_weight_share_stays_meaningful(case: Path):
    """An LLM grader that carries almost all the weight is an LLM-only case.

    `test_every_case_pairs_llm_with_deterministic` only asks that a deterministic
    grader EXISTS; at weight 1 against an LLM grader at weight 9 it exists and
    decides nothing. The suite already reasons in these terms and nothing checked
    it: `cites-blocking-layer` was raised to weight 2 when the two `file_exists`
    graders were deleted, expressly "so the non-LLM share stays meaningful".

    One third, not one half: the `outcome` grader is the only thing that measures
    correctness and should dominate. This is a floor against it becoming the only
    thing that measures anything.
    """
    gs = graders(case)
    if not any(g.get("type") == "llm" for g in gs):
        pytest.skip(f"{case.name} has no LLM grader")
    total = sum(g.get("weight", 1) for g in gs)
    deterministic = sum(g.get("weight", 1) for g in gs if g.get("type") in DETERMINISTIC)
    assert total and deterministic / total >= 1 / 3, (
        f"{case.name}: deterministic graders carry {deterministic}/{total} of the weight. "
        f"Below a third the case is decided by the judge, and an LLM grader reads the "
        f"transcript, so it passes a run that described the work instead of doing it."
    )


def test_at_least_one_case_carries_an_llm_grader():
    """Closes a skip-to-green path in the pairing invariant.

    `test_every_case_pairs_llm_with_deterministic` skips a case with no LLM
    grader, so deleting every LLM grader would retire the check silently rather
    than failing. Same shape as the zero-item guards elsewhere in this suite.
    """
    assert CASES, "no eval cases found; refusing to report success"
    with_llm = [c.name for c in CASES if any(g.get("type") == "llm" for g in graders(c))]
    assert with_llm, (
        "no case declares an LLM grader, so test_every_case_pairs_llm_with_deterministic "
        "skips every case and enforces nothing"
    )


# --------------------------------------------------------------------------
# The documented eval command must grant every gated tool the cases declare.
# --------------------------------------------------------------------------

# Read-only tools that need no operator grant. Everything else a case declares
# is gated and must appear in `--allow-tools`, or it stays denied at runtime no
# matter what the case says.
UNGATED_TOOLS = {"Read", "Glob", "Grep"}

TESTS_README = Path(__file__).resolve().parent / "README.md"


def documented_allow_tools() -> set[str]:
    """The `--allow-tools` values from the eval command in tests/README.md."""
    text = TESTS_README.read_text()
    m = re.search(r"--allow-tools\s+([A-Za-z][\w ]*?)\s*\\", text)
    assert m, "tests/README.md documents no `--allow-tools` grant to check"
    return set(m.group(1).split())


def test_the_documented_eval_command_grants_every_tool_the_cases_need():
    """A gated tool missing from the grant silently voids the with-plugin arm.

    This is not hypothetical twice over. The recorded run in
    fixtures/eval-result-2026-07-30.json is invalid because `Bash` and `Write`
    were never granted, so the skill could not produce executed output. The fix
    for that then granted only `Bash Write` and would have voided the re-run the
    same way: `Workflow` is gated too, and without it the skill cannot dispatch
    a single phase — the with-plugin arm degrades to a plain session and the
    ablation delta measures nothing at all.

    Cheaper to fail here than to pay for another run that measures the harness.
    """
    granted = documented_allow_tools()
    needed: set[str] = set()
    for case in CASES:
        declared = load_case(case).get("execution", {}).get("allowed_tools", [])
        needed |= set(declared) - UNGATED_TOOLS
    assert needed, "no case declares a gated tool; refusing to report success"

    missing = sorted(needed - granted)
    assert not missing, (
        f"tests/README.md documents `--allow-tools {' '.join(sorted(granted))}` but the "
        f"cases declare {missing}, which are gated and stay denied without the operator "
        f"grant. A run made with this command would not measure the plugin."
    )
