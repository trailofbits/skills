"""The completeness sweep's class filter, exercised through node against the real file.

The sweep is the only pass that looks at a bug class the location partition left silent, and
it is credited with uniquely finding a missing free on an error path, a `(void)` cast hiding
an unchecked return, a clamp done at the wrong width and a state returning success. All four
classes carry no `evidence` grep — and only classes that carry one are put to the detect
phase, so gating the sweep on a detect citation made every one of them unreachable. This
file is what keeps the two facts consistent.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "c-review.js"

# Not `skipif`. These are the only tests that exercise workflows/c-review.js at all, and a
# suite of silent skips exits 0 — the zero-item pass AGENTS.md forbids. CI's ubuntu-latest
# image happens to ship node and nothing asserts it, so a skip would be load bearing by
# accident. Set C_REVIEW_ALLOW_NO_NODE=1 to opt out deliberately.
if shutil.which("node") is None:  # pragma: no cover - environment guard
    import os

    if os.environ.get("C_REVIEW_ALLOW_NO_NODE") == "1":
        pytestmark = pytest.mark.skip(reason="C_REVIEW_ALLOW_NO_NODE=1")
    else:
        pytest.fail(
            "node is not installed, so the workflow contract tests would all skip and this "
            "suite would pass having checked nothing. Install node, or set "
            "C_REVIEW_ALLOW_NO_NODE=1 to accept the gap deliberately.",
            pytrace=False,
        )


def _catalogue_and_filter() -> str:
    """The CLASSES literal plus the one-line sweep filter, as a runnable node prelude."""
    src = WORKFLOW.read_text(encoding="utf-8")
    start = src.index("const CLASSES = {")
    end = src.index("\n}\n", start)
    classes = src[start : end + 2]
    line = re.search(r"^const sweepCandidate = .*$", src, re.M)
    if line is None:
        pytest.fail("no `const sweepCandidate` in the workflow — the sweep filter moved")
    return classes + "\n" + line.group(0) + "\n"


def _probe(body: str):
    script = _catalogue_and_filter() + body
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def test_a_class_with_no_evidence_grep_is_sweep_eligible_with_no_citation():
    """Ungateable means always-candidate. Nothing else can ever put these classes in front
    of the sweep, because the detect phase is never asked about them."""
    result = _probe(
        "const evidenceById = new Map();"
        "const ids = Object.keys(CLASSES).filter((id) => !CLASSES[id].evidence);"
        "console.log(JSON.stringify({"
        "  total: ids.length,"
        "  eligible: ids.filter(sweepCandidate).length,"
        "}));"
    )
    # A catalogue where every class carried a grep would make this test vacuous.
    assert result["total"] >= 15, "no ungateable classes left — this test now proves nothing"
    assert result["eligible"] == result["total"]


@pytest.mark.parametrize(
    "class_id", ["memory-leak", "error-handling", "integer-overflow", "logic-flaw"]
)
def test_the_classes_the_sweep_uniquely_found_are_reachable(class_id):
    """The four the workflow's own comment credits the sweep with. Gate the sweep on a
    detect citation and every one of them becomes unreachable."""
    result = _probe(
        f"const id = {json.dumps(class_id)};"
        "const evidenceById = new Map();"
        "console.log(JSON.stringify({known: id in CLASSES, eligible: sweepCandidate(id)}));"
    )
    assert result["known"], f"{class_id} is not in the catalogue"
    assert result["eligible"]


def test_a_gateable_class_still_needs_its_citation():
    """The gate is not removed, only narrowed to the classes it can actually decide: a class
    with a grep and no candidate site costs an agent that finds nothing."""
    result = _probe(
        "const id = Object.keys(CLASSES).find((k) => CLASSES[k].evidence);"
        "const empty = new Map();"
        "const cited = new Map([[id, 'src/x.c:1']]);"
        "let evidenceById = empty;"
        "const without = sweepCandidate(id);"
        "evidenceById = cited;"
        "console.log(JSON.stringify({id: id, without: without, with: sweepCandidate(id)}));"
    )
    assert result["id"], "no gateable class in the catalogue — the gate has nothing to gate"
    assert result["without"] is False
    assert result["with"] is True


# ------------------------------------------------- the platform and threat-model gate


def _select_groups(detect: dict, threat_model: str):
    """The real `selectGroups` and `GROUPS`, run through node against a detect answer."""
    src = WORKFLOW.read_text(encoding="utf-8")
    blocks = []
    for header in ("const CLASSES = {", "const GROUPS = [", "function selectGroups(detect) {"):
        start = src.find(header)
        assert start >= 0, f"{header!r} is not in the workflow"
        end = src.find("\n]\n" if header.endswith("[") else "\n}\n", start)
        blocks.append(src[start : end + 3])
    script = (
        f"const THREAT_MODEL = {json.dumps(threat_model)};\n"
        + "\n".join(blocks)
        + f"\nconsole.log(JSON.stringify(selectGroups({json.dumps(detect)})));"
    )
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


ISO_C = {"is_cpp": False, "is_posix": False, "is_windows": False}


@pytest.mark.parametrize("class_id", ["qsort", "signal-handler", "envvar"])
def test_iso_c_classes_are_not_gated_behind_is_posix(class_id):
    """`qsort`/`bsearch`, `signal()` and `getenv` are all <stdlib.h>/<signal.h>, not POSIX.

    Gated on `is_posix`, the CVE-2023-6246 comparator shape was structurally absent from
    every pure-libc review — and because `ruledOut` and `stillSilent` are computed from
    `selected`, it appeared in no coverage list either.
    """
    live = {
        cid
        for entry in _select_groups(ISO_C, "LOCAL_UNPRIVILEGED")["selected"]
        for cid in entry["classIds"]
    }
    assert class_id in live


def test_a_class_the_platform_gate_drops_is_reported_rather_than_vanishing():
    """A third coverage story: not silent, not ruled out — never looked at."""
    result = _select_groups(ISO_C, "REMOTE")
    live = {cid for entry in result["selected"] for cid in entry["classIds"]}
    assert result["dropped"], "nothing is platform-gated any more; this test proves nothing"
    for entry in result["dropped"]:
        assert entry.split(" ")[0] not in live
    assert any("POSIX" in e for e in result["dropped"])
    posix = _select_groups({**ISO_C, "is_posix": True}, "REMOTE")["dropped"]
    assert any(e.startswith("privilege-drop ") and "REMOTE" in e for e in posix)


# ------------------------------------------------ producer failure containment


def test_every_dispatched_agent_await_has_a_catch():
    """One unhandled rejection propagates out of the module and destroys the whole run.

    The dedup agent is the worst place to miss one, because its part file is `--expect`ed:
    a rejection there discards every completed slice AND the assemble phase, after all the
    review work has been paid for.
    """
    # PER DISPATCH, not two global counts. `\bagent\(\n` requires a newline immediately
    # after the paren, and comparing totals lets a 7th single-line `await agent({…})` with
    # no `.catch` sit beside a 7th `.catch` somewhere else entirely and keep the test green.
    src = re.sub(r"//[^\n]*", "", WORKFLOW.read_text(encoding="utf-8"))
    unguarded = []
    dispatches = 0
    for match in re.finditer(r"(?<![\w.])agent\(", src):
        before = src[: match.start()].rstrip()
        if before.endswith(("'", '"', "`")):
            continue  # the word inside a log string, not a call
        dispatches += 1
        depth = 0
        i = match.end() - 1
        while i < len(src):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if not src[i + 1 :].lstrip().startswith(".catch("):
            unguarded.append(src[: match.end()].splitlines()[-1].strip())
    assert dispatches >= 5, f"only {dispatches} agent dispatches found; the pattern moved"
    assert unguarded == [], f"{len(unguarded)} dispatch(es) with no .catch: {unguarded}"


def test_the_failed_group_list_is_the_groups_the_sweep_was_given():
    """`groupsAttempted.slice()` marks every live group failed when the sweep dies.

    The sweep is only ever given `silentByGroup`, so REPORT.md then prints "their classes are
    uncovered" — and SARIF emits one warning apiece — for groups whose classes were fully
    reviewed and produced findings.
    """
    src = WORKFLOW.read_text(encoding="utf-8")
    line = re.search(r"^const groupsFailed = .*$", src, re.M)
    assert line, "no `const groupsFailed` in the workflow"
    assert "groupsAttempted" not in line.group(0), line.group(0)
    assert "silentByGroup" in line.group(0), line.group(0)


def _js_function(name: str) -> str:
    src = WORKFLOW.read_text(encoding="utf-8")
    start = src.index("function " + name + "(")
    return src[start : src.index("\n}\n", start) + 2]


def test_a_prototype_chain_name_is_not_a_bug_class():
    """`CLASSES[raw.bug_class]` resolves `constructor`, `toString` and `__proto__` to a
    Function off Object.prototype, so all three pass as real bug classes here while
    assemble_findings.py — a real membership test — maps them to `logic-flaw`. The two sides
    then bucket the same finding differently in `tier1` and `crossClassTooFar`, and the
    workflow's `stats.primaries` disagrees with findings.json."""
    src = WORKFLOW.read_text(encoding="utf-8")
    start = src.index("const CLASSES = {")
    classes = src[start : src.index("\n}\n", start) + 2]
    script = (
        classes
        + "\n"
        + _js_function("knownClass")
        + "\n"
        + "console.log(JSON.stringify(['constructor', 'toString', '__proto__', 'hasOwnProperty',"
        " 'buffer-overflow'].map(knownClass)))"
    )
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout
    assert json.loads(out) == [False, False, False, False, True]


def test_the_class_sweep_records_the_class_a_finding_is_actually_filed_under():
    """`recordClasses` and `normalizeFinding` have to apply the SAME rule.

    `normClassId` slug-folds, so `"Buffer Overflow"`, `"format_string"` and
    `"use after free"` would mark three classes covered and skip all three in the sweep —
    while `normalizeFinding` and `assemble_findings.normalize_finding` both require a
    byte-exact catalogue match and file all three as `logic-flaw`. No artifact then holds a
    buffer-overflow, format-string or use-after-free finding; `stillSilent` omits them (they
    were never in `silentByGroup`) and so do `ruledOutClasses` and `platformDroppedClasses`.
    Three classes with zero coverage and no coverage story in any of the four fields the
    skill reports separately."""
    src = WORKFLOW.read_text(encoding="utf-8")
    body = src[src.index("function recordClasses(") : src.index("recordClasses(reviewResults)")]
    assert "normClassId(" not in body, body
    assert "knownClass(f && f.bug_class) ? f.bug_class : 'logic-flaw'" in body, body
    # The rule it has to agree with, in the function that decides what findings.json says.
    norm = src[src.index("function normalizeFinding(") : src.index("// Must match `_election_key`")]
    assert "knownClass(raw.bug_class) ? raw.bug_class : 'logic-flaw'" in norm, norm
    # A class whose only finding was never written to disk is still SILENT: the finding is
    # in no artifact, so recording it removed the run's only use-after-free from the sweep
    # AND from `stillSilent`, leaving no coverage story anywhere that said so.
    assert "part_written === false) continue" in body, body
    # And both producer sets go through it.
    assert "recordClasses(reviewResults)" in src and "recordClasses(sweepResults)" in src


def test_duplicate_and_over_budget_assignment_ids_are_refused():
    """The charset is not enough on its own. Two agents given one id write the same part
    path, so one agent's entire output is overwritten; `normalizeFinding` then keys two
    different findings identically; and the two `--expect <id>=N` operands disagree, which
    fails the assembler with exit 2 and NO artifacts for the whole run. The count is
    model-controlled too, so it needs a cap before it reaches `parallel`."""
    src = WORKFLOW.read_text(encoding="utf-8")
    guard = src[src.index("const malformedIds =") : src.index("const assignments =")]
    assert "new Set(assignmentIds).size !== assignmentIds.length" in guard
    assert "assignmentIds.length > AGENT_MAX" in guard
    # And the cap is passed to the enumerator, so the two cannot disagree.
    assert "' --agent-max ' + AGENT_MAX" in src


def test_the_workflow_re_elects_the_dedup_primary_the_way_the_assembler_does():
    """`assemble_findings.apply_agent_merges` re-elects with `_election_key`, so taking the
    agent's nomination verbatim here makes the run log and `stats.primaries` say one finding
    survived while findings.json and REPORT.md say the other did."""
    src = WORKFLOW.read_text(encoding="utf-8")
    block = src[
        src.index("for (const merge of asArray(res && res.merges)") : src.index("const primaries =")
    ]
    assert "pickPrimary(primary, byKey.get(dup))" in block
    assert "mergedInto.set(dup, merge.primary)" not in block


def test_a_part_its_own_agent_says_it_did_not_write_is_still_counted():
    """`part_written: false` must not be an agent-controlled switch that turns off the only
    check on that part's contents while the file, if present, is still read in full: a
    reviewer could otherwise summarise 12 findings down to 3, set the flag, and ship 3 with
    nothing comparing them against the 12 it returned. The expectation is pushed either way,
    and `--agent-failure` is what stops a genuinely missing file from failing the whole run —
    see test_assemble_findings for that half."""
    src = WORKFLOW.read_text(encoding="utf-8")
    loop = src.index("const producers = [...reviewResults")
    block = src[
        src.index("if (entry.result.part_written === false)", loop) : src.index(
            "partsExpected.push(entry.partId + '='", loop
        )
    ]
    assert "continue" not in block, block
    assert "agentFailures.push(entry.partId + ': did not write its part file')" in block
    # And the assembler is told, so the missing file is expected rather than fatal.
    assert "'--agent-failure ' + shq(f)" in src


def test_the_dedup_honesty_guard_is_built_from_what_the_agent_was_shown():
    """`bucketOf` has to be built from `sent`, which is what reaches the prompt, not from
    every bucket.

    Keys are `<partId>#<index>` and so are guessable, and `assemble_findings.py` applies the
    identical bucket rule to the part file — so a merge over findings that were capped away
    and never shown is accepted by both sides, and a real finding is dropped from REPORT.md
    on a hallucinated merge."""
    src = WORKFLOW.read_text(encoding="utf-8")
    block = src[
        src.index("const bucketOf = new Map()") : src.index("for (const merge of asArray(res")
    ]
    assert "for (const f of sent[b]) bucketOf.set(f.key, b)" in block, block
    assert "buckets[b]) bucketOf.set" not in block, block


def test_the_assemble_prompt_asks_for_coverage_on_a_rejection_too():
    """The assembler prints its JSON summary and THEN returns 1, so the counts exist on a
    rejection — which is exactly when coverage matters. Asking for them only "on success"
    makes a run with 400 of 445 satisfied come back as `coverage: null`, and SKILL.md then
    instructs the model to report coverage as unmeasured."""
    src = WORKFLOW.read_text(encoding="utf-8")
    block = src[
        src.index("'It also runs the coverage gate in-process") : src.index(
            "].join('\\n')", src.index("'It also runs the coverage gate in-process")
        )
    ]
    assert "WHATEVER the exit" in block, block
    assert "On success, copy the counts" not in block, block


# ------------------------------------------------------ the producing agents' tool scope


AGENT_FILE = WORKFLOW.parents[1] / "agents" / "c-review-worker.md"


def _opts_calls() -> list[tuple[str, str]]:
    """(opts builder, label expression) for every `agent(` dispatch in the workflow.

    DERIVED, not listed: a list of literal labels misses a producing dispatch added later
    through `workerOpts` with no tool scope, and misses a builder swapped on any dispatch the
    list does not name.
    """
    src = re.sub(r"//[^\n]*", "", WORKFLOW.read_text(encoding="utf-8"))
    out = []
    for match in re.finditer(r"(?<![\w.])agent\(", src):
        before = src[: match.start()].rstrip()
        if before.endswith(("'", '"', "`")):
            continue  # the word inside a log string, not a call
        depth, i = 0, match.end() - 1
        while i < len(src):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = src[match.end() : i]
        builder = re.search(r"(\w+Opts)\(", body)
        label = re.search(r"label:\s*([^,\n]+)", body)
        assert builder and label, body
        out.append((builder.group(1), label.group(1).strip()))
    return out


def test_every_producing_agent_is_dispatched_through_the_scoped_agent_type():
    """The only control that closes the two documented bypasses.

    `agent()` has no `allowedTools`; `agentType` resolves to an agent definition whose
    `tools:` frontmatter scopes the subagent, and an unresolvable one throws. A producing
    worker must not have Bash.

    Exactly two dispatches are exempt and both are named here: `detect` and `assemble` each
    run a command, so a shell is what they are for. They are trusted, not controlled, and
    that is stated where the reader is rather than implied by their absence.
    """
    assert AGENT_FILE.is_file(), "the agent definition the workflow names does not exist"
    front = AGENT_FILE.read_text(encoding="utf-8").split("---")[1]
    tools = [t.strip() for t in front.split("tools:")[1].splitlines()[0].split(",")]
    assert sorted(tools) == ["Glob", "Grep", "Read", "Write"], tools
    assert "name: c-review-worker" in front

    calls = _opts_calls()
    assert len(calls) >= 5, f"only {len(calls)} dispatches found; the pattern moved"
    unscoped = sorted(label for builder, label in calls if builder != "producingOpts")
    assert unscoped == ["'assemble'", "'detect'"], (
        f"{unscoped} is dispatched without the producing tool scope. Add it to this list "
        f"only with a reason a reader can check."
    )
    src = WORKFLOW.read_text(encoding="utf-8")
    assert "const WORKER_AGENT = 'c-review:c-review-worker'" in src


def test_the_agent_type_control_cannot_be_overridden_by_a_caller():
    """`Object.assign({agentType: WORKER_AGENT}, extra)` lets the CALLER win.

    The CLI's dispatch is guarded by `if (opts?.agentType != null)`, so an explicit
    `agentType: undefined` on one call skips the scoping block entirely and that subagent
    inherits every tool, Bash included — the control failing OPEN. Run through the real
    function rather than asserting on its text, which a prefix check survives.
    """
    src = WORKFLOW.read_text(encoding="utf-8")
    prelude = (
        "const WORKER_MODEL = null\n"
        + src[src.index("function workerOpts(") : src.index("function died(")]
    )
    for extra in (
        "{label: 'x'}",
        "{label: 'x', agentType: undefined}",
        "{label: 'x', agentType: null}",
        "{label: 'x', agentType: 'anything-else'}",
    ):
        got = _js_eval(prelude, "producingOpts(" + extra + ")")
        assert got.get("agentType") == "c-review:c-review-worker", (extra, got)


def test_no_producing_prompt_names_the_derivation_it_denies():
    """Anti-cheat text that describes the cheat is worse than none.

    Scanning only the workflow leaves the worker's SYSTEM prompt in
    `agents/c-review-worker.md` — the highest-salience text it sees — one file past where
    the check looks, so the sentence can simply move there. Both files are scanned.
    """
    shared = (
        "there is nothing to find",
        "You find\nthem the same way",
        "the gate reparses the source",
        "recomputed from the source when the gate runs",
        "sites_by_id",
        "One shell command",
        "re-running the enumerator",
    )
    # The agent file is a SYSTEM prompt and holds no schema, so it may not name the gate's
    # own vocabulary at all; the workflow legitimately carries `checks_required` in
    # ASSEMBLE_SCHEMA.
    for path, phrases in ((WORKFLOW, shared), (AGENT_FILE, shared + ("checks_required",))):
        src = re.sub(r"//[^\n]*", "", path.read_text(encoding="utf-8"))
        for phrase in phrases:
            assert phrase not in src, f"{path.name}: {phrase}"


# --------------------------------------------------------------- argument handling


def _js_eval(prelude: str, expr: str):
    out = subprocess.run(
        ["node", "-e", prelude + "\nconsole.log(JSON.stringify(" + expr + "))"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return json.loads(out)


NORMALISER_SPELLINGS = (
    "src/a.c",
    "a.c",
    "/proj/src/a.c",
    "/proj/src/./a.c",
    "src/x/../a.c",
    "[src/a.c](src/a.c)",
    "src//a.c",
    "./src/a.c",
    "./src/./a.c",
    "./a.c",
    "../a.c",
    "/other/a.c",
    "",
)


@pytest.mark.parametrize(
    ("scope", "scope_abs"),
    [
        # The configuration a real run uses: `findingScopeRoot` is documented as
        # REPO-RELATIVE, and it is the one the old pin (`SCOPE = '/proj'`) could not see,
        # because an absolute scope root is the single case in which stripping only one
        # spelling happens to agree with stripping both.
        ("src", "/proj/src"),
        (".", "/proj"),
        ("src", ""),  # the skill did not resolve it: both sides must degrade the same way
        ("/proj/src", "/proj/src"),
    ],
)
def test_the_workflow_path_normaliser_matches_the_assemblers(scope, scope_abs):
    """Same input, same two roots, same output — checked against the REAL `normalize_path`
    rather than against a hand-written expectation, because the two implementations drifting
    apart is the whole failure mode.

    `normalizePath` used to strip `SCOPE` exactly as the caller passed it while `main()`
    handed the assembler `str(Path(ns.scope).resolve())`, so with `findingScopeRoot: 'src'`
    reviewer A's `src/a.c` and reviewer B's `a.c` were one file here and two in findings.json:
    `collisionBuckets` groups by file, `tier1` merged the pair and reported
    `stats.primaries: 1` over a REPORT.md holding 2.
    """
    import assemble_findings

    roots = tuple(dict.fromkeys(r for r in (scope_abs, scope) if r))
    prelude = (
        "const SCOPE = " + json.dumps(scope) + ";\n"
        "const SCOPE_ABS = "
        + json.dumps(scope_abs)
        + ";\n"
        + _js_function("normalizePath")
        + _js_function("foldSegments")
    )
    for raw in NORMALISER_SPELLINGS:
        js = _js_eval(prelude, "normalizePath(" + json.dumps(raw) + ")")
        py = assemble_findings.normalize_path(raw, roots)
        assert js == py, (scope, scope_abs, raw, js, py)


def test_the_normaliser_folds_every_spelling_of_one_file_under_a_relative_scope_root():
    """The equivalence test above passes if BOTH sides are broken identically, so pin the
    values too: under `findingScopeRoot: 'src'` all three spellings a reviewer can reach for
    — the unit id (`enumerate_units --root src` names units relative to `src`), the path it
    read through `contextRoots: '.'`, and the absolute one a tool printed — are one file.

    Both sides are pinned here, not just the JS: this is the only test that would notice the
    two agreeing on a wrong value."""
    import assemble_findings

    prelude = (
        "const SCOPE = 'src';\nconst SCOPE_ABS = '/proj/src';\n"
        + _js_function("normalizePath")
        + _js_function("foldSegments")
    )
    for raw in (
        "a.c",
        "src/a.c",
        "/proj/src/a.c",
        "[src/a.c](src/a.c)",
        "src//a.c",
        # `./src/a.c` needs the `.` folded BEFORE the root is stripped. Stripping first
        # leaves the `./` on the front, nothing matches a root of `src` or `/proj/src`, and
        # this one spelling lands on `src/a.c` while every sibling lands on `a.c`.
        "./src/a.c",
        "./src/./a.c",
        "/proj/src/../src/a.c",
    ):
        assert _js_eval(prelude, "normalizePath(" + json.dumps(raw) + ")") == "a.c", raw
        assert assemble_findings.normalize_path(raw, ("/proj/src", "src")) == "a.c", raw


def test_a_required_arg_of_the_wrong_type_throws_instead_of_stringifying():
    """`REQUIRED_ARGS` checks truthiness only, so with a bare `String()` behind it
    `outputDir: {a: 1}` reaches every command as the literal `[object Object]`,
    `contextRoots: ['a','b']` as `a,b`, and `findingScopeRoot: {}` as a `--scope` nothing
    starts with — which turns off `normalize_path`'s containment silently and leaves every
    absolute-path finding absolute."""
    src = WORKFLOW.read_text(encoding="utf-8")
    prelude = "const ARGS = {outputDir: {a: 1}, contextRoots: ['a','b']};\n" + _js_function("text")
    for key in ("outputDir", "contextRoots"):
        script = prelude + "\ntry { text(" + json.dumps(key) + "); console.log('\"no throw\"') }"
        script += " catch (e) { console.log(JSON.stringify(e.message)) }"
        message = json.loads(
            subprocess.run(
                ["node", "-e", script], capture_output=True, text=True, check=True
            ).stdout
        )
        assert "must be a string" in message, (key, message)
    # And every one of them is read through it, not through `String(ARGS.…)`.
    assert "String(ARGS." not in src, src[
        src.index("const OUTPUT_DIR") : src.index("if (!['REMOTE'")
    ]


def test_a_truthy_non_array_findings_return_does_not_take_the_module_down():
    """`x || []` accepts any truthy non-iterable, so `findings: {a: 1}` throws
    `findings.forEach is not a function` out of the module — after every review agent has
    been paid for and before the assemble phase runs, discarding the whole run. `asArray` is
    this side's `_seq`."""
    prelude = _js_function("asArray")
    for raw in ("{a: 1}", "'nine'", "5", "null"):
        assert _js_eval(prelude, "asArray(" + raw + ")") == []
    assert _js_eval(prelude, "asArray([1, 2])") == [1, 2]
    # DERIVED, not a list of spellings. Naming `entry.result.findings || []` and
    # `(res && res.merges) || []` as literal strings leaves
    # `(merge && merge.duplicates) || []` — three lines below the second — invisible, and a
    # non-array there throws out of top-level module code AFTER every agent has been paid
    # for. `asArray` is the only way to read a list this workflow did not build itself, so
    # `|| []` must not appear at all outside a comment.
    src = re.sub(r"//[^\n]*", "", WORKFLOW.read_text(encoding="utf-8"))
    survivors = re.findall(r"[^\n]*\|\|\s*\[\][^\n]*", src)
    assert survivors == [], survivors
    # And the scan can still see one, so it is not passing by matching nothing.
    assert re.findall(r"[^\n]*\|\|\s*\[\][^\n]*", "const x = (a && a.b) || []")


def test_the_agent_counts_report_agents_that_came_back():
    """Count the assignments and 8 of them with 3 returning nothing reads as
    `review_agents: 8`, `agents_total: 12`, with the truth only in `agentFailures` — a
    separate field a reader may never correlate with the headline. `dedupAgents` has the
    same shape one level down: assigned before the `await`, a dedup agent that returned
    nothing still counts."""
    src = WORKFLOW.read_text(encoding="utf-8")
    stats = src[src.index("  stats: {") : src.index("  coverage: checksRequired")]
    assert "review_agents: reviewResults.filter((e) => e && e.result).length" in stats, stats
    assert "review_agents: assignments.length" not in stats, stats
    assert "sweep_agents: sweepThunks.length" not in stats, stats
    # And the dedup count is only taken once the agent has actually returned.
    dedup = src[src.index("    const res = await agent(") : src.index("const primaries =")]
    assert "if (res) dedupAgents = 1" in dedup, dedup


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
