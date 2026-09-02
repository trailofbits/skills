"""Layer 1: static contract tests for the fp-check dynamic workflows.

No model, no cost, runs in CI. Every assertion here is about the shipped script
text, not about anything Claude produced.

Run:
    uv run --with pytest --with jsonschema --no-project \
        pytest plugins/fp-check/tests/test_workflow_contract.py
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

WORKFLOW_DIR = Path(__file__).resolve().parents[1] / "workflows"
SCRIPTS = sorted(WORKFLOW_DIR.glob("*.js"))

# The plugin's declared name, used to check the namespaced command form.
PLUGIN_NAME = "fp-check"


# --------------------------------------------------------------------------
# Zero-item guard. A checker that inspects nothing must fail, not pass.
# --------------------------------------------------------------------------


def test_workflow_scripts_exist():
    assert SCRIPTS, f"no workflow scripts found under {WORKFLOW_DIR}; refusing to report success"


@pytest.fixture(scope="module", params=[p.name for p in SCRIPTS])
def script(request) -> Path:
    return WORKFLOW_DIR / request.param


@pytest.fixture(scope="module")
def sources() -> dict[str, str]:
    return {p.name: p.read_text() for p in SCRIPTS}


# --------------------------------------------------------------------------
# Source stripping. Two modes, one scanner.
#
# `agent(` appears inside log strings, so a naive count over-reports and the
# schema assertion would fail on text that is not a call. That is what
# strip_strings_and_comments() is for.
#
# But most assertions in this file scan for things that only ever live inside a
# string — prompt text, `phase: 'Layers'`, `status: 'BLOCKED'`,
# `${finding.summary}` — so they cannot use it and were scanning the RAW source
# instead. A comment could then decide the outcome in either direction: a
# commented-out `// schema: X` satisfied the schema check, and a stale
# `// schema: OLD_NAME` failed it. strip_comments() is the other half: comments
# gone, string CONTENTS kept.
#
# Rule of thumb for picking one: strip_strings_and_comments() when the pattern
# targets pure code (identifiers, operators, numbers); strip_comments() when it
# must see what a string carries. A comment counts for nothing either way.
# --------------------------------------------------------------------------


class UnlexableSource(AssertionError):
    """A construct the scanner below cannot lex, raised rather than guessed at.

    Subclasses AssertionError so pytest reports it as a failure rather than an
    error: a source this scanner cannot read is a contract test that did not run.
    """


def _strip(src: str, *, blank_strings: bool) -> str:
    """Blank comments — and, when `blank_strings`, string/template contents.

    Offsets are preserved in both modes, so a position found in the returned
    text still indexes correctly into the original.

    Deliberate limitation: a `/` in code position is REJECTED rather than
    lexed. Telling a regex literal from a division needs the previous
    significant token, and the usual lookback heuristic is itself silently
    wrong after `)` and `}`. Both mis-reads are catastrophic here and neither
    is visible: a quote inside a regex opens a phantom string that blanks
    everything to the next quote, and a division read as a regex blanks
    everything to the next `/`. Either one turns every check built on this
    text green. No workflow ships a regex literal or a division today, so this
    fails closed on the first that does; give it a real lexer at that point.
    Second known limitation: `${...}` is treated as template content, not as
    the code it is. A `/` inside an interpolation is therefore not seen as
    code, and a template NESTED inside one desyncs the scan — build-poc.js
    already has one. It happens to come out even there, and the unterminated
    check at the bottom catches the odd case, which is the whole reason that
    check exists.
    """
    out = list(src)
    i, n = 0, len(src)
    state = None  # None | 'line' | 'block' | quote char
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state is None:
            if ch == "/" and nxt == "/":
                state, out[i], out[i + 1] = "line", " ", " "
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state, out[i], out[i + 1] = "block", " ", " "
                i += 2
                continue
            if ch == "/":
                raise UnlexableSource(
                    f"line {src.count(chr(10), 0, i) + 1}: a `/` in code position is either a "
                    f"regex literal or a division, and this scanner lexes neither. Reading it "
                    f"wrong silently blanks the rest of the file and every check below goes "
                    f"green. See _strip()."
                )
            if ch in "\"'`":
                state = ch
                if blank_strings:
                    out[i] = " "
                i += 1
                continue
            i += 1
            continue
        if state == "line":
            if ch == "\n":
                state = None
            else:
                out[i] = " "
            i += 1
            continue
        if state == "block":
            if ch == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                state = None
                i += 2
                continue
            if ch != "\n":
                out[i] = " "
            i += 1
            continue
        # inside a string or template literal
        if ch == "\\":
            if blank_strings:
                out[i] = " "
                if i + 1 < n and src[i + 1] != "\n":
                    out[i + 1] = " "
            i += 2
            continue
        if ch == state:
            state = None
            if blank_strings:
                out[i] = " "
            i += 1
            continue
        if blank_strings and ch != "\n":
            out[i] = " "
        i += 1
    # An unterminated literal means the scan lost sync somewhere above — a
    # nested template inside `${...}`, say. Everything after that point was
    # blanked or kept for the wrong reason, so report it instead of returning
    # text that looks fine. A trailing `//` comment with no newline is normal.
    if state is not None and state != "line":
        raise UnlexableSource(
            f"unterminated {'block comment' if state == 'block' else repr(state) + ' literal'}; "
            f"the scan lost sync and the text it returned cannot be trusted"
        )
    return "".join(out)


def strip_strings_and_comments(src: str) -> str:
    """Blank out comments and string/template literals, preserving offsets."""
    return _strip(src, blank_strings=True)


def strip_comments(src: str) -> str:
    """Blank out comments only, preserving offsets and string CONTENTS.

    For every scan that has to read prompt text, `phase: 'X'`, `status: 'Y'` or
    `${finding.summary}` — things that only exist inside a string — while a
    comment naming the same thing must not count.
    """
    return _strip(src, blank_strings=False)


def balanced_slice(src: str, open_idx: int) -> str:
    """Return src[open_idx:] up to the matching close paren, inclusive."""
    depth = 0
    for j in range(open_idx, len(src)):
        if src[j] == "(":
            depth += 1
        elif src[j] == ")":
            depth -= 1
            if depth == 0:
                return src[open_idx : j + 1]
    raise AssertionError(f"unbalanced parentheses starting at offset {open_idx}")


def agent_call_sites(src: str) -> list[tuple[int, str]]:
    """Offsets and full text of each real `agent(` call, comments removed.

    Two strippings, deliberately, and both offsets line up with the original.
    Paren matching runs over the fully stripped text, because a `(` inside a
    prompt would unbalance it. The text returned comes from the COMMENT-stripped
    text: it has to keep string contents, since that is where `phase: 'X'` and
    the prompt live, but a comment inside the call must not count. Slicing the
    ORIGINAL here — as this did — meant a commented-out `// schema: X` satisfied
    the schema assertion for a call that passed none, and a stale
    `// schema: OLD_NAME` failed one that was correctly bound.
    """
    code = strip_strings_and_comments(src)
    uncommented = strip_comments(src)
    sites = []
    for m in re.finditer(r"(?<![A-Za-z0-9_$.])agent\s*\(", code):
        open_idx = code.index("(", m.start())
        span = balanced_slice(code, open_idx)
        sites.append((m.start(), uncommented[open_idx : open_idx + len(span)]))
    return sites


# --------------------------------------------------------------------------
# 1. The script parses.
# --------------------------------------------------------------------------


def test_node_is_available():
    assert shutil.which("node"), "node is required for the syntax check and must not be skipped"


def test_script_parses(script: Path, tmp_path: Path):
    """`node --check` on the script body.

    Top-level `return` and `await` are legal in the workflow runtime but not in a
    bare module, so the body is wrapped the way the runtime wraps it.
    """
    src = script.read_text()
    # Locate the meta block on the comment-stripped text but cut the RAW source
    # at the same offset: node has to check what actually ships, and the comment
    # stripper preserves offsets exactly for this. Matching on the raw text let a
    # comment line inside meta beginning with `}` truncate the non-greedy match,
    # which left half the literal in the body and failed node --check on a script
    # that parses perfectly well.
    m = META_RE.match(strip_comments(src))
    assert m, f"{script.name}: could not locate the meta block to strip"
    body = src[m.end() :]
    wrapped = tmp_path / f"{script.stem}.check.mjs"
    wrapped.write_text(f"async function __wf() {{\n{body}\n}}\n")
    proc = subprocess.run(
        ["node", "--check", str(wrapped)], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, f"{script.name} failed node --check:\n{proc.stderr}"


# --------------------------------------------------------------------------
# 2. meta is a pure literal with name and description.
# --------------------------------------------------------------------------

META_RE = re.compile(r"^export const meta = (\{.*?\n\})\n", re.S)


def parse_meta(script: Path) -> dict:
    # Comment-stripped, not raw: meta.name and meta.description are strings, so
    # this cannot use the full stripper, but a comment inside the literal must
    # not decide the outcome either. `// see makeMeta() for the old shape` read
    # as a "function call" and failed the PURE-literal check; a comment line
    # ending in `}` truncated the literal and failed the node evaluation. Blanked
    # comments are whitespace, so the literal still evaluates.
    m = META_RE.match(strip_comments(script.read_text()))
    assert m, f"{script.name}: must begin with `export const meta = {{...}}`"
    literal = m.group(1)
    forbidden = {
        "template interpolation": r"\$\{",
        "spread": r"\.\.\.",
        "function call": r"[A-Za-z_$][\w$]*\s*\(",
    }
    for label, pattern in forbidden.items():
        assert not re.search(pattern, literal), (
            f"{script.name}: meta must be a PURE literal; found {label}"
        )
    proc = subprocess.run(
        ["node", "-e", f"process.stdout.write(JSON.stringify({literal}))"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"{script.name}: meta literal did not evaluate:\n{proc.stderr}"
    return json.loads(proc.stdout)


def test_meta_name_matches_filename(script: Path):
    """meta.name is the shipped command name: /<plugin>:<meta.name>.

    `.get("name")`, not `["name"]`: an absent key must be an assertion failure
    naming the script, not a KeyError. That also makes a separate
    "meta.name is required" test redundant — equality with a non-empty stem
    implies presence — so only description is checked on its own.
    """
    meta = parse_meta(script)
    assert meta.get("description"), f"{script.name}: meta.description is required"
    assert meta.get("name") == script.stem, (
        f"{script.name}: meta.name {meta.get('name')!r} must match the filename stem "
        f"{script.stem!r}, since the command is /{PLUGIN_NAME}:{meta['name']}"
    )


def test_skill_dispatches_every_workflow_by_namespaced_name():
    """SKILL.md must invoke the namespaced form, not the bare meta.name."""
    skill = Path(__file__).resolve().parents[1] / "skills" / PLUGIN_NAME / "SKILL.md"
    text = skill.read_text()
    names = [parse_meta(p)["name"] for p in SCRIPTS]
    assert names, "no workflow names discovered; refusing to report success"
    for name in names:
        assert f"'{PLUGIN_NAME}:{name}'" in text, (
            f"SKILL.md does not dispatch {PLUGIN_NAME}:{name} by its namespaced name"
        )


# --------------------------------------------------------------------------
# 3. meta.phases[].title <-> phase('...') calls, both directions.
# --------------------------------------------------------------------------


def _declared_phases(script: Path) -> set[str]:
    return {p["title"] for p in parse_meta(script).get("phases", [])}


def _phase_calls(script: Path) -> set[str]:
    # Comment-stripped: the phase name is a string literal, so the full stripper
    # would blank it, but a commented-out `// phase('Impact')` must not stand in
    # for the call that was deleted.
    return set(re.findall(r"phase\(\s*'([^']+)'\s*\)", strip_comments(script.read_text())))


def _phase_opts(script: Path) -> set[str]:
    # Same reason, other direction: a comment naming a phase that no agent
    # assigns made test_every_agent_call_assigns_a_declared_phase fail on it.
    return set(re.findall(r"phase:\s*'([^']+)'", strip_comments(script.read_text())))


def test_phases_match_body_calls(script: Path):
    """meta.phases <-> phase('...') calls, exactly, in both directions.

    Checked against phase() CALLS only. Counting the `phase:` option on an
    agent() call as well would let a deleted phase() call hide behind an agent
    that still names that phase — a mutation that survived until this split.
    """
    declared, called = _declared_phases(script), _phase_calls(script)
    assert declared, f"{script.name}: meta.phases is empty; refusing to report success"
    assert called, f"{script.name}: no phase() calls found; refusing to report success"
    assert declared == called, (
        f"{script.name}: phase mismatch.\n"
        f"  declared in meta but never called: {sorted(declared - called)}\n"
        f"  called in body but not declared:   {sorted(called - declared)}"
    )


def test_every_agent_call_assigns_a_declared_phase(script: Path):
    """Every agent() carries a `phase:`, and every such phase is declared.

    Checking only for UNKNOWN phases was vacuous: stripping `phase:` from every
    call left the difference empty and the test green, while the agents landed in
    their own progress groups — the exact failure the message described.
    """
    src = script.read_text()
    sites = agent_call_sites(src)
    assert sites, f"{script.name}: no agent() call sites"
    without = [off for off, text in sites if not re.search(r"phase:\s*'", text)]
    assert not without, (
        f"{script.name}: agent() call(s) at {without} carry no phase:; they land in their "
        f"own progress group instead of the declared one"
    )
    declared, opts = _declared_phases(script), _phase_opts(script)
    assert opts <= declared, (
        f"{script.name}: agent() assigns undeclared phase(s) {sorted(opts - declared)}"
    )


# --------------------------------------------------------------------------
# 4. Every agent() call passes a schema. Highest-value assertion in this file.
# --------------------------------------------------------------------------


def test_every_agent_call_has_a_schema(script: Path):
    """Every agent() must pass a NAMED *_SCHEMA constant.

    Checking only for the literal text `schema:` was defeatable: `schema: {}`,
    `schema: null` and `schema: undefined` all satisfied it while providing no
    validation at all, leaving the stage returning prose for the next one to
    parse. Bind to a declared constant instead.
    """
    src = script.read_text()
    sites = agent_call_sites(src)
    assert sites, f"{script.name}: found 0 agent() call sites; refusing to report success"
    declared = set(schema_literals(script))
    assert declared, f"{script.name}: no *_SCHEMA constants declared"

    bad = []
    for off, text in sites:
        m = re.search(r"schema:\s*([A-Za-z_$][\w$]*)", text)
        if not m or m.group(1) not in declared:
            got = m.group(1) if m else "no schema: key"
            bad.append(f"offset {off} -> {got}")
    assert not bad, (
        f"{script.name}: agent() call(s) without a named schema: {bad}. "
        f"Declared schemas are {sorted(declared)}. An empty or absent schema means the "
        f"stage returns prose and the next stage parses a paragraph."
    )


def test_every_declared_schema_is_actually_used(script: Path):
    """A schema nothing binds to is dead weight that still passes validation."""
    src = strip_strings_and_comments(script.read_text())
    unused = [
        name
        for name in schema_literals(script)
        if not re.search(rf"schema:\s*{re.escape(name)}\b", src)
    ]
    assert not unused, f"{script.name}: declared but never passed to an agent(): {unused}"


# --------------------------------------------------------------------------
# 5. Each schema is valid JSON Schema.
# --------------------------------------------------------------------------

SCHEMA_CONST_RE = re.compile(r"const\s+([A-Z][A-Z0-9_]*SCHEMA)\s*=\s*(\{.*?\n\})\n", re.S)


def schema_literals(script: Path) -> dict[str, dict]:
    # Comment-stripped: the literals carry enum values and descriptions, so the
    # full stripper would gut them, but a commented-out `// const OLD_SCHEMA = {`
    # otherwise reads as declared. That is not cosmetic — `declared` is what
    # test_every_agent_call_has_a_schema binds against, so a schema that exists
    # only in a comment let an agent() reference a name that throws
    # ReferenceError at runtime and still pass. The shipped schemas also carry
    # comments INSIDE them, and a comment line ending in `}` truncated the
    # non-greedy match to something that would not evaluate.
    src = strip_comments(script.read_text())
    found = {}
    for name, literal in SCHEMA_CONST_RE.findall(src):
        proc = subprocess.run(
            ["node", "-e", f"process.stdout.write(JSON.stringify({literal}))"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"{script.name}: {name} did not evaluate:\n{proc.stderr}"
        found[name] = json.loads(proc.stdout)
    return found


def test_schemas_are_valid_json_schema(script: Path):
    schemas = schema_literals(script)
    assert schemas, f"{script.name}: found 0 *_SCHEMA constants; refusing to report success"
    for name, schema in schemas.items():
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:  # noqa: BLE001 - re-raised with the schema name attached
            raise AssertionError(f"{script.name}: {name} is not valid JSON Schema: {exc}") from exc


def test_schemas_declare_required_fields(script: Path):
    """A schema with no `required` lets a stage return {} and still validate.

    Presence only. `required` being non-empty says nothing about WHICH fields it
    names, so this passed while LAYER_SCHEMA shrank from ['verdict', 'evidence']
    to ['verdict']. The two tests below are what pin the contents:
    test_every_gate_reads_only_fields_its_schema_requires ties each gate to the
    fields it decides on, and test_evidence_is_never_an_optional_field pins the
    one field every verdict in this skill is defined by.
    """
    for name, schema in schema_literals(script).items():
        assert schema.get("required"), f"{script.name}: {name} declares no required fields"


def test_every_schema_forbids_extra_keys(script: Path):
    """`additionalProperties: false` on every schema an agent returns.

    A schema that accepts arbitrary extra keys accepts a shape the script never
    contracted for. That was load-bearing in verify-attack-path until the
    parallel() results stopped being disaggregated by shape: a recovery agent
    volunteering `inScope` won `results.find((r) => r.inScope)` and the real
    threat verdict was discarded, so the workflow returned PROCEED on an
    out-of-scope finding. Deleting the four `additionalProperties: false` lines
    left the entire free suite green — nothing pinned the only guard there was.

    The slicing is positional now, so this is no longer the thing standing
    between that bug and a client. It is still the thing that says the prompt and
    the schema agree: a volunteered key means one of them is stale, and accepting
    it silently hides which.
    """
    schemas = schema_literals(script)
    assert schemas, f"{script.name}: found 0 *_SCHEMA constants; refusing to report success"
    lax = sorted(
        name for name, schema in schemas.items() if schema.get("additionalProperties") is not False
    )
    assert not lax, (
        f"{script.name}: {lax} do not set `additionalProperties: false`. An agent can then "
        f"return keys this script never contracted for, and the runtime validator will pass "
        f"them through."
    )


def test_evidence_is_never_an_optional_field():
    """A schema that declares `evidence` must require it.

    This skill grades verdicts on evidence — checkpoint 2.2 passes on
    "determined pass/block/uncertain for each WITH EVIDENCE", 5.1 on
    evidence-based rebuttals. An `evidence` property left out of `required` means
    a verdict with no evidence validates, and the whole premise becomes
    self-report. It is also the concrete way LAYER_SCHEMA could shrink to
    ['verdict'] with every other test in this file green.
    """
    optional, found = [], 0
    for path in SCRIPTS:
        for name, schema in schema_literals(path).items():
            if "evidence" not in schema.get("properties", {}):
                continue
            found += 1
            if "evidence" not in schema.get("required", []):
                optional.append(f"{path.name}:{name}")
    assert found, "found 0 schemas declaring an `evidence` property; refusing to report success"
    assert not optional, (
        f"{optional} declare `evidence` but do not require it. JSON Schema `required` is the "
        f"only thing the runtime validator enforces; a prompt asking for evidence is a request "
        f"the model may decline."
    )


# Each row ties one gate to the schema whose instances it decides on.
#
# `test_the_builder_prompt_names_every_field_the_build_gate_reads` does this for
# isAcceptableBuild/POC_SCHEMA and nothing did it for any other gate, so a field
# a gate branches on could be dropped from `required` and the stage would be free
# to omit it: the gate then reads `undefined`, which is falsy, and the checkpoint
# fails closed on a finding that satisfied it.
#
# (script, gate function, schema, identifiers holding an instance of it,
#  fields exempt from the pin — and why)
GATE_FIELD_CONTRACTS = [
    # `layer` and `location` are put on the object by the .then() wrapper, out of
    # args, not by the agent — so no schema can be expected to require them.
    ("triage-static.js", "decideGate", "LAYER_SCHEMA", ("l",), {"layer", "location"}),
    ("triage-static.js", "decideGate", "THREAT_SCHEMA", ("threatVerdict",), set()),
    # `complete` was exempt here, on the reasoning that an omitted field reads as
    # `undefined` and "the fix is treated as complete, which is the safe direction".
    # That has the direction backwards: treating it as complete is exactly what
    # RETRACTS the finding, so a partial fix whose agent never set the flag was
    # discarded whole. It is pinned rather than exempt now, and HISTORY_SCHEMA
    # requires it.
    ("triage-static.js", "upstreamFixStands", "HISTORY_SCHEMA", ("historyVerdict",), set()),
    # `fixed` moved out of `upstreamFixStands` and into `fixedAnswer` when the
    # answer started being canonicalised, and the row above grades only the
    # fields the function it names dereferences. Without this row the pin on the
    # one field the retraction actually turns on would have quietly left the
    # table while every assertion stayed green.
    ("triage-static.js", "fixedAnswer", "HISTORY_SCHEMA", ("historyVerdict",), set()),
    ("triage-static.js", "decideVerdict", "VERDICT_SCHEMA", ("result",), set()),
    # The brocard pre-gate and its BROCARD_SCHEMA row are gone as of 2.0.0. The
    # four tests are guidance in references/dismissal-grounds.md now, read by the
    # agents that hold the traced path, and nothing dispatches an agent whose
    # verdict can end the stage on the shape of the claim alone.
    # lintOutput decorates a message that already carries its own fallback
    # ('no output captured', pinned in review.test.mjs). Its absence does not
    # change the decision, so it is not something this gate reads.
    ("triage-poc.js", "artifactProblem", "ARTIFACT_SCHEMA", ("check",), {"lintOutput"}),
    ("triage-poc.js", "tallyChallenges", "CHALLENGE_SCHEMA", ("v",), {"key"}),
    # `complete` is the field this row exists for: the gate branches on it, and
    # left out of `required` an omitted one reads as `undefined`, which is not
    # `true`, which switches the retraction off entirely. `reference` is the same
    # bargain one field over. `key` is exempt for the reason given on the
    # tallyChallenges row — the dispatch wrapper puts it on, not the agent.
    ("triage-poc.js", "alreadyFixedStands", "CHALLENGE_SCHEMA", ("verdict",), set()),
    ("triage-poc.js", "reportProblem", "REPORT_SCHEMA", ("result",), set()),
    ("triage-online.js", "offlineProblem", "POLICY_SCHEMA", ("result",), set()),
    ("triage-online.js", "scopeHalt", "SCOPE_SCHEMA", ("result",), set()),
    ("triage-online.js", "summaryProblem", "SUMMARY_SCHEMA", ("result",), set()),
    ("triage-online.js", "censusProblem", "CENSUS_SCHEMA", ("result",), set()),
    # `needsUserCensus` decides on two agents' results at once, so it gets a row
    # per schema. The `driver` row is the one that matters: the whole point of
    # giving the reachability agent its own schema was that SCOPE_SCHEMA could not
    # require the one field this gate reads.
    ("triage-online.js", "needsUserCensus", "REACHABILITY_SCHEMA", ("reachability",), set()),
    ("triage-online.js", "needsUserCensus", "SCOPE_SCHEMA", ("scope",), set()),
    # `impact` is exempt: the batch return carries it through for the reader and
    # `chainProblem` does not branch on it, so requiring it would pin a field the
    # gate does not read. Everything the gate DOES read decides whether a claimed
    # chain is reported, so all four are required.
    ("triage-batch.js", "chainProblem", "CHAIN_SCHEMA", ("v",), set()),
    ("triage-batch.js", "contextBlock", "CONTEXT_SCHEMA", ("ctx",), set()),
]


def test_every_gate_reads_only_fields_its_schema_requires():
    checked = 0
    for file_name, fn, schema_name, receivers, exempt in GATE_FIELD_CONTRACTS:
        path = WORKFLOW_DIR / file_name
        # Comment-stripped, not fully stripped: `${l.layer}` inside a template is
        # a real dereference of the agent's result and the full stripper would
        # blank it, while a commented-out read is not one.
        src = strip_comments(path.read_text())
        body = re.search(rf"function\s+{re.escape(fn)}\([\s\S]*?\n\}}", src)
        assert body, f"{file_name}: gate {fn} not found; this contract table is stale"
        schemas = schema_literals(path)
        assert schema_name in schemas, f"{file_name}: {schema_name} is not declared"
        declared = set(schemas[schema_name].get("properties", {}))
        required = set(schemas[schema_name].get("required", []))

        read = set()
        for receiver in receivers:
            read |= set(re.findall(rf"(?<![\w$.]){re.escape(receiver)}\.(\w+)", body.group(0)))

        # Zero-item guard, per row: a renamed parameter or a rewritten gate makes
        # this row inspect nothing, and a row that inspects nothing must fail.
        gated = (read & declared) - exempt
        assert gated, (
            f"{file_name}: {fn} dereferences no {schema_name} field via {receivers}. Either "
            f"the gate was rewritten or the receiver was renamed; this row is grading nothing."
        )

        ungated = sorted(gated - required)
        assert not ungated, (
            f"{file_name}: {fn} branches on {ungated}, which {schema_name} does not require. "
            f"Nothing forces the agent to report them, so an omitted field reads as undefined "
            f"and the checkpoint fails closed on work that actually passed it."
        )

        # A field the gate reads that the schema does not declare can never
        # arrive at all, now that additionalProperties is false everywhere.
        phantom = sorted(read - declared - exempt)
        assert not phantom, (
            f"{file_name}: {fn} reads {phantom}, which {schema_name} does not declare. With "
            f"`additionalProperties: false` those keys are rejected by the validator, so the "
            f"gate is branching on a value that is always undefined."
        )
        checked += 1
    assert checked == len(GATE_FIELD_CONTRACTS), "not every contract row ran"


# --------------------------------------------------------------------------
# 6. Banned non-determinism. These throw at runtime and break resume.
# --------------------------------------------------------------------------

BANNED = {
    "Date.now(": r"Date\.now\s*\(",
    "Math.random(": r"Math\.random\s*\(",
    "argless new Date()": r"new\s+Date\s*\(\s*\)",
}


def test_no_nondeterminism(script: Path):
    stripped = strip_strings_and_comments(script.read_text())
    for label, pattern in BANNED.items():
        assert not re.search(pattern, stripped), (
            f"{script.name}: contains {label}, which throws in the workflow runtime "
            f"and would break resume"
        )


# --------------------------------------------------------------------------
# 7. Runtime caps and null-safety, checked statically.
# --------------------------------------------------------------------------


def test_parallel_and_pipeline_results_are_null_filtered(script: Path):
    """A dead agent yields null. Using the array unfiltered propagates it."""
    stripped = strip_strings_and_comments(script.read_text())
    # Must be an explicit null filter. Accepting any `.filter(` let a downstream
    # `results.filter(r => r.verdict)` stand in for the missing null guard — a
    # mutation that survived until this was tightened.
    null_filter = re.compile(
        r"\.filter\(\s*Boolean\s*\)|\.filter\(\s*\(?\s*(\w+)\s*\)?\s*=>\s*\1\s*\)"
    )
    for m in re.finditer(r"await\s+(parallel|pipeline)\s*\(", stripped):
        open_idx = stripped.index("(", m.start())
        call = balanced_slice(stripped, open_idx)
        tail = stripped[open_idx + len(call) : open_idx + len(call) + 120]
        assert null_filter.search(call + tail), (
            f"{script.name}: result of {m.group(1)}() at offset {m.start()} is not "
            f"explicitly filtered for null (expected .filter(Boolean)); a dead agent "
            f"yields null and would propagate"
        )


def literal_array_consts(src: str) -> set[str]:
    """Names bound to a script-local array literal, so their length is fixed."""
    return set(re.findall(r"const\s+([A-Za-z_$][\w$]*)\s*=\s*\[", src))


# A cap that bounds the fan-out it sits in: either a MAX_* referenced there, or
# a `.slice(0, n)` applied to the collection being spread.
CAP_IN_SCOPE = re.compile(r"(?<![\w$])MAX_[A-Z_]+(?![\w$])|\.slice\s*\(\s*0\s*,")


def _latest_binding(stripped: str, name: str, before: int) -> str:
    """Text of the last `const <name> =` binding before `before`.

    For the `const thunks = args.x.map(...)` / `parallel(thunks)` shape, where
    the cap — if there is one — lives at the binding rather than at the call.
    Truncated at 300 characters: a cap further away than that is not visibly
    bounding this fan-out, and the failure direction is the safe one.
    """
    last = None
    for m in re.finditer(rf"(?<![\w$])const\s+{re.escape(name)}\s*=", stripped[:before]):
        last = m
    return "" if last is None else stripped[last.start() : last.start() + 300]


def test_no_unbounded_fanout(script: Path):
    """One parallel()/pipeline() call takes at most 4096 items.

    A fan-out over a script-local array literal is bounded by construction. A
    fan-out over anything derived from `args` is caller-supplied and needs a cap
    that bounds THAT call, because the caller can pass any length.

    The cap has to be tied to the call under test. This used to assert
    `over_literal or caps`, where `caps` was every `MAX_* = <n>` anywhere in the
    file: `MAX_LAYERS` and `MAX_ATTEMPTS` armed it file-wide, so adding
    `parallel(args.reviewers.map(...))` to either script would have shipped
    green with the assertion satisfied by a constant that bounds something else
    entirely.
    """
    stripped = strip_strings_and_comments(script.read_text())
    calls = list(re.finditer(r"await\s+(parallel|pipeline)\s*\(", stripped))
    if not calls:
        pytest.skip(f"{script.name} does not fan out")

    # Both of these read pure code, so they scan the fully stripped text. On the
    # raw source a comment decided the outcome: `// MAX_LAYERS = 4 used to cap
    # this` left `caps` non-empty, so an uncapped fan-out over a caller-supplied
    # collection passed, and `// MAX_X = 99999` failed the 4096 assertion for a
    # cap that does not exist.
    bounded_names = literal_array_consts(stripped)
    caps = [int(v) for v in re.findall(r"MAX_[A-Z_]+\s*=\s*(\d+)", stripped)]
    for cap in caps:
        assert cap <= 4096, f"{script.name}: cap {cap} exceeds the 4096-item limit"

    for m in calls:
        open_idx = stripped.index("(", m.start())
        call = balanced_slice(stripped, open_idx)
        head = call[:200]
        over_literal = any(
            re.search(rf"(?<![\w$]){re.escape(n)}(?![\w$])", head) for n in bounded_names
        )
        tied_cap = bool(CAP_IN_SCOPE.search(head))
        argument = call[1:-1].strip()
        if not tied_cap and re.fullmatch(r"[A-Za-z_$][\w$]*", argument):
            tied_cap = bool(CAP_IN_SCOPE.search(_latest_binding(stripped, argument, m.start())))
        assert over_literal or tied_cap, (
            f"{script.name}: {m.group(1)}() at offset {m.start()} fans out over a "
            f"caller-supplied collection with no MAX_* cap or .slice() bounding THIS "
            f"call; a cap elsewhere in the file does not bound it, and the 4096-item "
            f"limit could be exceeded"
        )


# --------------------------------------------------------------------------
# 8. The dispatch contract. Every args.* field a script reads must be
#    documented in SKILL.md, or the orchestrator will invent a plausible name.
# --------------------------------------------------------------------------

SKILL_MD = Path(__file__).resolve().parents[1] / "skills" / PLUGIN_NAME / "SKILL.md"

# Objects arriving via `args` whose sub-fields the prompts interpolate.
# `poc` is deliberately absent. It used to arrive via args, when building and
# reviewing were separate workflows; they are one script now, so the built PoC is
# a local. Leaving it here would demand that SKILL.md document fields no caller
# can pass.
ARG_OBJECTS = ("finding", "entryPoint", "envelope", "verification", "candidate", "project")


def arg_field_references(src: str) -> set[str]:
    """`${finding.summary}` -> {'finding.summary'}, from template literals only.

    Comment-stripped: an interpolation only exists inside a template, so the
    full stripper would erase all of them, but a commented-out one is not a
    read. A stale `// the prompt used to say ${finding.componentName}` made
    SKILL.md look like it was missing a field the scripts never reference.
    """
    pattern = r"\$\{(" + "|".join(ARG_OBJECTS) + r")\.([a-zA-Z_][\w]*)"
    return {f"{obj}.{field}" for obj, field in re.findall(pattern, strip_comments(src))}


def fenced_blocks(text: str) -> list[str]:
    """Every fenced code block body, whatever the info string.

    Pairing with a regex breaks here: SKILL.md mixes bare ``` fences with
    ```text and ```bash, so a pattern anchored on "```\\n" pairs a closing fence
    with the next opening one and desynchronises the whole document.
    """
    blocks, current, inside = [], [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            if inside:
                blocks.append("\n".join(current))
                current = []
            inside = not inside
            continue
        if inside:
            current.append(line)
    return blocks


def dispatch_contract_block(text: str) -> str:
    """Only the fenced arg-shape blocks count as documentation.

    Matching the whole of SKILL.md would let a field like `location` pass on any
    unrelated prose mention.
    """
    return "\n".join(b for b in fenced_blocks(text) if re.search(r"^\s*\w+\s*=\s*[{[]?", b, re.M))


def test_every_workflow_reading_nested_args_validates_them(sources: dict[str, str]):
    """A nested access on a missing arg throws, it does not read as undefined.

    `envelope.hosts.join()` and `verification.impact.impact` killed the run
    mid-prompt-construction; `verify-attack-path` had a guard and the other two
    did not.
    """
    unguarded = []
    for name, src in sources.items():
        if not arg_field_references(src):
            continue
        # Every pattern below is pure code, so it scans the fully stripped text.
        # On the raw source, commenting the gate out satisfied all three of them
        # at once: `// const argProblems = missingArgs(args)` above a live
        # `const argProblems = []` left the script with no validation and this
        # test green — the exact mutation the comment two lines down says it
        # was tightened to catch.
        code = strip_strings_and_comments(src)
        if "function missingArgs(" not in code:
            unguarded.append(f"{name} (no missingArgs)")
            continue
        # The gate must be FED by missingArgs(args). Checking only that the
        # function exists and that some `argProblems.length` test exists let a
        # mutation to `const argProblems = []` survive: guard defanged, shape intact.
        # `args` must be the FIRST argument; extra ones are fine (verify-attack-path
        # passes its layer cap as a second parameter so the extracted function stays
        # self-contained for the unit tests).
        if not re.search(r"const\s+argProblems\s*=\s*missingArgs\s*\(\s*args\s*[,)]", code):
            unguarded.append(f"{name} (argProblems is not the result of missingArgs(args))")
        elif not re.search(r"if\s*\(\s*argProblems\.length\s*>\s*0\s*\)", code):
            unguarded.append(f"{name} (missingArgs defined but never gates execution)")
    assert not unguarded, (
        f"{unguarded} read args.* sub-fields without validating them. A missing or "
        f"misnamed field either reaches an agent as the literal 'undefined' or, for a "
        f"nested access, throws a TypeError and kills the run."
    )


def test_no_unguarded_nested_arg_access(sources: dict[str, str]):
    """Every `args.a.b.c` dereference must be covered by that script's validator.

    The previous version asserted `f"{obj}.{mid}" in src`, which is true by
    construction — the pair was extracted FROM src. It could not fail. Check the
    body of missingArgs() specifically instead.
    """
    for name, src in sources.items():
        # Two strippings. The dereference is an interpolation, which only exists
        # inside a template, so it needs string contents kept — but a
        # commented-out `${verification.impact.impact}` is not a dereference.
        # The guard body is pure code, and on the raw source a comment inside
        # missingArgs() that merely NAMED the field satisfied the check for a
        # `need()` call that had been deleted.
        nested = re.findall(
            r"\$\{(" + "|".join(ARG_OBJECTS) + r")\.([a-zA-Z_]\w*)\.([a-zA-Z_]\w*)",
            strip_comments(src),
        )
        if not nested:
            continue
        body = re.search(r"function missingArgs\([\s\S]*?\n\}", strip_strings_and_comments(src))
        assert body, (
            f"{name} dereferences {nested[0][0]}.{nested[0][1]}.{nested[0][2]} with no "
            f"missingArgs() guard; a missing intermediate throws TypeError"
        )
        guard = body.group(0)
        for obj, mid, leaf in nested:
            assert re.search(rf"{re.escape(mid)}\b", guard), (
                f"{name}: `{obj}.{mid}.{leaf}` is dereferenced in a prompt but "
                f"missingArgs() never checks `{obj}.{mid}` — a missing intermediate throws"
            )


def test_dispatch_contract_documents_every_field_the_scripts_read(sources: dict[str, str]):
    """The bug this catches, observed live: the scripts read finding.summary,
    finding.component, finding.claimedImpact, entryPoint.description and
    entryPoint.payload; SKILL.md named only the top-level args. The orchestrator
    sent finding.title, entryPoint.function and so on, and the agents received
    the literal string 'undefined'.
    """
    contract = dispatch_contract_block(SKILL_MD.read_text())
    assert contract.strip(), (
        "SKILL.md has no fenced arg-shape block; there is no dispatch contract to check against"
    )
    referenced = set()
    for src in sources.values():
        referenced |= arg_field_references(src)

    assert referenced, "found 0 args.* field references; refusing to report success"

    undocumented = sorted(
        ref
        for ref in referenced
        if re.search(rf"\b{re.escape(ref.split('.')[1])}\b", contract) is None
    )
    assert not undocumented, (
        f"SKILL.md's dispatch contract does not document {undocumented}. "
        f"An undocumented field is one the orchestrator will guess at, and a near-miss "
        f"interpolates as the literal text 'undefined'."
    )


# verify-attack-path.js had its own copy of this assertion. It is a strict
# subset of test_every_workflow_reading_nested_args_validates_them, which checks
# the same two patterns plus `argProblems = missingArgs(args…)` over the same
# stripped source — and never skips that script, which carries 7 interpolated
# arg fields.


# --------------------------------------------------------------------------
# 9. No verification scaffolding in prompts. It makes output worse.
# --------------------------------------------------------------------------

SCAFFOLDING = [
    r"double[- ]check your",
    r"verify your (own )?(answer|work)",
    r"add a final verification step",
    r"make sure you did not miss",
]


def test_no_verification_scaffolding_in_prompts(script: Path):
    # Comment-stripped: the prompts ARE strings, so the full stripper would make
    # this check vacuous, but a comment is not a prompt. On the raw source, a
    # comment saying the scripts deliberately do NOT tell an agent to
    # double-check your work failed the very test it was explaining.
    src = strip_comments(script.read_text()).lower()
    for pattern in SCAFFOLDING:
        assert not re.search(pattern, src), (
            f"{script.name}: prompt contains verification scaffolding matching {pattern!r}. "
            f"Put the check in a test, where it runs deterministically."
        )


# --------------------------------------------------------------------------
# 10. `{...null}` is `{}`, not falsy. Spreading an agent result unguarded turns
#     a dead agent into a truthy phantom that survives .filter(Boolean).
# --------------------------------------------------------------------------


def test_agent_results_are_not_spread_without_a_null_guard(sources: dict[str, str]):
    """The bug: `.then((v) => ({ ...v, key }))` on a dead agent yields `{key}`.

    It passes .filter(Boolean), makes any "how many came back" count wrong, and
    reaches the next prompt as the literal text `undefined`. Unit tests could not
    see it, because they model a dead agent as an absent array element — a state
    this code path never produced.
    """
    offenders = []
    for name, src in sources.items():
        stripped = strip_strings_and_comments(src)
        # The spread may sit anywhere in the object literal, not only first. The
        # previous pattern required `({ ...v` and so could not see
        # `({ layer: …, location: …, ...v })` in verify-attack-path.js — the one
        # unguarded spread actually present, invisible to the assertion written
        # for it.
        for m in re.finditer(r"\.then\(\s*\((\w+)\)\s*=>\s*\(\s*\{[^}]*\.\.\.", stripped):
            var = m.group(1)
            window = stripped[max(0, m.start() - 200) : m.end() + 200]
            guarded = re.search(rf"{var}\s*\?", window) or re.search(rf"{var}\s*&&", window)
            if not guarded:
                offenders.append(f"{name}@{m.start()}")
    assert not offenders, (
        f"unguarded spread of an agent result at {offenders}. `{{...null}}` is `{{}}`, so a "
        f"dead agent becomes a truthy phantom. Use `.then((v) => (v ? {{...v}} : null))`."
    )


def test_terminal_returns_carry_a_reason(sources: dict[str, str]):
    """SKILL.md's failure protocol prints `Reason:`; a status with none is useless."""
    missing = []
    found = 0
    for name, src in sources.items():
        # Comment-stripped, not raw and not fully stripped.
        # strip_strings_and_comments() blanks string CONTENTS, so
        # `status: 'NO_CANDIDATES'` could never match and this loop inspected
        # zero returns while reporting success. The raw source was no better in
        # the other direction: a `// reason: dropped for now` inside the object
        # literal satisfied the `"reason" in ...` test for a return that carries
        # none, and a comment anywhere between `return {` and `status:` stopped
        # the regex matching at all, silently dropping that return from the scan.
        stripped = strip_comments(src)
        for m in re.finditer(r"return\s*(\{)\s*status:\s*'([A-Z_]+)'", stripped):
            found += 1
            status = m.group(2)
            if status in ("PROCEED", "BUILT", "REPORTED"):
                continue  # success paths carry payloads instead
            # Scope to THIS return's object literal. A fixed-size window found a
            # neighbouring return's `reason` and passed.
            depth, end = 0, None
            for j in range(m.start(1), len(stripped)):
                if stripped[j] == "{":
                    depth += 1
                elif stripped[j] == "}":
                    depth -= 1
                    if depth == 0:
                        end = j + 1
                        break
            assert end, f"{name}: unbalanced return object for {status}"
            if "reason" not in stripped[m.start(1) : end]:
                missing.append(f"{name}:{status}")
    assert found > 0, "found 0 status returns to check; refusing to report success"
    assert not missing, f"terminal status with no reason: {missing}"


def test_the_layer_cap_default_matches_max_layers():
    """`missingArgs(a, maxLayers = N)` must not drift from `MAX_LAYERS = N`.

    The cap is a defaulted parameter rather than a reference to the constant
    because the unit tests extract this function and evaluate it in isolation,
    where a free variable would throw ReferenceError. That independence is
    exactly what lets the two numbers drift, so it is pinned here.
    """
    # Fully stripped: both are pure code, and `re.search` takes the FIRST match,
    # so on the raw source a stale `// was: const MAX_LAYERS = 4` above a live
    # `const MAX_LAYERS = 8` reported agreement with a default of 4. The drift
    # this test exists to catch was masked by a comment recording it.
    src = strip_strings_and_comments((WORKFLOW_DIR / "triage-static.js").read_text())
    const = re.search(r"const\s+MAX_LAYERS\s*=\s*(\d+)", src)
    default = re.search(r"function\s+missingArgs\(\s*a\s*,\s*maxLayers\s*=\s*(\d+)\s*\)", src)
    assert const, "MAX_LAYERS constant not found"
    assert default, "missingArgs does not take a defaulted maxLayers parameter"
    assert const.group(1) == default.group(1), (
        f"MAX_LAYERS is {const.group(1)} but missingArgs defaults maxLayers to "
        f"{default.group(1)}; the arg gate and the dispatch cap disagree"
    )


def test_the_findings_cap_default_matches_max_findings():
    """`missingArgs(a, maxFindings = N)` must not drift from `MAX_FINDINGS = N`.

    Same bargain, and same reason for it, as MAX_LAYERS: the cap is a defaulted
    parameter so the unit tests can extract the function and evaluate it alone,
    and that independence is exactly what lets the two numbers drift.
    """
    src = strip_strings_and_comments((WORKFLOW_DIR / "triage-batch.js").read_text())
    const = re.search(r"const\s+MAX_FINDINGS\s*=\s*(\d+)", src)
    default = re.search(r"function\s+missingArgs\(\s*a\s*,\s*maxFindings\s*=\s*(\d+)\s*\)", src)
    assert const, "MAX_FINDINGS constant not found"
    assert default, "triage-batch's missingArgs does not take a defaulted maxFindings parameter"
    assert const.group(1) == default.group(1), (
        f"MAX_FINDINGS is {const.group(1)} but missingArgs defaults maxFindings to "
        f"{default.group(1)}; the arg gate and the dispatch cap disagree"
    )


def test_the_batch_verdict_allowlist_matches_what_stage_1_returns():
    """`accountFindings` files a sub-result as verified only on a NAMED status.

    Non-blankness counted `BLOCKED` as a verdict, and `BLOCKED` is this codebase's
    own word for an analysis that did not run — so a batch whose every child
    refused came back `BATCH_TRIAGED`, "3 of 3 finding(s) verified; 0 unverified",
    with the zero-verdict guard unable to fire because the ledger was full.

    Pinned in BOTH directions, so a new Stage 1 verdict cannot be added without
    landing here, and `BLOCKED` cannot creep back in.
    """
    # Comment-stripped, not fully stripped: the statuses ARE string literals, so
    # the full stripper would blank the thing being compared.
    static_src = strip_comments((WORKFLOW_DIR / "triage-static.js").read_text())
    returned = set(re.findall(r"status:\s*'([A-Z_]+)'", static_src))
    # PROCEED is decideGate's internal sentinel, never returned to a caller — the
    # terminal-reason scan above excludes it the same way.
    returned.discard("PROCEED")
    assert returned, "triage-static returns no status literals; refusing to report success"
    assert "BLOCKED" in returned, (
        "triage-static no longer returns BLOCKED, so the premise of this pin is stale"
    )

    batch_src = strip_comments((WORKFLOW_DIR / "triage-batch.js").read_text())
    # `\n\s*\]` because VERDICT_STATUSES lives INSIDE accountFindings — the unit
    # tests extract that function and evaluate it alone, where a module-level
    # const is a ReferenceError — so its closing bracket is indented.
    listing = re.search(r"const VERDICT_STATUSES = \[[\s\S]*?\n\s*\]", batch_src)
    assert listing, "triage-batch's VERDICT_STATUSES not found; this pin is stale"
    allowed = set(re.findall(r"'([A-Z_]+)'", listing.group(0)))
    assert allowed, "VERDICT_STATUSES is empty; every sub-result would read as unverified"

    assert allowed == returned - {"BLOCKED"}, (
        f"triage-batch accepts {sorted(allowed - returned)} that triage-static never returns, "
        f"and rejects {sorted(returned - {'BLOCKED'} - allowed)} that it does. A verdict missing "
        f"from the allowlist is reported as unverified; BLOCKED present in it is an analysis that "
        f"never ran reported as a verdict."
    )


def test_the_batch_entry_contract_matches_triage_static():
    """triage-batch re-validates each entry against triage-static's own field list.

    It has to duplicate that list — workflow scripts have no module system — and
    a duplicated validator is exactly the drift this repo has been bitten by. The
    duplication buys something real: the batch rejects an unusable entry BEFORE
    the shared-context agent is paid for, rather than after. This pin is what
    makes it safe, and it fails in both directions, so neither list can quietly
    gain or lose a field.
    """
    # Comment-stripped: the field names are string literals, so the full stripper
    # would blank the very thing being compared, while a commented-out `need` is
    # not a requirement and must not count on either side.
    static_src = strip_comments((WORKFLOW_DIR / "triage-static.js").read_text())
    static_body = re.search(r"function missingArgs\([\s\S]*?\n\}", static_src)
    assert static_body, "triage-static's missingArgs not found; this pin is stale"
    static_fields = set(re.findall(r"need\(\s*'(finding|entryPoint)\.(\w+)'", static_body.group(0)))
    assert static_fields, (
        "triage-static requires no finding/entryPoint field; refusing to report success"
    )

    batch_src = strip_comments((WORKFLOW_DIR / "triage-batch.js").read_text())
    # `\n\s*\]`, not `\n\]`: ENTRY_FIELDS lives INSIDE missingArgs, because the
    # unit tests extract that function and evaluate it alone, where a module-level
    # const is a ReferenceError. So its closing bracket is indented.
    listing = re.search(r"const ENTRY_FIELDS = \[[\s\S]*?\n\s*\]", batch_src)
    assert listing, "triage-batch's ENTRY_FIELDS not found; this pin is stale"
    batch_fields = set(re.findall(r"\[\s*'(finding|entryPoint)',\s*'(\w+)'\s*\]", listing.group(0)))
    assert batch_fields, "ENTRY_FIELDS is empty; the batch would dispatch entries it never checked"

    assert batch_fields == static_fields, (
        f"triage-batch checks {sorted(batch_fields - static_fields)} that triage-static does not "
        f"require, and misses {sorted(static_fields - batch_fields)} that it does. A field only "
        f"triage-static requires is one the batch pays for a context agent before discovering."
    )


def build_gate_fields() -> set[str]:
    """Every field `isAcceptableBuild` rejects a build for.

    Two shapes: the booleans are `result.x` dereferences, and the strings are an
    inline array of names iterated with `result[f]`. The array is read from
    COMMENT-stripped source because `strip_strings_and_comments` blanks string
    contents, which is exactly where the names live — over the fully stripped
    source this found the three booleans, silently missed all six strings, and
    still satisfied a plain non-empty guard.
    """
    path = WORKFLOW_DIR / "triage-poc.js"
    # Fully stripped for the dereferences: on raw source a comment inside the
    # function naming a field it no longer reads counted as gated, and — worse —
    # a comment could satisfy the zero-item guard for a gate reading nothing.
    gate = re.search(
        r"function\s+isAcceptableBuild\([\s\S]*?\n\}",
        strip_strings_and_comments(path.read_text()),
    )
    assert gate, "isAcceptableBuild not found"
    fields = set(re.findall(r"result\.(\w+)", gate.group(0)))

    gate_raw = re.search(
        r"function\s+isAcceptableBuild\([\s\S]*?\n\}", strip_comments(path.read_text())
    )
    assert gate_raw, "isAcceptableBuild not found in comment-stripped source"
    literal = re.search(r"\[([^\]]*)\]", gate_raw.group(0))
    assert literal, "isAcceptableBuild no longer carries its string-field list"
    fields |= set(re.findall(r"'(\w+)'", literal.group(1)))

    assert len(fields) > 3, (
        f"found only {sorted(fields)} gated fields, which is the booleans alone — "
        f"the string list was not picked up and this check is grading almost nothing"
    )
    return fields


def test_the_build_gate_covers_every_field_the_reviewers_read():
    """A `poc.X` the gate lets through reaches five reviewers as blank.

    This used to compare build-poc's gate against review-poc's `need('poc.X')`
    list, because the PoC crossed a dispatch boundary between them and the two
    lists were maintained by hand. They drifted: `path` and `pocType` were
    required downstream and ungated upstream, so a builder returning whitespace
    for either returned BUILT and was then rejected without a single reviewer
    running — after the whole build had been paid for.

    The two are one script now, so there is no arg validator to compare against.
    The requirement is unchanged and the consequence is worse: whitespace now
    reaches the challenge and artifact prompts as the evidence they are meant to
    judge, and five high-effort agents form an opinion about a blank.
    """
    src = strip_comments((WORKFLOW_DIR / "triage-poc.js").read_text())
    # The reviewers' half of the file: everything after the build loop returns.
    reviewers = src.split("phase('Challenges')", 1)
    assert len(reviewers) == 2, (
        "triage-poc.js has no Challenges phase, so this test cannot locate the "
        "reviewer prompts; either the script was restructured or this is stale"
    )
    interpolated = set(re.findall(r"\$\{poc\.(\w+)", reviewers[1]))
    assert interpolated, (
        "the reviewer prompts interpolate no poc.* field at all; either they were "
        "rewritten or the pattern is stale, and this test is grading nothing"
    )

    ungated = sorted(interpolated - build_gate_fields())
    assert not ungated, (
        f"the reviewer prompts interpolate poc.{ungated} but isAcceptableBuild does not "
        f"check them. JSON Schema `required` validates whitespace, so a builder "
        f"reporting '   ' returns BUILT and that blank is what five reviewers judge."
    )


def test_the_builder_prompt_names_every_field_the_build_gate_reads():
    """A field the gate reads but the prompt never names is a discarded PoC.

    `isAcceptableBuild` rejects a build missing any of these, and JSON Schema
    only forces the ones in `required`. `lintPassed` was gated, optional, and
    unnamed — so a model that built, executed and linted correctly could omit
    it, fail the gate, burn the retry and return BUILD_FAILED for a finding it
    had actually proven.
    """
    path = WORKFLOW_DIR / "triage-poc.js"
    fields = build_gate_fields()

    # Subset, not "required OR named in the prompt". `required` is enforced by
    # the runtime validator; a prompt is a request the model may decline. The
    # disjunction was also satisfiable by accident — `\bcommand\b` matches "run
    # this exact command" and `\boutput\b` matches "capture the full output to a
    # file", neither of which names a field to return.
    required = set(schema_literals(path)["POC_SCHEMA"].get("required", []))
    ungated = sorted(fields - required)
    assert not ungated, (
        f"triage-poc.js: isAcceptableBuild gates on {ungated}, which POC_SCHEMA does not "
        f"require. Nothing forces the model to report them, so omitting one fails the "
        f"gate, burns the retry and returns BUILD_FAILED for a PoC that actually built."
    )


# --------------------------------------------------------------------------
# 11. The scanner's own contract.
#
# Everything above scans script text, so the scanner decides every outcome in
# this file. Fifteen assertions could be flipped either way by a comment before
# these existed: a comment could satisfy a check the code no longer satisfied,
# and a comment could fail a check the code passed. Each case below is one of
# those, reduced to the smallest source that shows it, so a regression in the
# scanner is reported here rather than as a silently green contract suite.
# --------------------------------------------------------------------------


def _js(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "synthetic.js"
    p.write_text(body)
    return p


def test_strip_comments_keeps_string_contents_and_offsets():
    src = "const a = 'keep me' // drop me\n/* drop */ const b = `keep ${x}`\n"
    out = strip_comments(src)
    assert len(out) == len(src), "offsets must be preserved for the slicing callers"
    assert "'keep me'" in out and "`keep ${x}`" in out
    assert "drop me" not in out and "drop *" not in out
    assert out.index("keep me") == src.index("keep me")


def test_strip_strings_and_comments_still_blanks_both():
    """The wrapper's behaviour is unchanged; callers and mutations depend on it."""
    src = "const a = 'gone' // also gone\nconst b = `gone too`\n"
    out = strip_strings_and_comments(src)
    assert len(out) == len(src)
    assert "gone" not in out
    assert "const a =" in out and "const b =" in out


def test_a_double_slash_inside_a_string_is_not_a_comment():
    """Otherwise a URL in a prompt blanks the rest of its line, both modes."""
    src = "const u = 'https://example.test/x'\nconst t = Date.now()\n"
    assert re.search(r"Date\.now\s*\(", strip_strings_and_comments(src))
    assert re.search(r"Date\.now\s*\(", strip_comments(src))


def test_a_regex_literal_is_rejected_rather_than_mis_lexed():
    """Reproduced before the guard existed, in a scratch copy of the workflows.

    `const QUOTED = /['"]/` above a `Date.now()` left test_no_nondeterminism
    green: the `/` read as division, the quote inside the character class opened
    a phantom string, and everything to the next quote — including the
    `Date.now(` — was blanked. Every stripped-source check in this file was
    disarmed at once, silently. Reading it the other way is no better, so the
    scanner refuses to guess.
    """
    src = "const QUOTED = /['\"]/\nconst t = Date.now()\n"
    for strip in (strip_strings_and_comments, strip_comments):
        with pytest.raises(UnlexableSource, match="code position"):
            strip(src)


def test_an_unterminated_literal_is_rejected_rather_than_mis_lexed():
    with pytest.raises(UnlexableSource, match="lost sync"):
        strip_strings_and_comments("const a = 'oops\nconst t = Date.now()\n")


def test_a_commented_out_phase_option_does_not_satisfy_an_agent_call():
    src = """const r = agent(
  `do a thing`,
  // phase: 'Layers'
  { label: 'x', schema: S },
)
"""
    ((_, text),) = agent_call_sites(src)
    assert not re.search(r"phase:\s*'", text), "a commented-out phase: satisfied the phase check"
    assert "label: 'x'" in text, "string contents must survive; the option scan reads them"


def test_a_commented_out_schema_does_not_satisfy_an_agent_call():
    src = "const r = agent(`p`, { label: 'x' /* schema: FAKE_SCHEMA */ })\n"
    ((_, text),) = agent_call_sites(src)
    assert not re.search(r"schema:\s*[A-Za-z_$][\w$]*", text)


def test_a_stale_schema_name_in_a_comment_does_not_shadow_the_real_one():
    """The other direction: the comment made a correctly bound call look unbound."""
    src = "const r = agent(`p`, {\n  // schema: OLD_SCHEMA\n  schema: REAL_SCHEMA,\n})\n"
    ((_, text),) = agent_call_sites(src)
    m = re.search(r"schema:\s*([A-Za-z_$][\w$]*)", text)
    assert m and m.group(1) == "REAL_SCHEMA"


def test_a_commented_out_phase_call_is_not_a_phase_call(tmp_path: Path):
    assert _phase_calls(_js(tmp_path, "// phase('Impact')\nphase('Layers')\n")) == {"Layers"}


def test_a_phase_named_only_in_a_comment_is_not_assigned(tmp_path: Path):
    src = "// TODO: was phase: 'Recovery'\nagent(`p`, { phase: 'Layers' })\n"
    assert _phase_opts(_js(tmp_path, src)) == {"Layers"}


def test_a_commented_out_schema_constant_is_not_declared(tmp_path: Path):
    src = (
        "// const LEGACY_SCHEMA = {\n//   type: 'object',\n//   required: ['x'],\n// }\n"
        "const REAL_SCHEMA = {\n  type: 'object',\n  required: ['a'],\n}\n"
    )
    assert set(schema_literals(_js(tmp_path, src))) == {"REAL_SCHEMA"}


def test_an_arg_reference_in_a_comment_is_not_a_reference():
    src = "// used to say `Component: ${finding.componentName}`\nconst p = `${finding.summary}`\n"
    assert arg_field_references(src) == {"finding.summary"}


def test_a_reason_in_a_comment_does_not_satisfy_a_terminal_return():
    src = "return {\n  status: 'BLOCKED',\n  // reason: dropped for now\n}\n"
    with pytest.raises(AssertionError, match="terminal status with no reason"):
        test_terminal_returns_carry_a_reason({"synthetic.js": src})


def test_a_comment_cannot_hide_a_terminal_return_from_the_scan():
    """A comment between `return {` and `status:` used to drop it from the scan."""
    src = "return {\n  // } was a one-liner\n  status: 'BLOCKED',\n}\n"
    with pytest.raises(AssertionError, match="terminal status with no reason"):
        test_terminal_returns_carry_a_reason({"synthetic.js": src})


def test_the_terminal_return_check_fails_when_it_inspects_nothing():
    """The zero-item guard, exercised rather than assumed."""
    with pytest.raises(AssertionError, match="refusing to report success"):
        test_terminal_returns_carry_a_reason({"synthetic.js": "const a = 1\n"})


def test_a_scaffolding_phrase_in_a_comment_does_not_fail_the_prompt_check(tmp_path: Path):
    src = "// We deliberately never tell it to double-check your work.\nagent(`Find the bug.`)\n"
    test_no_verification_scaffolding_in_prompts(_js(tmp_path, src))


def test_a_scaffolding_phrase_in_a_prompt_still_fails(tmp_path: Path):
    """The check must still bite where it matters, or the fix above is a mute."""
    src = "agent(`Find the bug. Double-check your answer.`)\n"
    with pytest.raises(AssertionError, match="verification scaffolding"):
        test_no_verification_scaffolding_in_prompts(_js(tmp_path, src))


def test_a_commented_out_arg_gate_does_not_count_as_validation():
    src = (
        "const p = `Finding: ${finding.summary}`\n"
        "// function missingArgs(a) { return [] }\n"
        "// const argProblems = missingArgs(args)\n"
        "// if (argProblems.length > 0) { return { status: 'BLOCKED' } }\n"
        "const argProblems = []\n"
    )
    with pytest.raises(AssertionError, match="without validating them"):
        test_every_workflow_reading_nested_args_validates_them({"synthetic.js": src})


def test_a_cap_named_only_in_a_comment_does_not_bound_a_fanout(tmp_path: Path):
    src = (
        "// MAX_LAYERS = 4 used to cap this\n"
        "const r = await parallel(args.layers.map((l) => () => agent(`x`)))\n"
    )
    with pytest.raises(AssertionError, match=r"no MAX_\* cap"):
        test_no_unbounded_fanout(_js(tmp_path, src))


def test_an_unrelated_cap_does_not_bound_a_fanout(tmp_path: Path):
    """The mis-arming this guard shipped with, reduced to its smallest form.

    `caps` was every `MAX_* = <n>` in the file, so `MAX_ATTEMPTS` — which bounds
    build-poc's retry loop and nothing else — satisfied the per-call assertion
    for a fan-out over a caller-supplied collection. Both real scripts already
    define a MAX_*, so this held for every fan-out either of them could grow.
    """
    src = (
        "const MAX_ATTEMPTS = 2\n"
        "const r = await parallel(args.reviewers.map((x) => () => agent(`review`)))\n"
    )
    with pytest.raises(AssertionError, match=r"no MAX_\* cap"):
        test_no_unbounded_fanout(_js(tmp_path, src))


def test_an_unrelated_cap_does_not_bound_a_fanout_via_its_binding(tmp_path: Path):
    """Same defect, one indirection out: the cap must bound the binding too."""
    src = (
        "const MAX_ATTEMPTS = 2\n"
        "const thunks = args.reviewers.map((x) => () => agent(`review`))\n"
        "const r = await parallel(thunks)\n"
    )
    with pytest.raises(AssertionError, match=r"no MAX_\* cap"):
        test_no_unbounded_fanout(_js(tmp_path, src))


def test_a_cap_on_the_fanout_itself_is_accepted(tmp_path: Path):
    """The tightened rule must still pass a genuinely bounded caller fan-out.

    Otherwise it is a mute that forbids the pattern rather than checking it.
    Both forms the scripts could legitimately use are accepted: the cap named in
    the call, and the cap named at the binding the call spreads.
    """
    inline = (
        "const MAX_REVIEWERS = 4\n"
        "const r = await parallel(args.reviewers.slice(0, MAX_REVIEWERS).map(\n"
        "  (x) => () => agent(`review`),\n"
        "))\n"
    )
    test_no_unbounded_fanout(_js(tmp_path, inline))

    (tmp_path / "sub").mkdir()
    at_binding = (
        "const MAX_REVIEWERS = 4\n"
        "const thunks = args.reviewers.slice(0, MAX_REVIEWERS).map((x) => () => agent(`r`))\n"
        "const r = await parallel(thunks)\n"
    )
    test_no_unbounded_fanout(_js(tmp_path / "sub", at_binding))


def test_skill_tells_the_orchestrator_to_wait_for_each_workflow():
    """`Workflow` returns on launch, so ending the turn kills the run.

    Measured: an orchestrator ended its turn 2.4s after dispatching review-poc
    and the workflow was aborted 140s in, after the artifact check and four of
    five challenges had completed but before any report existed. Nothing in the
    runtime enforces the wait — only this instruction does, so it must not be
    silently dropped from the dispatch contract.

    The Completion Gate must also distinguish "did not return" from "returned a
    failing status": a torn-down run has not failed its checkpoints, it has not
    finished them, and inferring a verdict from partial agent output is exactly
    the mistake this skill exists to prevent.
    """
    text = SKILL_MD.read_text()
    assert re.search(r"do not end your turn", text, re.I), (
        "SKILL.md does not tell the orchestrator to wait for a dispatched workflow. "
        "Workflow returns on launch; ending the turn tears the run down mid-flight."
    )
    assert re.search(r"killed|aborted|torn down", text, re.I), (
        "SKILL.md's Completion Gate does not distinguish a workflow that was killed "
        "from one that returned a failing status"
    )


# --------------------------------------------------------------------------
# 12. Routing agrees with the bug-class reference the orchestrator reads.
# --------------------------------------------------------------------------

BUG_CLASS_REFERENCE = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / PLUGIN_NAME
    / "references"
    / "bug-class-verification.md"
)

# Every class the reference defines, and the route it must take. `deep` adds the
# API-contract/environment pass, the algebraic bounds proof and the race
# feasibility proof, so a class needs it when one of those three is the work.
#
# This table is the decision. Its purpose is that adding a class to the reference
# FAILS the build until someone routes it, rather than silently inheriting
# `standard` — which is what happened to Memory Corruption.
EXPECTED_ROUTES = {
    "Memory Corruption": "deep",
    "Logic Bugs": "standard",
    "Race Conditions": "deep",
    "Integer Issues": "deep",
    "Crypto Weaknesses": "standard",
    "Injection": "standard",
    "Information Disclosure": "standard",
    "Denial of Service": "deep",
    "Deserialization": "standard",
}


def reference_bug_classes() -> list[str]:
    text = BUG_CLASS_REFERENCE.read_text()
    return re.findall(r"^## (.+)$", text, re.M)


def test_every_bug_class_has_a_routing_decision():
    """SKILL.md sends the orchestrator to the reference for `finding.bugClass`.

    So the strings that reference uses as headings are the strings that reach
    `selectRoute`, and a heading it does not recognise takes the cheap path with
    no algebraic proof. That was live: "Memory Corruption" routed `standard` while
    "buffer overflow" — the same finding, written differently — routed `deep`.

    Checked in both directions. A class in the reference with no entry in
    EXPECTED_ROUTES fails, and an entry naming a class the reference dropped fails
    too, so the table cannot rot into a description of a document that has moved.
    """
    classes = reference_bug_classes()
    assert classes, (
        f"no `## ` class headings found in {BUG_CLASS_REFERENCE.name}; either it was "
        f"restructured or this scan is stale, and it is grading nothing"
    )
    assert set(classes) == set(EXPECTED_ROUTES), (
        f"the reference defines {sorted(set(classes) - set(EXPECTED_ROUTES))} with no routing "
        f"decision, and this table names {sorted(set(EXPECTED_ROUTES) - set(classes))} which it "
        f"no longer defines. A class with no decision takes the cheap path by default."
    )


def test_select_route_recognises_every_bug_class_name():
    """The keyword list must actually match the reference's own headings.

    Extracted and run, not read: the list is inline in `selectRoute` (it has to
    be — a module const cannot be extracted), so nothing but executing it proves
    the strings agree.
    """
    node = shutil.which("node")
    assert node, "node is required to evaluate selectRoute"
    probe = json.dumps(list(EXPECTED_ROUTES))
    script_body = (
        "import('./extract.mjs').then(({loadFn, script}) => {"
        "const f = loadFn(script('triage-static.js'), 'selectRoute');"
        f"const out = {{}}; for (const c of {probe}) "
        "out[c] = f({finding: {bugClass: c}, layers: [{}]});"
        "console.log(JSON.stringify(out))})"
    )
    result = subprocess.run(
        [node, "-e", script_body],
        cwd=Path(__file__).resolve().parent,
        capture_output=True,
        text=True,
        check=True,
    )
    actual = json.loads(result.stdout)
    wrong = {k: (v, EXPECTED_ROUTES[k]) for k, v in actual.items() if v != EXPECTED_ROUTES[k]}
    assert not wrong, (
        f"selectRoute routes these bug classes against the decision table "
        f"(got, expected): {wrong}. The orchestrator reads these exact strings out of "
        f"{BUG_CLASS_REFERENCE.name}, so a mismatch is a routing coin flip."
    )


NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6}


def test_the_documented_impact_field_count_matches_what_stage_2_requires():
    """SKILL.md's Stage 2 paragraph must name the number `missingArgs` enforces.

    It said "all three `verification.impact` fields" while `missingArgs` required
    four — `impact`, `result`, `rootCause`, `classification`. A caller who trimmed
    the dispatch to the documented three got BLOCKED with no hint that the prose
    was the stale half, and the two fields added last are exactly the ones whose
    absence silently switches the cap and the census off.

    Counted rather than spelled out, because the failure is drift: the count moved
    twice while the sentence did not.
    """
    # Comment-stripped, not fully stripped: the field names ARE string literals,
    # so the full stripper blanks the very thing being counted — while a
    # commented-out `need` is not a requirement and must still not count.
    src = strip_comments((WORKFLOW_DIR / "triage-online.js").read_text())
    body = re.search(r"function\s+missingArgs\([\s\S]*?\n\}", src)
    assert body, "missingArgs not found in triage-online.js; this pin is stale"
    required = set(re.findall(r"need\(\s*'verification\.impact\.(\w+)'", body.group(0)))
    assert required, "missingArgs requires no verification.impact field; refusing to report success"

    prose = re.search(
        r"requires `verification\.severity` and all (\w+) `verification\.impact`",
        SKILL_MD.read_text(),
    )
    assert prose, (
        "SKILL.md no longer states how many `verification.impact` fields Stage 2 requires; "
        "this pin is stale, or the dispatch contract lost the sentence."
    )
    documented = NUMBER_WORDS.get(prose.group(1))
    assert documented == len(required), (
        f"SKILL.md documents '{prose.group(1)}' verification.impact fields; missingArgs requires "
        f"{len(required)}: {sorted(required)}. A caller dispatching the documented set is BLOCKED."
    )


def test_the_band_total_matches_the_challenge_count():
    """`confidenceBand(defeated, total = N)` must not drift from CHALLENGES.length.

    The total is a defaulted parameter rather than a reference to the array because
    the unit tests extract this function and evaluate it in isolation, where a free
    variable is a ReferenceError. That independence is exactly what lets the two
    numbers drift, so it is pinned here — the same treatment MAX_LAYERS gets.

    It used to be the literal `5` in a `defeated === 5` comparison. A sixth
    challenge would have made HIGH unreachable and reported every perfect review as
    MEDIUM, with nothing failing.
    """
    src = strip_strings_and_comments((WORKFLOW_DIR / "triage-poc.js").read_text())
    default = re.search(r"function\s+confidenceBand\(\s*defeated\s*,\s*total\s*=\s*(\d+)\s*\)", src)
    assert default, "confidenceBand does not take a defaulted `total` parameter"
    listing = re.search(r"const\s+CHALLENGES\s*=\s*\[", src)
    assert listing, "CHALLENGES array not found"
    # Count the `key:` entries in the comment-stripped source, where the strings live.
    raw = strip_comments((WORKFLOW_DIR / "triage-poc.js").read_text())
    block = raw[raw.index("const CHALLENGES = [") :]
    keys = re.findall(r"^\s{4}key: '", block[: block.index("\n]")], re.M)
    assert keys, "no challenge keys found; this check is grading nothing"
    assert int(default.group(1)) == len(keys), (
        f"confidenceBand defaults total to {default.group(1)} but CHALLENGES has {len(keys)} "
        f"entries; HIGH becomes unreachable when they disagree"
    )
