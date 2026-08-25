"""Contract tests for the port-rule-to-languages workflow script: the properties the
runtime requires of any script, as opposed to the porting-specific ones in
test_port_rule_workflow.py, which grades the golden variants. Nothing here knows what a
Semgrep rule is, which is the test for whether a new check belongs here.

`test_node_suites_pass` runs both .test.mjs suites through pytest, so `make check` covers
them without a second Makefile target. Everything needing node skips when it is absent,
which silently drops the only checks that execute the script rather than reading it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = TESTS_DIR.parent
WORKFLOW = PLUGIN_ROOT / "workflows" / "port-rule-to-languages.js"
FAILURE_PATH_SUITE = TESTS_DIR / "workflow-failure-paths.test.mjs"
NODE_SUITES = (TESTS_DIR / "workflow-functions.test.mjs", FAILURE_PATH_SUITE)

# Floor for how many tests a node suite must report having run. Well below the 26 and 38
# the two suites run today, so ordinary churn does not trip it, and well above the 1 that
# node reports for a file containing no tests at all.
MIN_NODE_SUITE_TESTS = 10

SCRIPT = WORKFLOW.read_text(encoding="utf-8")

AGENT_CALL_RE = re.compile(r"\bagent\(")
META_TITLE_RE = re.compile(r"title:\s*'([^']+)'")
PHASE_CALL_RE = re.compile(r"\bphase\('([^']+)'\)")
PHASE_OPT_RE = re.compile(r"\bphase:\s*'([^']+)'")
SCHEMA_DECL_RE = re.compile(r"const (\w+_SCHEMA)\s*=\s*\{")
# `new Date()` with no argument is the throwing form; `new Date(args.stamp)` is fine.
NONDETERMINISM_RES = (
    ("Date.now()", re.compile(r"\bDate\.now\s*\(")),
    ("Math.random()", re.compile(r"\bMath\.random\s*\(")),
    ("argless new Date()", re.compile(r"\bnew Date\s*\(\s*\)")),
)

# Text that must not appear: a guessed test-file extension. Semgrep decides which files a
# rule applies to by extension and skips the rest, so a test file with the wrong one is never
# graded and `semgrep --test` reports a pass for the zero tests it ran.
VACUOUS_EXTENSION_RES = (
    re.compile(r"fileExtension\s*\|\|\s*'[a-z]+'"),
    re.compile(r"\|\|\s*'txt'"),
)


def brace_block(text: str, open_index: int) -> str:
    """Return the `{...}` block starting at `open_index`, brace-matched."""
    depth = 0
    for index in range(open_index, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[open_index : index + 1]
    raise AssertionError(f"unbalanced braces from offset {open_index}")


def meta_block(script: str) -> str:
    """Return the text of the script's `meta` object literal."""
    marker = script.index("export const meta")
    return brace_block(script, script.index("{", marker))


def declared_phases(script: str) -> list[str]:
    """Return the phase titles listed in meta.phases, in order."""
    block = meta_block(script)
    start = block.find("phases:")
    return META_TITLE_RE.findall(block[start:]) if start != -1 else []


def used_phases(script: str) -> set[str]:
    """Return every phase title the body groups agents under."""
    return set(PHASE_CALL_RE.findall(script)) | set(PHASE_OPT_RE.findall(script))


def node_json(program: str) -> object:
    """Evaluate an ES module that prints JSON, and return the parsed value."""
    with tempfile.TemporaryDirectory() as workdir:
        module = Path(workdir) / "probe.mjs"
        module.write_text(program, encoding="utf-8")
        completed = subprocess.run(
            ["node", str(module)], capture_output=True, text=True, check=False
        )
    assert completed.returncode == 0, f"node could not evaluate the probe:\n{completed.stderr}"
    return json.loads(completed.stdout)


def schema_objects(script: str) -> dict[str, object]:
    """Return every `*_SCHEMA` literal in the script, evaluated by node.

    Evaluating rather than pattern-matching is the point: a schema that interpolates a
    variable or calls a helper is not a literal the runtime can hand to a subagent, and it
    fails here instead of at run time.
    """
    declarations = []
    names = []
    for match in SCHEMA_DECL_RE.finditer(script):
        names.append(match.group(1))
        declarations.append(f"const {match.group(1)} = {brace_block(script, match.end() - 1)}")

    assert names, "no *_SCHEMA declarations found; schema discovery is broken"
    payload = ", ".join(f"{name}: {name}" for name in names)
    parsed = node_json("\n".join([*declarations, f"console.log(JSON.stringify({{{payload}}}))"]))
    assert isinstance(parsed, dict)
    return parsed


def schema_errors(name: str, schema: object, path: str = "") -> list[str]:
    """Return every way `schema` fails to be a usable JSON Schema fragment."""
    where = f"{name}{path}"
    if not isinstance(schema, dict):
        return [f"{where} is not an object"]

    errors = []
    kind = schema.get("type")
    if not kind:
        errors.append(f"{where} has no type")

    enum = schema.get("enum")
    if enum is not None and (not isinstance(enum, list) or not enum):
        errors.append(f"{where} has an empty or non-list enum")

    if kind == "object":
        properties = schema.get("properties")
        if not isinstance(properties, dict) or not properties:
            return [*errors, f"{where} is an object with no properties"]
        for field in schema.get("required", []):
            if field not in properties:
                errors.append(f"{where}.required names {field!r}, which is not a property")
        for field, subschema in properties.items():
            errors += schema_errors(name, subschema, f"{path}.{field}")
    elif kind == "array":
        items = schema.get("items")
        if not isinstance(items, dict):
            errors.append(f"{where} is an array with no items schema")
        else:
            errors += schema_errors(name, items, f"{path}[]")

    return errors


def check_script_has_work_to_inspect(script: str) -> list[str]:
    """Check there is anything here at all, so no other checker passes vacuously."""
    errors = []
    if not AGENT_CALL_RE.findall(script):
        errors.append("no agent() calls; every per-agent check below would pass vacuously")
    if not used_phases(script):
        errors.append("no phase() grouping; every per-phase check below would pass vacuously")
    return errors


def check_meta_is_a_pure_literal(script: str) -> list[str]:
    """Check the meta block is a literal the runtime can read before running anything.

    The runtime parses `meta` to render the permission prompt and the phase list, so it is
    read without executing the body. Interpolation or a helper call there fails the run.
    """
    try:
        block = meta_block(script)
    except ValueError:
        return ["no `export const meta` block"]

    errors = []
    if "${" in block or "`" in block:
        errors.append("meta interpolates a template literal; it must be a pure literal")
    if "..." in block:
        errors.append("meta spreads a value; it must be a pure literal")
    for field in ("name:", "description:"):
        if field not in block:
            errors.append(f"meta has no {field.rstrip(':')}")
    return errors


def check_phases_match_meta(script: str) -> list[str]:
    """Check meta.phases and the body's phase grouping name the same phases."""
    declared, used = declared_phases(script), used_phases(script)
    if not declared:
        return ["meta declares no phases, so the progress view has nothing to group under"]
    if not used:
        return ["the body groups no agents into phases"]

    errors = [
        f"phase {title!r} is used but not declared in meta.phases" for title in used - set(declared)
    ]
    errors += [
        f"phase {title!r} is declared in meta.phases but never used"
        for title in set(declared) - used
    ]
    return errors


def check_every_agent_call_has_a_schema(script: str) -> list[str]:
    """Check each agent() call passes a schema.

    The highest-value check here: without a schema an agent returns prose, and the next
    stage has to guess at its shape. Every failure downstream then looks like a model
    problem rather than a missing contract.
    """
    starts = [call.start() for call in AGENT_CALL_RE.finditer(script)]
    if not starts:
        return ["no agent() calls found; schema discovery is broken"]

    # Each call owns the text up to where the next one begins. A fixed-size window instead of
    # this boundary reads the *following* call's options, so an unschema'd call added anywhere
    # above another one passes on its neighbour's schema.
    bounds = list(zip(starts, [*starts[1:], len(script)], strict=True))
    unschemad = [
        script[:start].count("\n") + 1
        for start, end in bounds
        if "schema:" not in script[start:end]
    ]
    if unschemad:
        return [f"agent() calls without a schema at line(s) {unschemad}"]
    return []


def check_no_guessed_test_file_extension(script: str) -> list[str]:
    """Check the test file's extension is derived, never guessed.

    This is the F1 failure class: a rule declaring `languages: [rust]` beside a `.txt` test
    file makes semgrep skip the file, run no tests, and print "All tests passed" with exit 0.
    The port then lands in `passed` having never been applied to anything.
    """
    if "EXTENSION_BY_LANGUAGE" not in script:
        return ["no extension table; the test file extension is being taken on trust"]

    errors = [
        f"the script falls back to a guessed extension ({pattern.search(script).group(0)!r}); "
        "an unknown language must stop, not produce a file semgrep will skip"
        for pattern in VACUOUS_EXTENSION_RES
        if pattern.search(script)
    ]

    # The patterns above only know the words `fileExtension` and `txt`, so a fallback spelled
    # any other way — `|| 'pl'`, or the `if (claimed) return claimed` shape this once had —
    # passed them clean. The resolver has one legitimate return, and it is the table lookup;
    # anything else it can hand back is a guess whatever it is named.
    start = script.find("function testFileExtension(")
    if start == -1:
        return [*errors, "no testFileExtension(); the extension is not derived at all"]

    # Comments come out before the scan below looks for `return`. A comment explaining why the
    # function throws rather than falling back reads as a second return value otherwise, so the
    # checker fired on prose — a false positive that punishes explaining the invariant.
    body = re.sub(r"//[^\n]*", "", brace_block(script, script.index("{", start)))
    returns = [found.strip() for found in re.findall(r"\breturn\b([^\n]*)", body)]
    if not returns:
        return [*errors, "testFileExtension returns nothing; it cannot be deriving an extension"]

    errors += [
        f"testFileExtension can return {found!r}, which is not the table lookup; an "
        "unrecognised language key must stop the port, not name a file semgrep will skip"
        for found in returns
        if "EXTENSION_BY_LANGUAGE" not in found or "||" in found
    ]
    return errors


def check_the_rule_is_read_rather_than_relayed(script: str) -> list[str]:
    """Check no phase receives the rule as text another agent retyped.

    Asked to repeat the file back verbatim into a schema field, the reader HTML-escaped `<`
    and `>`, silently breaking Semgrep's `<... ...>` deep-expression operator for every phase
    downstream. Nothing fails when that happens: the port is simply made against a corrupted
    specification, and every language still reports as passed.
    """
    if "rulePath" not in script:
        return ["the script never names the rule path, so no phase can read the rule itself"]
    # A field or a read of one, not the bare word: a comment explaining why the field is gone
    # should not fail the build.
    if re.search(r"\.rawYaml\b|\brawYaml\s*:", script):
        return [
            "the script relays the rule as text (rawYaml); it must pass args.rulePath and let "
            "each phase read the file, because an agent does not repeat a file back verbatim"
        ]
    return []


def check_no_nondeterministic_builtins(script: str) -> list[str]:
    """Check the script avoids the builtins the runtime blocks to keep runs resumable."""
    if not script.strip():
        return ["empty script; nothing was inspected"]
    return [
        f"{label} is unavailable in a workflow script and throws at run time"
        for label, pattern in NONDETERMINISM_RES
        if pattern.search(script)
    ]


CHECKERS = (
    check_script_has_work_to_inspect,
    check_meta_is_a_pure_literal,
    check_phases_match_meta,
    check_every_agent_call_has_a_schema,
    check_no_guessed_test_file_extension,
    check_the_rule_is_read_rather_than_relayed,
    check_no_nondeterministic_builtins,
)


@pytest.mark.parametrize("checker", CHECKERS, ids=lambda c: c.__name__)
def test_workflow_script_satisfies_the_runtime_contract(checker) -> None:
    assert checker(SCRIPT) == []


def parse_error(script: str) -> str:
    """Return node's complaint about the script, or an empty string when it parses.

    Parses it the way the runtime evaluates it: an async function body, not a module.
    `node --check` on the file itself rejects the top-level `return` the runtime supplies a
    wrapper for, so the body is wrapped first and the `export` keyword dropped.
    """
    with tempfile.TemporaryDirectory() as workdir:
        wrapped = Path(workdir) / "workflow-body.mjs"
        wrapped.write_text(
            "async function body(agent, pipeline, parallel, log, phase, args, budget) {\n"
            + script.replace("export const meta", "const meta", 1)
            + "\n}\n",
            encoding="utf-8",
        )
        completed = subprocess.run(
            ["node", "--check", str(wrapped)], capture_output=True, text=True, check=False
        )
    return "" if completed.returncode == 0 else completed.stderr


def test_ci_has_node_so_the_script_is_never_left_unexecuted() -> None:
    """Fail in CI when node is missing, rather than skipping every check that runs the script.

    Everything here needing node skips without it: the parse check, the schema validation, both
    node suites, and the whole mutation battery behind them. That is a green job that never
    executed the script — the same hole `test_ci_has_semgrep_...` closes for the grader, and a
    wider one, since node gates the only checks that run this script rather than reading it.
    """
    if os.environ.get("CI") != "true":
        pytest.skip("not CI: the node checks may skip where node is not installed")
    assert shutil.which("node"), (
        "node is not on PATH in CI, so the parse check, the schema validation, both node suites "
        "and the entire mutation battery skipped without running the script once"
    )


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_workflow_script_parses() -> None:
    """Every other check here is a pattern over text.

    Without this one, a script with a syntax error satisfies all of them and fails only on
    a real run, after the permission prompt and the first agent spawn.
    """
    assert parse_error(SCRIPT) == ""


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_the_parse_check_rejects_a_syntax_error() -> None:
    """Prove the parse check has teeth rather than always reporting clean."""
    mutated = SCRIPT.replace("const outputDir = args.outputDir || '.'", "const outputDir = (", 1)
    assert mutated != SCRIPT, "mutation target is stale; the script moved on"
    assert parse_error(mutated), "node --check accepted a script with an unclosed expression"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_meta_evaluates_on_its_own() -> None:
    """Evaluate meta in isolation, and cross-check it against the text-derived phases."""
    meta = node_json(f"const meta = {meta_block(SCRIPT)}\nconsole.log(JSON.stringify(meta))")
    assert isinstance(meta, dict)
    assert meta["name"], "meta.name is empty; it decides the slash command"
    assert meta["description"], "meta.description is empty; it is shown in the permission prompt"

    titles = [phase["title"] for phase in meta["phases"]]
    assert titles == declared_phases(SCRIPT), (
        "the evaluated meta and the text-scanned meta disagree, so one of the two "
        "extractions is wrong and the phase checks cannot be trusted"
    )


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_meta_isolation_rejects_a_field_that_reads_the_script() -> None:
    """Prove the isolation check has teeth.

    A meta field referencing a script constant evaluates fine in the running script and is
    exactly what the runtime cannot read, since it parses meta without executing the body.
    """
    mutated = SCRIPT.replace("phases: [", "rounds: MAX_VALIDATE_ROUNDS,\n    phases: [", 1)
    assert mutated != SCRIPT, "mutation target is stale; the script moved on"

    probe = f"const meta = {meta_block(mutated)}\nconsole.log(JSON.stringify(meta))"
    with pytest.raises(AssertionError, match="node could not evaluate"):
        node_json(probe)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_every_schema_is_a_usable_json_schema() -> None:
    schemas = schema_objects(SCRIPT)
    assert len(schemas) >= len(SCHEMA_DECL_RE.findall(SCRIPT)), "a schema went missing"

    errors = [error for name, schema in schemas.items() for error in schema_errors(name, schema)]
    assert errors == [], "\n".join(errors)


def node_test(suite: Path, script: Path | None = None) -> tuple[int, str]:
    """Run a node test suite, optionally against a substitute workflow script.

    An ambient `WORKFLOW_SCRIPT` is stripped rather than inherited. Left in, a contributor who
    exported it while debugging a mutated copy would have `make check` grade that copy and report
    the real script green — the suite passing while measuring something else entirely.
    """
    env = {**os.environ}
    env.pop("WORKFLOW_SCRIPT", None)
    if script:
        env["WORKFLOW_SCRIPT"] = str(script)
    completed = subprocess.run(
        # The reporter is pinned because callers below read `# pass N` out of this
        # output. Node's default is version-dependent and not a TTY-independent
        # contract: node 22 defaults to tap when stdout is not a terminal, node 23+
        # defaults to spec, which prints `ℹ pass N` instead. Left unpinned, every
        # assertion on that text fails on a newer node while CI stays green.
        ["node", "--test", "--test-reporter=tap", str(suite)],
        capture_output=True,
        text=True,
        check=False,
        cwd=TESTS_DIR,
        env=env,
    )
    return completed.returncode, completed.stdout + completed.stderr


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.parametrize("suite", NODE_SUITES, ids=lambda p: p.name)
def test_node_suites_pass(suite: Path) -> None:
    """Run the node suites from here, so `make check` covers them without a second target."""
    assert suite.is_file(), f"missing node suite at {suite}"
    code, output = node_test(suite)
    assert code == 0, f"node --test failed:\n{output}"

    # `# fail 0` only restated the exit code. What it could not see is a suite that
    # stopped running its tests and passed anyway. Node makes that harder to detect
    # than it looks: a file containing NO tests still reports `# tests 1 # pass 1`,
    # counting the file itself, which is indistinguishable from a file holding one
    # test. So a floor, not a non-zero check. These two suites run 26 and 38.
    passed = re.search(r"^# pass (\d+)", output, re.MULTILINE)
    assert passed, f"no TAP summary in output; did the reporter change?\n{output}"
    assert int(passed.group(1)) >= MIN_NODE_SUITE_TESTS, (
        f"{suite.name} ran only {passed.group(1)} tests, below the floor of "
        f"{MIN_NODE_SUITE_TESTS} — the suite is not running what it used to:\n{output}"
    )


# Each mutation breaks one failure-handling behaviour the node suite claims to cover.
FAILURE_PATH_BREAKAGES = (
    pytest.param(
        # Caps the loop at one round rather than replacing `while` with `if`: that swap makes
        # the `break` inside illegal, so the script stops compiling and every test fails on a
        # SyntaxError — which would satisfy a bare "did it go red" check without ever
        # exercising the retry.
        ("rounds < MAX_VALIDATE_ROUNDS", "rounds < 1"),
        id="capping the retry loop at a single round",
    ),
    pytest.param(
        ("validationPassed(reported, rule.semgrepVersion, prev.stem)", "reported.passed"),
        id="trusting the agent's self-reported pass",
    ),
    pytest.param(
        # Quoting semgrep only binds the agent while the binary is fixed: one that could not
        # make its tests pass installed an older build whose parser was not yet Pro-gated and
        # reported its genuine green.
        ("if (got !== want) {", "if (false) {"),
        id="accepting a pass graded by a different semgrep",
    ),
    pytest.param(
        ("if (SKIPPED_RATHER_THAN_RUN.test(output)) {", "if (false) {"),
        id="accepting a green over a rule semgrep skipped",
    ),
    pytest.param(
        # Back to trusting the summary line, which is what shipped: "All tests passed" is also
        # what semgrep prints over a spec with no annotations left in it.
        ("const ungraded = gradingFailure(validation?.testJson, stem)", "const ungraded = ''"),
        id="accepting a green over a spec that graded no annotation",
    ),
    pytest.param(
        # The other half of the spec, which `--test --json` cannot show: an annotated safe line is
        # neither expected nor reported there, so vulnerable cases alone grade clean and the rule
        # that passes them can flag every construct in the target language.
        ("return safeCaseFailure(validation?.safeCaseJson, stem)", "return ''"),
        id="accepting a green over a spec that annotates no safe case",
    ),
    pytest.param(
        ("if (assessment.semgrepCanAnalyze === false) {", "if (false) {"),
        id="porting to a language semgrep cannot parse",
    ),
    pytest.param(
        # The gate runs before the refuter, against the key the assessment probed. Inheriting that
        # answer through a rename let a Pro-only parser reach translation and three xhigh rounds.
        ("renamed ? refutation.semgrepCanAnalyze :", ""),
        id="inheriting the parse answer through a renamed language key",
    ),
    pytest.param(
        ("if (constructs.length === 0) {", "if (false) {"),
        id="overturning a verdict without naming a construct",
    ),
    pytest.param(
        # Back to reading an absent answer as permission to proceed, which is what `=== false`
        # alone did: the field is schema-required, so missing is malformed, not a yes.
        ("typeof assessment.semgrepCanAnalyze !== 'boolean'", "false"),
        id="treating an unanswered parse question as a yes",
    ),
    pytest.param(
        # The live grader accepting one annotated line where the golden grader demands two.
        ("if (expected.length < 2) {", "if (false) {"),
        id="grading a spec with a single annotated line as a pass",
    ),
    pytest.param(
        # A dead refuter folded into "the verdict stands" drops the language on a verdict
        # nothing second-guessed, reported identically to one that was.
        ("if (!refutation) {\n    return null\n  }", "if (false) {\n    return null\n  }"),
        id="treating a dead refuter as an upheld verdict",
    ),
    pytest.param(
        # The call site only: replacing the definition too renames a function into `String`
        # and the script stops compiling, which proves nothing about the guard.
        ("stem = claimStem(", "stem = String("),
        id="letting two languages share one output directory",
    ),
    pytest.param(
        ("canonicalLanguage(settled.semgrepLanguage)", "(settled.semgrepLanguage)"),
        id="slugging an alias without canonicalising it first",
    ),
    pytest.param(
        # Without the catch the throw drops the item to null, and a deterministic refusal
        # reaches the caller as "did not report back".
        ("return stop(language, settled, error.message)", "throw error"),
        id="losing the reason a guard stopped a language",
    ),
    pytest.param(
        ("extension = testFileExtension(language, settled)", "extension = 'txt'"),
        id="guessing the test file extension",
    ),
    pytest.param(
        # Without it the translate phase overwrites the spec the test phase wrote, and the rule
        # is graded against itself over zero surviving annotations.
        ("if (EXTENSION_BY_LANGUAGE[key] === RULE_FILE_EXTENSION) {", "if (false) {"),
        id="writing a test file the translated rule would overwrite",
    ),
    pytest.param(
        # The references reach an agent only as a resolved absolute path, and nothing
        # downstream fails when they stop doing so, so the prompts are where it shows.
        ("Read ${referencesDir}/${file}", "Read references/${file}"),
        id="passing a relative reference path",
    ),
    pytest.param(
        ("effort: 'xhigh',\n        phase: 'Translate rule',", "phase: 'Translate rule',"),
        id="unpinning an effort level",
    ),
    pytest.param(
        # Softening the guard back to a warning, which is the regression that matters: the
        # run then finishes and reports every language passed, with no references anywhere.
        ("if (!referencesDir) {", "if (false) {"),
        id="letting a run proceed without the references",
    ),
    pytest.param(
        # Back to accepting anything non-empty, which is the state that shipped: a script cannot
        # expand `{baseDir}` and has no filesystem access to notice the path is not there, so the
        # literal reached every prompt while the run reported every language passed.
        (
            "if (referencesDir.includes('{') || !referencesDir.startsWith('/')) {",
            "if (false) {",
        ),
        id="accepting a references path that cannot resolve",
    ),
    pytest.param(
        ("incomplete: lost,", "incomplete: lost.length,"),
        id="reporting a lost language as a count that names nothing",
    ),
    pytest.param(
        # Without it, "Go and Java" ports one language named after the whole phrase.
        ("if (malformed.length > 0) {", "if (false) {"),
        id="accepting a phrase as a single language",
    ),
    pytest.param(
        # Back to relaying only the agent's own words, which is what shipped: a round that went
        # green on the wrong binary reports "clean" and the retry learns nothing it can act on.
        ("could not always see: ${rejection}", "could not always see: (not relayed)"),
        id="retrying without saying why the last round was refused",
    ),
    pytest.param(
        # Without it the run reaches the loop and refuses every round of every language on a
        # condition settled before the first agent spawned.
        ("if (!baseline) {", "if (false) {"),
        id="starting a run with no baseline semgrep version",
    ),
    pytest.param(
        # Collapsing the two argument guards back into one message, which opened by naming
        # args.rulePath however the call was actually wrong.
        ("if (languages.length === 0) {", "if (false) {"),
        id="losing the error that names the language list",
    ),
)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.parametrize("mutation", FAILURE_PATH_BREAKAGES)
def test_failure_path_suite_detects_breakage(tmp_path: Path, mutation: tuple[str, str]) -> None:
    """Prove the failure-path suite fails when the behaviour it covers is broken.

    It executes the real script, so a mutated copy has to make it go red. Otherwise those
    tests would be describing the runtime rather than constraining this script.
    """
    target, replacement = mutation
    assert target in SCRIPT, f"mutation target {target!r} is stale; the script moved on"

    broken = tmp_path / "port-rule-to-languages.js"
    broken.write_text(SCRIPT.replace(target, replacement), encoding="utf-8")

    code, output = node_test(FAILURE_PATH_SUITE, broken)
    assert code != 0, f"the failure-path suite passed against a broken script:\n{output}"

    # A mutation that stops the script compiling fails every test, which would satisfy the
    # assertion above while proving nothing about the behaviour under test. Demand a targeted
    # failure: some tests still pass, and nothing blew up before the body ran.
    assert "SyntaxError" not in output, (
        f"the mutation broke parsing rather than behaviour, so this proves nothing:\n{output}"
    )
    assert re.search(r"^# pass [1-9]", output, re.MULTILINE), (
        f"every test failed, so the mutation was not targeted:\n{output}"
    )


# Each mutation is a plausible edit that would defeat one contract check.
BREAKAGES = (
    pytest.param(
        check_script_has_work_to_inspect,
        # Every call, not just the awaited ones: stage one returns `agent(...)` directly, and
        # leaving that occurrence behind means the script still spawns something.
        ("agent(", "noAgent("),
        id="a script that spawns no agents",
    ),
    pytest.param(
        check_meta_is_a_pure_literal,
        ("name: 'port-rule-to-languages'", "name: `port-${'rule'}-to-languages`"),
        id="computing a meta field",
    ),
    pytest.param(
        check_phases_match_meta,
        ("phase: 'Recheck applicability'", "phase: 'Recheck'"),
        id="renaming a phase in the body only",
    ),
    pytest.param(
        check_every_agent_call_has_a_schema,
        ("schema: REFUTATION_SCHEMA,", ""),
        id="dropping a schema from an agent call",
    ),
    pytest.param(
        check_every_agent_call_has_a_schema,
        (
            "phase('Read rule')",
            "phase('Read rule')\nconst extra = await agent('summarise it', { effort: 'low' })",
        ),
        id="adding an unschema'd agent call above a schema'd one",
    ),
    pytest.param(
        check_no_guessed_test_file_extension,
        (
            "extension = testFileExtension(language, settled)",
            "extension = settled.fileExtension || 'txt'",
        ),
        id="guessing the test file extension",
    ),
    pytest.param(
        check_the_rule_is_read_rather_than_relayed,
        (
            "The rule being ported is at ${args.rulePath}",
            "The rule is:\\n```yaml\\n${rule.rawYaml}\\n```",
        ),
        id="relaying the rule as text an agent retyped",
    ),
    pytest.param(
        check_no_nondeterministic_builtins,
        ("const outputDir = args.outputDir", "const outputDir = Math.random() + args.outputDir"),
        id="reaching for a blocked builtin",
    ),
)


@pytest.mark.parametrize(("checker", "mutation"), BREAKAGES)
def test_checkers_detect_breakage(checker, mutation: tuple[str, str]) -> None:
    """Prove each contract checker still detects what it exists to detect."""
    target, replacement = mutation
    assert target in SCRIPT, f"mutation target {target!r} is stale; the script moved on"
    mutated = SCRIPT.replace(target, replacement)
    assert mutated != SCRIPT, "mutation changed nothing"
    assert checker(mutated), f"{checker.__name__} accepted a script it should have rejected"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_schema_validation_rejects_a_required_field_that_does_not_exist() -> None:
    """The schema checks run through node, so they get their own mutation."""
    mutated = SCRIPT.replace(
        "required: ['refuted', 'reasoning']", "required: ['refuted', 'why']", 1
    )
    assert mutated != SCRIPT, "mutation target is stale; the script moved on"

    schemas = schema_objects(mutated)
    errors = [error for name, schema in schemas.items() for error in schema_errors(name, schema)]
    assert any("'why'" in error for error in errors), (
        "a required field naming a property that does not exist was accepted"
    )
