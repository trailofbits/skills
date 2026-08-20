"""The workflow's argument preamble, exercised through node against the real file.

Why this exists. `args` reaches the workflow from a model emitting a tool call, and that
model serialises the object one extra time often enough to matter — the Workflow tool's own
documentation warns about it. Rejecting a JSON-encoded string outright throws away the whole
run: a bench cell is ~2.5M tokens and ~45 minutes, and the failure surfaces as "no args"
long after anyone is watching.

The load-bearing assertion is the last one: the object form and the string form must resolve
to *identical* configuration. If they ever diverge, the leniency has started changing what
the pipeline measures, which is worse than the refusal it replaced.
"""

from __future__ import annotations

import itertools
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "c-review.js"

# The preamble runs standalone; everything after this marker needs the workflow runtime
# (agent/parallel/phase), which is not available under plain node. Both markers are
# structural — a section banner and a `const` — because a prose marker means rewording one
# comment turns every test in this file into a ValueError rather than a failure anyone
# could read.
PREAMBLE_START = "const REQUIRED_ARGS"
PREAMBLE_END = "// ------------------------------------------------------------------- catalog"

VALID = {
    "outputDir": "/o",
    "pluginRoot": "/p",
    "threatModel": "BOTH",
    "severityFilter": "all",
    "workerModel": "sonnet",
}

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


def _preamble() -> str:
    src = WORKFLOW.read_text(encoding="utf-8")
    return src[src.index(PREAMBLE_START) : src.index(PREAMBLE_END)]


def resolve(args_literal: str, tmp_path: Path) -> tuple[bool, str]:
    """Run the real preamble with `args` bound to `args_literal`; return (accepted, output)."""
    script = tmp_path / "probe.mjs"
    script.write_text(
        "import fs from 'fs';\n"
        f"const pre = fs.readFileSync({json.dumps(str(tmp_path / 'pre.js'))}, 'utf8');\n"
        "const fn = new Function('args', pre + '\\nreturn JSON.stringify("
        "{OUTPUT_DIR, PLUGIN_ROOT, THREAT_MODEL, SEVERITY_FILTER, SCOPE, CONTEXT_ROOTS, "
        "WORKER_MODEL, LINES_PER_AGENT});');\n"
        f"try {{ process.stdout.write('OK' + fn({args_literal})); }}\n"
        "catch (e) { process.stdout.write('ERR' + e.message); }\n",
        encoding="utf-8",
    )
    (tmp_path / "pre.js").write_text(_preamble(), encoding="utf-8")
    out = subprocess.run(["node", str(script)], capture_output=True, text=True, check=True).stdout
    return out.startswith("OK"), out[2:] if out.startswith("OK") else out[3:]


def test_an_args_object_is_accepted(tmp_path):
    ok, _ = resolve(json.dumps(VALID), tmp_path)
    assert ok


def test_a_json_encoded_args_string_is_accepted(tmp_path):
    """The shape that lost a cell. A model that stringifies once too often is not an error."""
    ok, _ = resolve(json.dumps(json.dumps(VALID)), tmp_path)
    assert ok


def test_both_forms_resolve_to_identical_configuration(tmp_path):
    """The one that matters: accepting the string form must not change the measurement."""
    ok_obj, as_obj = resolve(json.dumps(VALID), tmp_path)
    ok_str, as_str = resolve(json.dumps(json.dumps(VALID)), tmp_path)
    assert ok_obj and ok_str
    assert json.loads(as_obj) == json.loads(as_str)


@pytest.mark.parametrize(
    ("literal", "because"),
    [
        ('"{not json"', "a string that is not JSON"),
        ('"[1,2,3]"', "a JSON array, which is not an args object"),
        ("null", "no args at all"),
        ("undefined", "no args at all"),
        ('JSON.stringify({outputDir: "/o"})', "a string missing required keys"),
    ],
)
def test_bad_args_are_still_refused(literal, because, tmp_path):
    """Leniency about the *encoding* must not become leniency about the *content*."""
    ok, message = resolve(literal, tmp_path)
    assert not ok, f"{because} was accepted: {message}"
    assert "c-review:" in message


# ---------------------------------------------------------------- shell quoting


def _shq_and(tail: str, tmp_path: Path) -> str:
    """Run the real `shq` (and anything else named) against a value, through node."""
    src = WORKFLOW.read_text(encoding="utf-8")
    start = src.index("function shq(value) {")
    block = src[start : src.index("\n}\n", start) + 2]
    out = subprocess.run(["node", "-e", block + tail], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def test_shq_makes_a_dollar_sign_and_a_backtick_inert(tmp_path):
    """`JSON.stringify` is a JSON encoder, not a shell quoter.

    Inside bash double quotes `\\"` and `\\\\` survive but `$` and backticks stay live, so
    `outputDir` of `/tmp/c-review-$USER/run` silently became `/tmp/c-review-/run` and the
    unit list landed where the assembler never looks.
    """
    quoted = _shq_and("process.stdout.write(shq('/tmp/c-review-$USER/run'))", tmp_path)
    assert quoted == "'/tmp/c-review-$USER/run'"
    echoed = subprocess.run(
        ["bash", "-c", "printf %s " + quoted], capture_output=True, text=True, check=True
    ).stdout
    assert echoed == "/tmp/c-review-$USER/run"


def test_shq_survives_an_embedded_single_quote_and_a_command_substitution(tmp_path):
    """`partId` comes from `detect.assignment_ids`, which is model output influenced by the
    reviewed source tree, and is interpolated into a command the assemble agent is told to
    run exactly."""
    for value in ["it's", "$(touch /tmp/pwned)", "a`whoami`b", "x\\y"]:
        quoted = _shq_and("process.stdout.write(shq(" + json.dumps(value) + "))", tmp_path)
        echoed = subprocess.run(
            ["bash", "-c", "printf %s " + quoted], capture_output=True, text=True, check=True
        ).stdout
        assert echoed == value, value


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("maxUnitLines", "200"),
        ("reviewAgents", "8"),
        ("linesPerAgent", "1500"),
        ("benchmarkMode", "true"),
        ("invariantAudit", "true"),
        ("maxUnitLines", True),
        # Coerced, `findingScopeRootAbs: ['/a']` reaches `normalizePath` as `/a` and the
        # assembler as a `--scope-abs` operand nothing starts with, silently halving the
        # spellings both sides fold.
        ("findingScopeRootAbs", ["/a"]),
        # A bare string would iterate as characters if coerced; each entry becomes an
        # `--exclude` shell operand, so the element type is load-bearing too.
        ("exclude", "src/generated"),
        ("exclude", [1]),
        ("exclude", [""]),
    ],
)
def test_a_wrong_typed_optional_arg_is_refused_not_silently_defaulted(key, value, tmp_path):
    """Every REQUIRED arg is validated with a named throw; the optional ones must be too.

    `benchmarkMode: "true"` is the expensive one: `=== true` is false for the string, so a
    silent fallback leaves benchmark mode OFF — the two required schema fields gone,
    `--benchmark-mode` not passed, `declarations_seen` 0 — and a scored eval run measures
    the un-instrumented protocol while SKILL.md tells the caller these "default correctly".
    """
    ok, message = resolve(json.dumps({**VALID, key: value}), tmp_path)
    assert not ok, f"args.{key}={value!r} was accepted"
    assert key in message and "must be a" in message


def test_an_absent_optional_arg_still_takes_its_default(tmp_path):
    ok, resolved = resolve(json.dumps(VALID), tmp_path)
    assert ok
    assert json.loads(resolved)["LINES_PER_AGENT"] == 1500


@pytest.mark.parametrize(
    "bad", ["unit-01'; echo PWNED; #", "unit=01", "../../etc/passwd", "unit 01", "", "UNIT-01"]
)
def test_the_assignment_id_charset_refuses_everything_that_escapes(bad, tmp_path):
    """`assignment.id` is model output that becomes a shell word, an `--expect ID=COUNT`
    operand and a part-file stem. An `=` mis-splits `check_expectations`; a `/` or `..`
    escapes the parts directory; a `'` closes a hand-rolled quote."""
    src = WORKFLOW.read_text(encoding="utf-8")
    line = re.search(r"^const ASSIGNMENT_ID = .*$", src, re.M)
    assert line, "no `const ASSIGNMENT_ID` in the workflow — the id charset moved"
    script = (
        line.group(0) + ";process.stdout.write(String(ASSIGNMENT_ID.test(" + json.dumps(bad) + ")))"
    )
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout
    assert out == "false", f"{bad!r} passed the assignment-id charset"
    good = subprocess.run(
        [
            "node",
            "-e",
            line.group(0) + ";process.stdout.write(String(ASSIGNMENT_ID.test('unit-01')))",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert good == "true", "the charset rejects the ids enumerate_units.py actually emits"


# Every prompt builder whose output goes to an agent dispatched through `producingOpts`.
PRODUCING_PROMPT_BUILDERS = (
    "partBlock",
    "contextBlock",
    "scopeBlock",
    "severityBlock",
    "reviewPrompt",
    "invariantSweepPrompt",
    "classSweepPrompt",
    "dedupPrompt",
)

# The const prompt blocks those builders interpolate BY REFERENCE, so the function bodies
# hold only the identifier and a scan of the bodies alone sees none of this text. Most of
# the words a producing worker reads live here: without this list, inserting "If the Write
# tool is refused, use a Bash heredoc with a quoted delimiter instead." into
# `REVIEW_ESCAPE_HATCH` leaves the whole suite green.
PRODUCING_PROMPT_CONSTS = (
    "EVIDENCE_RULE",
    "EXTERNAL_SOURCE_DECLARATION",
    "REVIEW_ESCAPE_HATCH",
    "ESCAPE_HATCH",
    "CLASS_SWEEP_ESCAPE_HATCH",
    "DEDUP_RULES",
    "SEVERITY_TABLES",
)


def _function_body(src: str, name: str) -> str:
    start = src.index("\nfunction " + name + "(")
    return re.sub(r"//[^\n]*", "", src[start : src.index("\n}\n", start) + 2])


def _prompt_consts(src: str) -> dict[str, str]:
    """`const NAME = [ … ].join(…)` blocks, by name, comments stripped.

    Shape, not a name list: `GROUPS` is also `const GROUPS = [` and is data rather than
    prompt text, and it is excluded because its block closes with `]` and no `.join`.
    """
    out: dict[str, str] = {}
    starts = [m for m in re.finditer(r"^const ([A-Z][A-Z0-9_]*) = \[$", src, re.M)]
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(src)
        block = src[match.start() : end]
        close = block.find("\n].join(")
        if close != -1:
            out[match.group(1)] = re.sub(r"//[^\n]*", "", block[:close])
    return out


def test_no_producing_prompt_offers_a_shell_fallback():
    """A producing worker is dispatched through `agents/c-review-worker.md`, whose `tools:`
    list has no Bash. A prompt that hands a shell command to an agent with no shell is at
    best a dead end and at worst an instruction to go looking for one.

    The scan has to cover every producer, not one: slicing `partBlock` alone leaves
    `dedupPrompt`, which does not call it and carries its own copy of the sentence, telling
    a shell-less agent to fall back to `Bash`. Eight FUNCTIONS is still not enough, because
    most of the prompt text lives in the seven `const … = [...]` blocks they interpolate by
    reference. Both sets are scanned and both are asserted against the file, so a new one
    cannot be omitted from either.
    """
    src = WORKFLOW.read_text(encoding="utf-8")
    declared = {
        m.group(1)
        for m in re.finditer(r"^function (\w+(?:Prompt|Block))\(", src, re.M)
        if m.group(1) not in ("detectPrompt", "assemblePrompt")
    }
    assert declared == set(PRODUCING_PROMPT_BUILDERS), (
        f"the producing prompt builders moved: {sorted(declared)}. Add it to the list, or "
        f"to the detect/assemble exemption with a reason."
    )
    # Every multi-line prompt const in the file, so a new one is a failure rather than a
    # blind spot.
    consts = _prompt_consts(src)
    assert set(consts) == set(PRODUCING_PROMPT_CONSTS), (
        f"the prompt const blocks moved: {sorted(consts)}. Add it to the list with a "
        f"reason, or the text inside it is unscanned."
    )
    # Each block really holds its own text, so a helper that silently returns "" would fail
    # here rather than pass every assertion below by matching nothing.
    assert "EVIDENCE RULE" in consts["EVIDENCE_RULE"]
    assert "ONLY WRITE UP WHAT IS YOURS" in consts["REVIEW_ESCAPE_HATCH"]
    bodies = [(n, _function_body(src, n)) for n in PRODUCING_PROMPT_BUILDERS]
    bodies += [(n, consts[n]) for n in PRODUCING_PROMPT_CONSTS]
    for name, body in bodies:
        assert "cat >" not in body, name
        assert "heredoc" not in body.lower(), name
        assert "Bash" not in body, name


# Operands that are integers `bounded()` has already range-checked, so they cannot carry a
# shell metacharacter, plus EXCLUDE_FLAGS, whose every element went through `shq` where the
# string was built — test_exclude_flags_are_shell_quoted_where_they_are_built holds that.
UNQUOTED_NUMERIC_OPERANDS = {
    "MAX_UNIT_LINES",
    "LINES_PER_AGENT",
    "AGENT_MAX",
    "REVIEW_AGENTS",
    "EXCLUDE_FLAGS",
}


def test_exclude_flags_are_shell_quoted_where_they_are_built():
    """EXCLUDE_FLAGS is spliced verbatim into the detect command, so the shq scan above
    allowlists the name — which is only sound while every element is quoted at the build
    site. An entry of `src'; echo PWNED; #` otherwise reaches the shell live."""
    src = WORKFLOW.read_text(encoding="utf-8")
    build = re.search(r"^const EXCLUDE_FLAGS = .*$", src, re.M)
    assert build, "no `const EXCLUDE_FLAGS` in the workflow — the builder moved"
    assert "shq(" in build.group(0), build.group(0)


def _command_regions(src: str) -> list[tuple[str, str]]:
    """The two places in the workflow that build a shell command, comments stripped."""
    detect = src.index("const cmd =", src.index("function detectPrompt("))
    assemble = src.index("const parts = [", src.index("function assemblePrompt("))
    regions = [
        ("detectPrompt", src[detect : src.index("\n\n", detect)]),
        ("assemblePrompt", src[assemble : src.index("return [", assemble)]),
    ]
    for name, text in regions:
        assert "--" in text, f"the {name} command region no longer holds a command"
    return [(name, re.sub(r"//[^\n]*", "", text)) for name, text in regions]


def test_every_operand_interpolated_into_a_command_goes_through_shq():
    """Every operand must be REQUIRED to go through `shq`, not merely forbidden to use
    `JSON.stringify`.

    A line-oriented scan hides an offender behind a newline (`'--scope ' +\n
    JSON.stringify(SCOPE)`), and a floor like `len(shq lines) >= 10` absorbs six removals
    out of sixteen — so `'--scope ' + SCOPE` and `parts.push('--expect ' + e)`, the
    model-controlled part-id path, both pass. This finds every `+ <operand>` in the two
    command regions and names the operand.

    It also finds `${…}`, because matching only `+ IDENT` lets a rewrite of
    `'--scope ' + shq(SCOPE),` into the template literal `` `--scope ${SCOPE}`, `` remove
    the `+`, remove the operand, and pass. `SCOPE` is `findingScopeRoot` straight from the
    caller, validated only as a string.
    """
    src = WORKFLOW.read_text(encoding="utf-8")
    operands = []
    for name, region in _command_regions(src):
        # Newlines collapsed FIRST: the concatenation continues across them and a
        # line-oriented scan cannot see an operand on the next line.
        flat = " ".join(region.split())
        operands += [(name, m.group(1)) for m in re.finditer(r"\+\s*([A-Za-z_$][\w$.]*)", flat)]
        # `${…}` is the other way to interpolate, and it does not need a `+` at all. The
        # whole expression is captured so `${shq(SCOPE)}` reads as quoted and `${SCOPE}`
        # does not.
        operands += [
            (name, m.group(1).strip().split("(")[0].strip())
            for m in re.finditer(r"\$\{([^}]*)\}", flat)
        ]
    assert len(operands) >= 15, f"only {len(operands)} interpolated operand(s); the scan broke"
    quoted = [o for o in operands if o[1] == "shq"]
    assert len(quoted) >= 12, f"only {len(quoted)} go through shq; the builders moved"
    offenders = [
        f"{n}: {o}" for n, o in operands if o != "shq" and o not in UNQUOTED_NUMERIC_OPERANDS
    ]
    assert offenders == [], offenders
    # The `${…}` half of the scan is not passing by matching nothing.
    probe = " ".join(["const", "cmd", "=", "`--scope", "${SCOPE}`"])
    assert [m.group(1) for m in re.finditer(r"\$\{([^}]*)\}", probe)] == ["SCOPE"]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("maxUnitLines", 10),
        ("maxUnitLines", 39),
        ("linesPerAgent", 100),
        ("reviewAgents", 0),
        ("reviewAgents", -5),
        # `AGENT_MAX = Math.max(14, REVIEW_AGENTS)`, so this number is also the enumerator's
        # cap and the `parallel()` fan-out: unbounded, `reviewAgents: 5000` resolves to
        # `--agents 5000 --agent-max 5000` and dispatches 5000 agents. The model-controlled
        # path is capped elsewhere; this is the caller-supplied one.
        ("reviewAgents", 5000),
        # `bounded` returns `Math.floor(value)` and the result is string-concatenated into
        # the detect command, so a huge number reaches argparse as `--max-unit-lines 1e+21`
        # and `type=int` rejects it — killing the run after the fan-out has been decided.
        ("maxUnitLines", 1e21),
        ("workerModel", 5),
        ("workerModel", False),
    ],
)
def test_an_out_of_range_optional_arg_throws_rather_than_defaulting(key, value, tmp_path):
    """`optional()`'s own error text says a wrong value "is not defaulted: a wrong type here
    changes what the run measures" — and a value of the right type but outside the usable
    range does exactly that, silently. A caller pinning `reviewAgents: 0` for a measured
    comparison gets the derived 4-14 fan-out and believes it pinned 0, and `workerModel: 5`
    becomes the string "5" on every agent and on the assembler's command line."""
    ok, message = resolve(json.dumps(dict(VALID, **{key: value})), tmp_path)
    assert not ok, f"{key}={value!r} was accepted: {message}"
    assert "args." + key in message


@pytest.mark.parametrize("value", [40, 150, 1000])
def test_an_in_range_optional_arg_is_still_honoured(value, tmp_path):
    ok, message = resolve(json.dumps(dict(VALID, maxUnitLines=value)), tmp_path)
    assert ok, message


def test_assignment_ids_is_required_by_the_detect_schema():
    """A schema-valid detect return that omits it throws *after* enumerate_units.py has
    parsed the tree and written every assignment file, and nothing is recoverable."""
    src = WORKFLOW.read_text(encoding="utf-8")
    block = src[src.index("const DETECT_SCHEMA = {") : src.index("const LEDGER_ROW = {")]
    required = block[block.index("required: [") : block.index("],", block.index("required: ["))]
    assert "'assignment_ids'" in required


# -------------------------------------------------- what SKILL.md has to hand the workflow

SKILL_MD = Path(__file__).resolve().parents[1] / "skills" / "c-review" / "SKILL.md"


def test_the_skill_resolves_the_scope_root_the_workflow_cannot():
    """A Workflow script has no filesystem APIs, so `findingScopeRootAbs` is the only route by
    which the absolute spelling of the scope root reaches `normalizePath`. Drop it from the
    example and every run goes back to folding one spelling: with `findingScopeRoot: 'src'`,
    `/repo/src/a.c` and `a.c` stop being the same file and one bug is reported twice."""
    doc = SKILL_MD.read_text(encoding="utf-8")
    # The CALL, not the prose around it: a paragraph explaining the argument keeps a
    # whole-document substring check green over an example that stopped passing it.
    start = doc.index("Workflow({")
    call = doc[start : doc.index("})", start)]
    assert "findingScopeRootAbs:" in call, call
    assert "scope_abs=" in doc, "Phase 1 no longer resolves the scope root with Bash"
    assert "findingScopeRootAbs" in WORKFLOW.read_text(encoding="utf-8")


def test_the_plugin_root_fallback_never_searches_the_audited_tree():
    """`find ~/.claude . -path '*/c-review/workflows/c-review.js' -print -quit` takes the
    FIRST hit in traversal order, and `.` is the repository under audit: a tree that vendors
    or mirrors this marketplace runs its own copy of the scripts — a different site-kind
    table and question set — and nothing reports which copy ran. The `2>/dev/null` on it also
    hid a missing search root, which is a failure to report and not noise."""
    lines = [
        ln
        for ln in SKILL_MD.read_text(encoding="utf-8").splitlines()
        if "find " in ln and "c-review.js" in ln
    ]
    assert lines, "SKILL.md no longer resolves the plugin root by search"
    for line in lines:
        args = line[line.index("find ") + len("find ") :].split()
        roots = list(itertools.takewhile(lambda a: not a.startswith("-"), args))
        assert roots in (['"$HOME/.claude"'], ["~/.claude"]), line
        assert "2>/dev/null" not in line, line


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
