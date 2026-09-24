from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "validate-patch.js"
# The meta object is the only top-level brace closed at column 0; everything after it is body.
META_END_RE = re.compile(r"^\}$", flags=re.MULTILINE)


def source() -> str:
    assert WORKFLOW.is_file(), f"workflow missing: {WORKFLOW}"
    return WORKFLOW.read_text()


def test_node_is_available() -> None:
    assert shutil.which("node"), "node is required for the syntax check and must not be skipped"


def test_workflow_is_valid_javascript(tmp_path: Path) -> None:
    """`node --check` on the script body, wrapped the way the runtime wraps it.

    The raw file parses under neither module system: as CommonJS it trips on `export`, and as
    an ES module it trips on the top-level `return` guards. Both are legal in the Workflow
    runtime, which strips `meta` and runs the body in an async function. Checking the file
    as-shipped therefore fails on every Node version, which is how this test shipped red.
    """
    text = source()
    end = META_END_RE.search(text)
    assert end, "could not locate the end of the meta block"
    body = text[end.end() :]
    wrapped = tmp_path / "validate-patch.check.mjs"
    wrapped.write_text(f"async function __wf(args, log, phase, agent, parallel) {{\n{body}\n}}\n")
    result = subprocess.run(
        ["node", "--check", str(wrapped)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_meta_and_phase_calls_agree() -> None:
    text = source()
    meta_block = text[text.index("phases: [") : text.index("  ],", text.index("phases: ["))]
    declared = re.findall(r"title: '([^']+)'", meta_block)
    called = re.findall(r"^phase\('([^']+)'\)$", text, flags=re.MULTILINE)
    assert declared == ["Inventory", "Coverage", "Plan", "Execute", "Review"]
    assert called == declared


def test_every_agent_call_has_a_schema_and_phase() -> None:
    text = source()
    fragments = text.split("agent(")[1:]
    assert len(fragments) == 5, "expected five fixed agent call sites"
    for fragment in fragments:
        before_next = fragment.split("agent(", 1)[0]
        assert "{ schema:" in before_next
        assert "phase:" in before_next
    assert text.count("additionalProperties: false") >= 5


def test_workflow_has_no_nondeterministic_or_self_verification_scaffolding() -> None:
    text = source()
    for banned in ["Math.random", "Date.now", "new Date", "Promise.race", "double-check"]:
        assert banned not in text


def test_machine_assessment_is_not_changed_by_reviewers() -> None:
    text = source()
    assert "const status = finalStatus(execution.assessment, reviews)" in text
    assert "assessment: execution.assessment" in text
    assert "schema: EXECUTION_SCHEMA" in text


def test_workflow_carries_evidence_scope_and_check_contracts() -> None:
    text = source()
    assert "'--evidence-level', 'source'" in text
    assert "evidenceLevel: execution.evidenceLevel" in text
    assert "Exploit and variant assertions must" in text
    assert "liveness, exact error type, timing, and compatibility" in text
    assert "Preserve the scaffolded submodules list" in text


def test_workflow_routes_mechanical_phases_to_haiku_and_keeps_four_lenses() -> None:
    text = source()
    for key in ("root-cause", "behavior", "adjacent-security", "harness"):
        assert f"key: '{key}'" in text
    assert text.count("key: '") == 6  # four coverage lenses and two independent reviews
    assert text.count("model: 'haiku', effort: 'low'") == 2  # inventory and execute only
    assert "model: 'sonnet'" not in text  # judgement phases keep the session's model and effort
    assert "git diff -U3" in text
    assert "verify_evidence.py" in text
    assert "evidenceVerified" in text
    assert "JSON.stringify(inventoryArgv)" in text and "JSON.stringify(executionArgv)" in text
