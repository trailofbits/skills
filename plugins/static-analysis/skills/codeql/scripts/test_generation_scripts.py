"""Run generate_suite.sh for real, in both modes.

It writes the `.qls` that decides which queries run. Both modes previously lived as
copy-pasted bash inside two reference docs, and both ended with
`if ! codeql resolve queries "$SUITE_FILE" | wc -l; then` — a condition that can never
be true, since `wc` succeeding masks any CodeQL failure.

Runs against a fake `codeql` on PATH, so no CodeQL install is needed and the real
control flow is still exercised.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).resolve().parent.parent
BASH_BLOCK = re.compile(r"^```bash\n(.*?)^```", re.MULTILINE | re.DOTALL)

GENERATE_SUITE = SKILL_ROOT / "scripts" / "generate_suite.sh"
YAML_BLOCK = re.compile(r"^```yaml\n(.*?)^```", re.MULTILINE | re.DOTALL)


def _significant(text: str) -> list[str]:
    """Suite lines that carry meaning — comments and blanks are presentation."""
    return [
        ln.rstrip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    ]


def _invocation_block(doc: Path) -> str:
    """The bash block that calls generate_suite.sh."""
    blocks = [
        b for b in BASH_BLOCK.findall(doc.read_text(encoding="utf-8")) if "generate_suite.sh" in b
    ]
    if len(blocks) != 1:
        pytest.fail(f"expected one invocation block in {doc.name}, found {len(blocks)}")
    return blocks[0]


# The doc that documents each mode. Both must invoke the script rather than inlining it
# again, or the duplication this script replaced grows back unnoticed.
SUITES = {
    "important-only": SKILL_ROOT / "references" / "important-only-suite.md",
    "run-all": SKILL_ROOT / "references" / "run-all-suite.md",
}


def test_the_docs_invoke_the_script_rather_than_inlining_it() -> None:
    """Guard the guard: these tests exercise the script, not what the docs tell an agent.

    If a doc grows its own `cat > "$SUITE_FILE" << HEADER` again, everything below still
    passes while the skill runs unverified bash.
    """
    for name, doc in sorted(SUITES.items()):
        text = doc.read_text(encoding="utf-8")
        assert f"generate_suite.sh {name}" in text, f"{doc.name} no longer calls the script"
        inlined = [b for b in BASH_BLOCK.findall(text) if "<< HEADER" in b or "<<HEADER" in b]
        assert not inlined, f"{doc.name} inlines suite generation again: {inlined[0][:80]}"


@pytest.mark.parametrize("name", sorted(SUITES))
def test_the_invocation_block_propagates_failure(name: str) -> None:
    """A failed generation must fail the block an agent runs, not just the script.

    `generate_suite.sh` exits non-zero on an unset language and on a suite that resolves
    to nothing. Written with the `SUITE_FILE=` assignment last, the block discards that
    status and returns 0, and the run proceeds to analysis with no suite — or with a
    stale one from an earlier run. Rediscovered here after exactly that shipped.
    """
    block = _invocation_block(SUITES[name])
    assert "set -e" in block, f"{SUITES[name].name}: invocation block does not set -e"
    last = [
        ln.strip() for ln in block.splitlines() if ln.strip() and not ln.strip().startswith("#")
    ][-1]
    assert not re.match(r"[A-Z_]+=", last), (
        f"{SUITES[name].name}: the block ends with the assignment `{last}`, which "
        f"overwrites the script's exit status. Put the script call last."
    )


@pytest.mark.parametrize("name", sorted(SUITES))
def test_the_documented_template_matches_what_the_script_writes(name: str, tmp_path: Path) -> None:
    """The yaml template is a copy of logic that now lives in the script.

    Nothing else compares them: test_suite_templates.py checks the template's shape, so a
    filter changed in one place leaves every test green while the doc documents filters
    nobody runs. Neither resolves against the real CLI — that is a manual check now.
    """
    result = _run(name, tmp_path, env_extra={"CODEQL_LANG": "cpp"})
    assert result.returncode == 0, result.stderr

    blocks = YAML_BLOCK.findall(SUITES[name].read_text(encoding="utf-8"))
    assert len(blocks) == 1, f"expected one yaml template in {SUITES[name].name}"
    documented = _significant(blocks[0].replace("<CODEQL_LANG>", "cpp"))
    written = _significant(_suite_text(tmp_path, name))
    assert documented == written, (
        f"{SUITES[name].name}'s template no longer matches generate_suite.sh.\n"
        f"documented: {documented}\nwritten:    {written}"
    )


@pytest.mark.parametrize("name", sorted(SUITES))
def test_the_doc_names_the_path_the_script_writes(name: str, tmp_path: Path) -> None:
    """The doc assigns SUITE_FILE literally; the script derives it. Two definitions."""
    _run(name, tmp_path, env_extra={"CODEQL_LANG": "cpp"})
    written = next((tmp_path / "out" / "raw").glob("*.qls"))
    documented = f'SUITE_FILE="$OUTPUT_DIR/raw/{name}.qls"'
    assert documented in SUITES[name].read_text(encoding="utf-8"), (
        f"{SUITES[name].name} does not assign {documented}"
    )
    assert written.name == f"{name}.qls", (
        f"script wrote {written.name}, but the doc points at {name}.qls"
    )


def _fake_codeql(directory: Path, *, queries: int = 3, exit_code: int = 0) -> Path:
    """A stand-in for the CodeQL CLI that reports a controlled query count.

    It reads the suite it is handed and rejects one that is missing or empty, the way
    the real CLI would. An earlier version ignored its arguments entirely, so these
    tests would have passed even if the generator had written nothing at all.
    """
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / "codeql"
    payload = "[" + ", ".join(f'"q{i}.ql"' for i in range(queries)) + "]"
    script.write_text(
        "#!/bin/sh\n"
        "# Last argument is the suite path, as `codeql resolve queries ... -- FILE`.\n"
        'for arg in "$@"; do suite="$arg"; done\n'
        'if [ ! -s "$suite" ]; then\n'
        '  echo "fake codeql: no such suite or empty: $suite" >&2\n'
        "  exit 2\n"
        "fi\n"
        'if ! grep -q "^- " "$suite"; then\n'
        '  echo "fake codeql: $suite has no suite entries" >&2\n'
        "  exit 2\n"
        "fi\n"
        f"if [ {exit_code} -ne 0 ]; then\n"
        '  echo "fake codeql failure" >&2\n'
        f"  exit {exit_code}\n"
        "fi\n"
        f"echo '{payload}'\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return script


def _fake_uv(directory: Path) -> Path:
    """`uv run SCRIPT ARGS...` -> `python3 SCRIPT ARGS...`.

    The generation scripts invoke the guard via `uv run`. Relying on the real uv would
    make these tests depend on the ambient environment: CI runs pytest inside `uv run`,
    where uv is not on the child's PATH, so the suite passed locally and failed there.
    """
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / "uv"
    script.write_text(
        "#!/bin/sh\n"
        '[ "$1" = "run" ] && shift\n'
        "# Drop uv-only flags so the remaining argv is the script and its arguments.\n"
        "while [ $# -gt 0 ]; do\n"
        '  case "$1" in --no-project|--quiet|-q) shift ;; --with) shift 2 ;; *) break ;; esac\n'
        "done\n"
        'exec python3 "$@"\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return script


def _run(
    mode: str, tmp_path: Path, *, env_extra: dict[str, str], **fake
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    _fake_codeql(bin_dir, **fake)
    _fake_uv(bin_dir)
    output_dir = tmp_path / "out"
    (output_dir / "raw").mkdir(parents=True, exist_ok=True)

    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "OUTPUT_DIR": str(output_dir),
        **env_extra,
    }
    return subprocess.run(
        [str(GENERATE_SUITE), mode], capture_output=True, text=True, env=env, cwd=tmp_path
    )


def _suite_text(tmp_path: Path, name: str) -> str:
    matches = list((tmp_path / "out" / "raw").glob("*.qls"))
    assert matches, f"{name}: no .qls was written"
    return matches[0].read_text()


@pytest.mark.parametrize("name", sorted(SUITES))
def test_generates_a_suite_naming_the_language(name: str, tmp_path: Path) -> None:
    result = _run(name, tmp_path, env_extra={"CODEQL_LANG": "cpp"})
    assert result.returncode == 0, f"{name} generation failed:\n{result.stderr}"

    text = _suite_text(tmp_path, name)
    assert "codeql/cpp-queries" in text, f"{name}: CODEQL_LANG did not expand"
    assert "${CODEQL_LANG}" not in text, f"{name}: placeholder left unexpanded"


@pytest.mark.parametrize("name", sorted(SUITES))
def test_third_party_packs_are_included(name: str, tmp_path: Path) -> None:
    result = _run(
        name,
        tmp_path,
        env_extra={
            "CODEQL_LANG": "cpp",
            "INSTALLED_THIRD_PARTY_PACKS": "trailofbits/cpp-queries acme/cpp-queries",
        },
    )
    assert result.returncode == 0, result.stderr

    text = _suite_text(tmp_path, name)
    assert "trailofbits/cpp-queries" in text
    assert "acme/cpp-queries" in text, "second pack dropped — the loop only handled one"


@pytest.mark.parametrize("name", sorted(SUITES))
def test_generation_aborts_when_codeql_fails(name: str, tmp_path: Path) -> None:
    """The regression guard. This failed before the `| wc -l` pipeline was replaced."""
    result = _run(
        name,
        tmp_path,
        env_extra={"CODEQL_LANG": "cpp"},
        exit_code=2,
    )
    assert result.returncode != 0, (
        f"{name}: CodeQL failed but the script exited 0. A suite that cannot be resolved "
        f"will produce an empty SARIF that reads as a clean scan."
    )


@pytest.mark.parametrize("name", sorted(SUITES))
def test_generation_aborts_when_suite_resolves_to_zero_queries(name: str, tmp_path: Path) -> None:
    """Zero queries is the failure Essential Principle #3 exists to prevent."""
    result = _run(
        name,
        tmp_path,
        env_extra={"CODEQL_LANG": "cpp"},
        queries=0,
    )
    assert result.returncode != 0, (
        f"{name}: suite resolved to zero queries and the script exited 0 — analysis would "
        f"run and report no findings for a codebase it never examined."
    )


@pytest.mark.parametrize("name", sorted(SUITES))
def test_a_suite_that_fails_verification_is_deleted(name: str, tmp_path: Path) -> None:
    """Left on disk it is indistinguishable from a verified one.

    run-analysis Step 4 derives the same path, and the docs tell the model the generator
    already verified the suite — so the file that just failed gets analysed with, and the
    empty SARIF reads as a clean codebase.
    """
    result = _run(name, tmp_path, env_extra={"CODEQL_LANG": "cpp"}, queries=0)
    assert result.returncode != 0

    left = list((tmp_path / "out" / "raw").glob("*.qls"))
    assert not left, f"{name}: unverifiable suite left behind at {left}"


@pytest.mark.parametrize("name", sorted(SUITES))
def test_unset_language_aborts_before_writing_a_suite(name: str, tmp_path: Path) -> None:
    """The guard must precede the heredoc.

    Checked afterwards, an unset CODEQL_LANG leaves a suite naming `codeql/-queries` on
    disk for a later step to pick up.
    """
    result = _run(name, tmp_path, env_extra={})
    assert result.returncode != 0, f"{name}: unset CODEQL_LANG did not abort"

    for written in (tmp_path / "out" / "raw").glob("*.qls"):
        assert "codeql/-queries" not in written.read_text(), (
            f"{name}: wrote a suite naming the empty pack `codeql/-queries` before the "
            f"guard fired — the guard is still after the heredoc"
        )
