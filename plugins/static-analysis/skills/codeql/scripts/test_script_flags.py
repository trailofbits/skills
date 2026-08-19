"""Every flag the docs pass to this plugin's own scripts must be a flag they accept.

`codeql-build.js` shipped `check_db_quality.py --json`. The script takes
`--format {text,json}`, so argparse exited 2 on the Assess phase's first command --
and 2 is the one exit code the workflow's schema does not describe, so the failure
read as an unknown status rather than a typo.

Nothing caught it because the two call sites live in different trees:
`test_shell_blocks.py` lints markdown under the skill, and `codeql-build.js` sits
outside it under the plugin's `workflows/`. This check scans the whole plugin, both
file types, and asks the scripts themselves what they accept.

Hermetic: the scripts are stdlib-only, so `--help` runs under the ambient
interpreter. No CodeQL, no uv, no network.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = SCRIPTS_DIR.parent.parent.parent
SKIP_DIRS = {".pytest_cache", "__pycache__", ".venv", ".ruff_cache"}

# Anything after one of these belongs to the next command, not to the script.
COMMAND_END = re.compile(r"[|;)`]|&&|\|\|")
LONG_FLAG = re.compile(r"--[A-Za-z][A-Za-z0-9-]*")


def _argparse_scripts() -> list[Path]:
    """The scripts that parse flags, discovered rather than listed.

    A hardcoded list stops covering a script the moment someone adds one.
    """
    return sorted(
        p
        for p in SCRIPTS_DIR.glob("*.py")
        if not p.name.startswith("test_") and "add_argument" in p.read_text(encoding="utf-8")
    )


def _accepted_flags(script: Path) -> set[str]:
    """What the script really takes, from its own --help."""
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, (
        f"{script.name} --help exited {result.returncode}, so its accepted flags could "
        f"not be read:\n{result.stderr}"
    )
    return set(LONG_FLAG.findall(result.stdout))


ACCEPTED = {script.name: _accepted_flags(script) for script in _argparse_scripts()}


def _doc_files() -> list[Path]:
    return sorted(
        p
        for p in PLUGIN_ROOT.rglob("*")
        if p.suffix in {".md", ".js"}
        and not SKIP_DIRS.intersection(p.parts)
        and not p.name.startswith("test_")
    )


# An invocation names the script by path — `{baseDir}/scripts/x.py`, `${SKILL_DIR}/scripts/x.py`.
# A bare mention is prose: a comment reading "the workflow passed check_db_quality.py a --json
# flag" is not a call site, and reporting it as one made this check fail on its own changelog.
INVOCATION = re.compile(r"/(" + "|".join(re.escape(n) for n in ACCEPTED) + r")(?=\s|$)")


def _invocations() -> list[tuple[Path, int, str, str]]:
    """Every (file, line, script, flag) the plugin documents.

    Flags are read from the text between the script name and the end of that command,
    so the `jq -r` in `$(… --format=json | jq -r '.x')` is not mistaken for the
    script's own.
    """
    found: list[tuple[Path, int, str, str]] = []
    for path in _doc_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in INVOCATION.finditer(line):
                tail = line[match.end() :]
                end = COMMAND_END.search(tail)
                if end:
                    tail = tail[: end.start()]
                for flag in LONG_FLAG.findall(tail):
                    found.append((path, lineno, match.group(1), flag))
    return found


ALL_INVOCATIONS = _invocations()


def test_scripts_were_discovered() -> None:
    """Guard the guard: no scripts found turns every check below into a no-op."""
    assert len(ACCEPTED) >= 2, (
        f"only {len(ACCEPTED)} argparse scripts found in {SCRIPTS_DIR} — discovery is "
        f"broken, not the skill"
    )
    for name, flags in ACCEPTED.items():
        assert flags, f"{name} --help listed no long flags, so nothing can be checked against it"


def test_flagged_invocations_were_found() -> None:
    """A regex that matches nothing would pass this file silently.

    Deliberately low: deduplicating the docs legitimately removes call sites, and this
    guard is here to catch a scanner that finds nothing at all, not to pin a count.
    """
    assert len(ALL_INVOCATIONS) >= 2, (
        f"only {len(ALL_INVOCATIONS)} flagged script invocations extracted from "
        f"{PLUGIN_ROOT} — the scanner is broken, not the docs"
    )


def test_the_workflow_is_in_scope() -> None:
    """The file the original bug shipped in must be one of the files scanned.

    It lives outside the skill tree, which is why the markdown linters missed it.
    """
    workflow = PLUGIN_ROOT / "workflows" / "codeql-build.js"
    assert workflow.exists(), f"{workflow} is gone — update this check to match"
    assert workflow in _doc_files(), (
        f"{workflow.name} is no longer scanned, so a bad flag in the workflow would ship again"
    )


@pytest.mark.parametrize(
    ("path", "line", "script", "flag"),
    ALL_INVOCATIONS,
    ids=[f"{p.relative_to(PLUGIN_ROOT)}:{ln}:{flag}" for p, ln, _, flag in ALL_INVOCATIONS],
)
def test_documented_flag_exists(path: Path, line: int, script: str, flag: str) -> None:
    accepted = ACCEPTED[script]
    assert flag in accepted, (
        f"{path.relative_to(PLUGIN_ROOT)}:{line} passes {flag} to {script}, which does "
        f"not accept it. argparse exits 2 on an unrecognised flag. Accepted: "
        f"{', '.join(sorted(accepted))}"
    )


def test_the_scanner_tells_an_invocation_from_a_mention() -> None:
    """Both directions, because getting either wrong disables the check quietly.

    A prose mention counted as a call site makes the check fail on documentation that
    merely discusses a flag. A real call site missed makes it pass on a broken command.
    """
    script = next(iter(ACCEPTED))
    assert not INVOCATION.search(f"the workflow passed {script} a --json flag"), (
        "a bare mention in prose is being read as an invocation"
    )
    for real in (
        f'uv run {{baseDir}}/scripts/{script} "$DB_NAME" --format=json',
        f'  uv run ${{SKILL_DIR}}/scripts/{script} "$DB_NAME" --format=json',
    ):
        assert INVOCATION.search(real), f"a real invocation is not being scanned: {real}"
