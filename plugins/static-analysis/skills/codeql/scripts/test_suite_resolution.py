"""Resolve the shipped suite templates with the real CodeQL CLI.

The hermetic suites cannot do this. `test_generation_scripts.py` runs the generator
against a fake CLI, which proves the script's control flow and nothing about whether the
`.qls` it writes is valid. `test_suite_templates.py` checks the template's structure,
which is a text property. Only CodeQL can say whether a suite resolves, and to what.

Requires the CodeQL CLI plus `codeql/cpp-queries`. Skipped without them, with a reason
that says which of the two is missing — the hermetic suites still run in that case, so a
skip here does not leave the templates unchecked, it leaves them checked less deeply. CI
has neither and reports every test in this file as a skip; run it locally, and after any
CodeQL upgrade.

    codeql pack download codeql/cpp-queries
    uv run --with pytest python3 -m pytest test_suite_resolution.py -v
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).resolve().parent.parent
YAML_BLOCK = re.compile(r"^```yaml\n(.*?)^```", re.MULTILINE | re.DOTALL)

# run-all-suite.md tells the reader to "confirm on your own packs" with this file, so the
# language has to be selectable. Defaults to cpp, which is what the documented counts were
# measured against.
LANGUAGE = os.environ.get("CODEQL_TEST_LANGUAGE", "cpp")
SAQ = f"codeql/{LANGUAGE}-queries:codeql-suites/{LANGUAGE}-security-and-quality.qls"
SEC = f"codeql/{LANGUAGE}-queries:codeql-suites/{LANGUAGE}-security-experimental.qls"


def _resolve(target: str) -> set[str]:
    result = subprocess.run(
        ["codeql", "resolve", "queries", target, "--format=json"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"codeql could not resolve {target}: {result.stderr.strip()}")
    return set(json.loads(result.stdout))


def _unavailable() -> str | None:
    """Why this file cannot run here, or None if it can.

    Split by cause rather than reported as one reason. "no CLI" is a machine that was
    never going to run these; "CLI but no pack" is one command away, and a single message
    covering both makes those look identical in a run that is otherwise all skips.
    """
    if not shutil.which("codeql"):
        return "needs the CodeQL CLI — not on PATH"
    probe = subprocess.run(
        ["codeql", "resolve", "queries", SAQ, "--format=json"], capture_output=True, text=True
    )
    if probe.returncode != 0:
        return (
            f"CodeQL is installed but {SAQ} does not resolve — "
            f"run `codeql pack download codeql/{LANGUAGE}-queries`"
        )
    return None


UNAVAILABLE = _unavailable()

requires_codeql = pytest.mark.skipif(UNAVAILABLE is not None, reason=UNAVAILABLE or "")


def _template(doc: Path) -> str:
    blocks = YAML_BLOCK.findall(doc.read_text(encoding="utf-8"))
    assert len(blocks) == 1, f"expected one yaml template in {doc.name}, got {len(blocks)}"
    return blocks[0].replace("<CODEQL_LANG>", LANGUAGE)


@requires_codeql
def test_run_all_template_resolves_to_queries(tmp_path: Path) -> None:
    """The shipped template must produce a working suite, not just plausible YAML."""
    suite = tmp_path / "run-all.qls"
    suite.write_text(_template(SKILL_ROOT / "references" / "run-all-suite.md"))
    assert len(_resolve(str(suite))) > 0


@requires_codeql
def test_the_two_official_suites_are_genuinely_complementary() -> None:
    """The claim the docs make, tested rather than asserted as text.

    Neither suite is a superset. Importing only security-and-quality drops every
    experimental security query, and that loss is invisible in the results.
    """
    saq, sec = _resolve(SAQ), _resolve(SEC)
    assert sec - saq, "security-experimental adds nothing; the docs' rationale is wrong"
    assert saq - sec, "security-and-quality adds nothing; the docs' rationale is wrong"


@requires_codeql
def test_run_all_resolves_to_the_union_of_both(tmp_path: Path) -> None:
    """Importing both must yield every query from either, with CodeQL deduplicating."""
    suite = tmp_path / "run-all.qls"
    suite.write_text(_template(SKILL_ROOT / "references" / "run-all-suite.md"))

    resolved = _resolve(str(suite))
    union = _resolve(SAQ) | _resolve(SEC)
    missing = union - resolved
    assert not missing, f"{len(missing)} queries in the official suites are not in run-all"


@requires_codeql
def test_important_only_is_not_a_subset_of_run_all(tmp_path: Path) -> None:
    """The modes select by different mechanisms, so neither contains the other.

    run-all `import:`s two official suites. important-only takes `queries: .` — the whole
    pack — and filters on precision. So important-only can select a query that is in the
    pack but in neither official suite.

    Documented because it is counter-intuitive: "run all" does not run everything
    "important only" runs. Assert the surprising direction so nobody quietly relies on
    the subset relationship the names imply.
    """
    run_all = tmp_path / "run-all.qls"
    run_all.write_text(_template(SKILL_ROOT / "references" / "run-all-suite.md"))
    important = tmp_path / "important-only.qls"
    important.write_text(_template(SKILL_ROOT / "references" / "important-only-suite.md"))

    important_queries = _resolve(str(important))
    assert important_queries, "important-only resolved to zero queries"
    assert important_queries - _resolve(str(run_all)), (
        "important-only is now a subset of run-all. If the templates were changed to "
        "make that true, the caveat in run-all-suite.md should go with it."
    )


@requires_codeql
def test_run_all_does_not_resolve_the_whole_pack(tmp_path: Path) -> None:
    """ "Run all" imports two suites; it is not every alert query in the pack.

    Pinned so the docs cannot drift back to claiming total coverage. The omitted queries
    are mostly the coding-standard packs (jsf, JPL_C, Power of 10), which is a defensible
    choice — but Security/CWE and Critical queries go with them, and the mode name hides
    that.
    """
    run_all = tmp_path / "run-all.qls"
    run_all.write_text(_template(SKILL_ROOT / "references" / "run-all-suite.md"))

    whole_pack = tmp_path / "pack.qls"
    whole_pack.write_text(
        f"- description: whole pack\n- queries: .\n  from: codeql/{LANGUAGE}-queries\n"
        "- include:\n    kind:\n      - problem\n      - path-problem\n"
    )
    assert _resolve(str(whole_pack)) - _resolve(str(run_all)), (
        "run-all now covers every alert query in the pack; drop the caveat from the docs"
    )


@requires_codeql
def test_important_only_actually_narrows(tmp_path: Path) -> None:
    """If it does not filter, the two modes are the same scan under two names."""
    run_all = tmp_path / "run-all.qls"
    run_all.write_text(_template(SKILL_ROOT / "references" / "run-all-suite.md"))
    important = tmp_path / "important-only.qls"
    important.write_text(_template(SKILL_ROOT / "references" / "important-only-suite.md"))

    assert len(_resolve(str(important))) < len(_resolve(str(run_all)))
