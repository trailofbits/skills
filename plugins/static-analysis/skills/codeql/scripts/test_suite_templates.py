"""Structural checks on the `.qls` templates in the suite reference docs.

A malformed or over-filtered template resolves to few or no queries, and the resulting
empty SARIF reads as a clean codebase.

Text-based rather than YAML-parsed: `make python-tests` runs pytest with no extra
dependencies, so importing PyYAML would fail on a clean checkout.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).resolve().parent.parent
YAML_BLOCK = re.compile(r"^```yaml\n(.*?)^```", re.MULTILINE | re.DOTALL)

IMPORTANT_ONLY = SKILL_ROOT / "references" / "important-only-suite.md"
RUN_ALL = SKILL_ROOT / "references" / "run-all-suite.md"
DOCS = {"important-only": IMPORTANT_ONLY, "run-all": RUN_ALL}


def _template(doc: Path) -> str:
    blocks = YAML_BLOCK.findall(doc.read_text(encoding="utf-8"))
    if len(blocks) != 1:
        pytest.fail(
            f"expected exactly one yaml template in {doc.name}, found {len(blocks)}. "
            f"The doc changed shape — update this test rather than deleting it."
        )
    return blocks[0]


def _entry_keys(template: str) -> list[str]:
    """Top-level list-entry keys, e.g. queries / import / include / exclude."""
    return re.findall(r"^- (\w+):", template, re.MULTILINE)


@pytest.mark.parametrize("name", sorted(DOCS))
def test_template_exists_and_is_non_trivial(name: str) -> None:
    template = _template(DOCS[name])
    assert len(template.splitlines()) > 5, f"{name}: template is too short to be real"


@pytest.mark.parametrize("name", sorted(DOCS))
def test_template_has_at_least_one_query_source(name: str) -> None:
    """A suite with no `queries:` or `import:` resolves to nothing."""
    keys = _entry_keys(_template(DOCS[name]))
    sources = [k for k in keys if k in {"queries", "import"}]
    assert sources, (
        f"{name}: template declares no query source — it would resolve to zero queries "
        f"and the analysis would report no findings"
    )


@pytest.mark.parametrize("name", sorted(DOCS))
def test_template_declares_the_language_placeholder(name: str) -> None:
    template = _template(DOCS[name])
    assert "<CODEQL_LANG>" in template, (
        f"{name}: template hardcodes a language instead of using <CODEQL_LANG>"
    )


@pytest.mark.parametrize("name", sorted(DOCS))
def test_template_selects_alert_queries_only(name: str) -> None:
    """Both suites restrict to problem/path-problem — the query kinds that produce alerts."""
    template = _template(DOCS[name])
    assert "include" in _entry_keys(template), f"{name}: no include block"
    assert "problem" in template and "path-problem" in template, (
        f"{name}: does not restrict to alert-producing query kinds"
    )


@pytest.mark.parametrize("name", sorted(DOCS))
def test_template_excludes_deprecated_and_model_queries(name: str) -> None:
    template = _template(DOCS[name])
    assert "deprecated" in template, f"{name}: does not exclude deprecated queries"
    assert "modeleditor" in template and "modelgenerator" in template, (
        f"{name}: does not exclude model editor/generator queries, which are tooling "
        f"support rather than alerts"
    )


def test_important_only_covers_every_precision_it_claims() -> None:
    """The doc's Phase 1 table promises high, very-high, and medium. Pin all three.

    Dropping one narrows the scan silently: the suite still resolves and still reports
    findings, just fewer, with nothing indicating queries were excluded.
    """
    template = _template(IMPORTANT_ONLY)
    precisions = set(re.findall(r"^\s+- (high|very-high|medium|low)$", template, re.MULTILINE))
    assert precisions == {"high", "very-high", "medium"}, (
        f"important-only covers {sorted(precisions)}; the documented criteria are "
        f"high, very-high, and medium"
    )


def test_important_only_filters_on_security_tag() -> None:
    template = _template(IMPORTANT_ONLY)
    assert "tags contain" in template and "security" in template, (
        "important-only must restrict to security-tagged queries; without it the mode "
        "is just security-extended under another name"
    )


def test_run_all_imports_both_official_suites() -> None:
    """The two suites are complementary, not hierarchical.

    security-and-quality excludes experimental/ paths; security-experimental re-adds
    them. Importing only the first drops the delta run-all exists to capture.
    """
    template = _template(RUN_ALL)
    assert "security-and-quality" in template, "run-all: missing security-and-quality"
    assert "security-experimental" in template, (
        "run-all: missing security-experimental — experimental/ queries would be dropped "
        "with no signal that the scan narrowed"
    )


def test_run_all_does_not_filter_on_precision() -> None:
    """Filtering by precision here would make run-all a duplicate of important-only."""
    template = _template(RUN_ALL)
    assert not re.search(r"^\s+precision:", template, re.MULTILINE), (
        "run-all applies a precision filter, which is what distinguishes important-only"
    )
