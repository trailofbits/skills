#!/usr/bin/env bash
# Writes the case's target tree into the eval's empty working directory.
# The eval runs each case in a fresh scaffold dir, so a repo-relative path in
# the prompt resolves to nothing; the fixtures have to be materialised here.
#
# Generated from the checked-in fixtures and held byte-identical to them by
# tests/test_eval_suite.py::test_scaffold_fixture_matches_the_checked_in_copy.
# If ruff reformats a fixture, regenerate rather than hand-editing this file.
set -euo pipefail
mkdir -p app
cat >app/router.py <<'CONCEPT_PROVER_FIXTURE_EOF'
"""URL routing for the reporting service.

Paths are matched exactly. An unknown path raises before any handler runs, so
every request that reaches a handler came through the table below.
"""

from app import reports

ROUTES = {
    "/reports": reports.list_reports,
    "/reports/detail": reports.get_report,
}


def dispatch(path: str, request_args: dict[str, str]):
    """Route `path` to its handler and call it with the query string args."""
    handler = ROUTES.get(path)
    if handler is None:
        raise KeyError(f"no handler for {path}")
    return handler(request_args)
CONCEPT_PROVER_FIXTURE_EOF
cat >app/reports.py <<'CONCEPT_PROVER_FIXTURE_EOF'
"""Report listing, retrieval and PDF rendering for the reporting service."""

import subprocess

STORE = "/var/lib/reports"


def list_reports(request_args: dict[str, str]) -> list[str]:
    """Handle GET /reports. Returns the names of the stored reports."""
    del request_args
    return ["q1-summary", "q2-summary"]


def get_report(request_args: dict[str, str]) -> str:
    """Handle GET /reports/detail. `name` selects one of the stored reports."""
    name = request_args.get("name", "")
    if name not in list_reports({}):
        raise ValueError("unknown report")
    return f"{STORE}/{name}.json"


def render_pdf(request_args: dict[str, str]) -> bytes:
    """Render a stored report to PDF with the wkhtmltopdf binary.

    `source` is the report filename relative to STORE.
    """
    source = request_args.get("source", "")
    subprocess.run(f"wkhtmltopdf {STORE}/{source} /tmp/out.pdf", shell=True, check=True)
    with open("/tmp/out.pdf", "rb") as handle:
        return handle.read()
CONCEPT_PROVER_FIXTURE_EOF
