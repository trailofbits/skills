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
cat >app/auth.py <<'CONCEPT_PROVER_FIXTURE_EOF'
"""Session decoding and role checks for the maintenance API."""

import json

DEFAULTS = {"user": "anonymous", "role": "viewer"}


def load_session(cookie: str) -> dict[str, str]:
    """Decode the session cookie the sign-in service issues.

    The cookie is JSON. Fields the caller omits fall back to DEFAULTS.
    """
    data = json.loads(cookie) if cookie else {}
    return {key: data.get(key, default) for key, default in DEFAULTS.items()}


def require_role(session: dict[str, str], role: str) -> None:
    """Raise unless `session` carries `role`."""
    if session.get("role") != role:
        raise PermissionError(f"{role} role required")
CONCEPT_PROVER_FIXTURE_EOF
cat >app/admin.py <<'CONCEPT_PROVER_FIXTURE_EOF'
"""Maintenance endpoints for the operations team."""

import subprocess


def service_status(request_args: dict[str, str]) -> dict[str, str]:
    """Handle GET /admin/status. Reports whether the log writer is running."""
    del request_args
    return {"log_writer": "running"}


def rotate_logs(request_args: dict[str, str]) -> dict[str, str]:
    """Handle POST /admin/rotate. `target` names the logrotate config to force."""
    target = request_args.get("target", "")
    subprocess.run(f"logrotate -f /etc/logrotate.d/{target}", shell=True, check=True)
    return {"rotated": target}
CONCEPT_PROVER_FIXTURE_EOF
cat >app/router.py <<'CONCEPT_PROVER_FIXTURE_EOF'
"""Path routing for the maintenance API.

Every route carries the role it requires. Paths are matched exactly, and an
unknown path raises before any handler runs.
"""

from app import admin, auth

ROUTES = {
    "/admin/status": (admin.service_status, "viewer"),
    "/admin/rotate": (admin.rotate_logs, "admin"),
}


def dispatch(path: str, cookie: str, request_args: dict[str, str]):
    """Route `path` to its handler, enforcing the role its ROUTES entry names."""
    entry = ROUTES.get(path)
    if entry is None:
        raise KeyError(f"no handler for {path}")
    handler, role = entry
    auth.require_role(auth.load_session(cookie), role)
    return handler(request_args)
CONCEPT_PROVER_FIXTURE_EOF
