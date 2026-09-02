#!/usr/bin/env bash
# Writes the case's targets into the eval's empty working directory, then puts
# them under git with the history the case is about: 1.4.0 as the researcher
# saw it, and the 1.4.1 fix on top.
#
# The 1.4.1 tree is kept byte-identical to fixtures/case5_session/ by
# tests/test_eval_suite.py::test_scaffold_fixture_matches_the_checked_in_copy.
# Only the 1.4.0 copies of auth.py and CHANGELOG.md live here, because only
# HEAD is what the case is analysed against.
#
# The history is not decoration. It is the evidence: the reported line is
# unchanged at HEAD, and what closed the report is one layer up in the caller.
# The tree is committed for a second reason too — build-poc builds with
# isolation: 'worktree', and a worktree is cut from HEAD.
set -euo pipefail

cat >session.py <<'CONCEPT_PROVER_FIXTURE_EOF'
"""Server-side session store.

Sessions live in the worker process for their whole lifetime; nothing here is
persisted, so a restart logs everybody out. Each record holds the value a
client has to present, when it was issued and when it stops being accepted.

The store deals in opaque strings. Callers decide what a session value is and
are responsible for producing the same string on every request that carries it.
"""

import time
from dataclasses import dataclass, field

DEFAULT_TTL_SECONDS = 3600
MAX_SESSIONS = 10_000


@dataclass
class SessionRecord:
    """One live session."""

    token: str
    user: str
    issued_at: float
    expires_at: float
    last_seen: float = field(default=0.0)


class SessionStore:
    """In-memory session table keyed by session id."""

    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._sessions: dict[str, SessionRecord] = {}

    def create(self, session_id: str, token: str, user: str) -> SessionRecord:
        """Record `token` as the value that authenticates `session_id`."""
        now = time.time()
        if len(self._sessions) >= MAX_SESSIONS:
            self._evict_expired(now)
        record = SessionRecord(
            token=token,
            user=user,
            issued_at=now,
            expires_at=now + self._ttl,
        )
        self._sessions[session_id] = record
        return record

    def get(self, session_id: str) -> SessionRecord | None:
        """Return the record for `session_id`, or None when there is none."""
        return self._sessions.get(session_id)

    def revoke(self, session_id: str) -> None:
        """Drop the session, if it is still there."""
        self._sessions.pop(session_id, None)

    def touch(self, session_id: str) -> None:
        """Extend a live session by a further TTL."""
        record = self._sessions.get(session_id)
        if record is None:
            return
        record.expires_at = time.time() + self._ttl

    def _evict_expired(self, now: float) -> None:
        """Drop every record whose expiry has already passed."""
        expired = [sid for sid, rec in self._sessions.items() if rec.expires_at <= now]
        for sid in expired:
            del self._sessions[sid]

    def validate(self, session_id: str, token: str) -> bool:
        """Return True when `token` is the value recorded for `session_id`.

        An unknown session id and an expired one are both reported the same way,
        so a caller cannot use the answer to enumerate live sessions.

        A session that validates has its last-seen time refreshed, which is the
        field the idle-timeout job reads.
        """
        record = self._sessions.get(session_id)
        if record is None:
            return False
        now = time.time()
        if record.expires_at <= now:
            del self._sessions[session_id]
            return False
        expected = record.token
        if token == expected:
            record.last_seen = now
            return True
        return False
CONCEPT_PROVER_FIXTURE_EOF

cat >auth.py <<'CONCEPT_PROVER_FIXTURE_EOF'
"""Request authentication for the session-backed API.

`issue_session` is called by the login handler; `authenticate` runs on every
subsequent request, before routing.
"""

import secrets

from session import SessionStore

STORE = SessionStore()


def issue_session(user: str) -> tuple[str, str]:
    """Start a session for `user`, returning the id and token to set as cookies."""
    session_id = secrets.token_urlsafe(18)
    token = secrets.token_urlsafe(32)
    STORE.create(session_id, token, user)
    return session_id, token


def authenticate(cookies: dict[str, str]) -> bool:
    """Return True when the request's cookies name a live session."""
    session_id = cookies.get("sid", "")
    token = cookies.get("stok", "")
    if not session_id or not token:
        return False
    return STORE.validate(session_id, token)


def sign_out(cookies: dict[str, str]) -> None:
    """End the session the request carries, if it has one."""
    STORE.revoke(cookies.get("sid", ""))
CONCEPT_PROVER_FIXTURE_EOF

cat >CHANGELOG.md <<'CONCEPT_PROVER_FIXTURE_EOF'
# Changelog

Notable changes to the session service. Dates are release dates.

## [1.4.0] - 2026-04-11

### Added

- In-memory session store with per-record expiry and idle timeout (#397).
- `sign_out` clears the session server-side rather than only expiring the
  cookie (#401).
CONCEPT_PROVER_FIXTURE_EOF

git -c init.defaultBranch=main init -q
git add -A
GIT_AUTHOR_DATE='2026-04-11T14:02:00+00:00' \
  GIT_COMMITTER_DATE='2026-04-11T14:02:00+00:00' \
  git -c user.name='Platform Team' -c user.email='platform@example.invalid' \
  -c commit.gpgsign=false \
  commit -q -m 'feat(auth): in-memory session store with expiry (#397)'
git tag v1.4.0

cat >auth.py <<'CONCEPT_PROVER_FIXTURE_EOF'
"""Request authentication for the session-backed API.

`issue_session` is called by the login handler; `authenticate` runs on every
subsequent request, before routing.
"""

import hashlib
import hmac
import os
import secrets

from session import SessionStore

PEPPER = os.environ.get("SESSION_PEPPER", "").encode()
STORE = SessionStore()


def _digest(value: str) -> str:
    """Reduce a client-supplied value to a fixed-length keyed digest."""
    return hmac.new(PEPPER, value.encode(), hashlib.sha256).hexdigest()


def issue_session(user: str) -> tuple[str, str]:
    """Start a session for `user`, returning the id and token to set as cookies."""
    session_id = secrets.token_urlsafe(18)
    token = secrets.token_urlsafe(32)
    STORE.create(session_id, _digest(token), user)
    return session_id, token


def authenticate(cookies: dict[str, str]) -> bool:
    """Return True when the request's cookies name a live session."""
    session_id = cookies.get("sid", "")
    token = cookies.get("stok", "")
    if not session_id or not token:
        return False
    return STORE.validate(session_id, _digest(token))


def sign_out(cookies: dict[str, str]) -> None:
    """End the session the request carries, if it has one."""
    STORE.revoke(cookies.get("sid", ""))
CONCEPT_PROVER_FIXTURE_EOF

cat >CHANGELOG.md <<'CONCEPT_PROVER_FIXTURE_EOF'
# Changelog

Notable changes to the session service. Dates are release dates.

## [1.4.1] - 2026-05-02

### Fixed

- Session tokens are reduced to a keyed digest before the store compares them,
  so the comparison no longer runs over the stored value itself (#412).

## [1.4.0] - 2026-04-11

### Added

- In-memory session store with per-record expiry and idle timeout (#397).
- `sign_out` clears the session server-side rather than only expiring the
  cookie (#401).
CONCEPT_PROVER_FIXTURE_EOF

git add -A
GIT_AUTHOR_DATE='2026-05-02T11:20:00+00:00' \
  GIT_COMMITTER_DATE='2026-05-02T11:20:00+00:00' \
  git -c user.name='Platform Team' -c user.email='platform@example.invalid' \
  -c commit.gpgsign=false \
  commit -q -m 'fix(auth): constant-time token comparison (#412)' \
  -m 'Hash the presented token and the stored token with the session pepper before the store compares them, so the comparison runs over two fixed-length digests and its running time no longer depends on the stored value.'
git tag v1.4.1
