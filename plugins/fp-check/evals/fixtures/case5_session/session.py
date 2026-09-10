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
