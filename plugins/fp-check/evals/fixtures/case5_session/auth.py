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
