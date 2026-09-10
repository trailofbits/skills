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
