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
