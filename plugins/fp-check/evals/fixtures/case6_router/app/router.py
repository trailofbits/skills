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
