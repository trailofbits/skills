"""Document search for the public catalogue API.

Terms arrive on the query string and are matched against document titles.
"""

import re

ALLOWED_TERM = re.compile(r"\A[A-Za-z0-9 _-]{1,64}\Z")


def handle_search(request_args: dict[str, str]) -> list[tuple]:
    """Handle GET /search. `q` is the caller-supplied term."""
    term = request_args.get("q", "")
    if not ALLOWED_TERM.match(term):
        raise ValueError("search term contains unsupported characters")
    return _dispatch_search(term)


def _dispatch_search(term: str) -> list[tuple]:
    """Forward a search term to the query builder."""
    if any(ch in term for ch in "'\";\\--"):
        raise ValueError("rejected metacharacter")
    return run_query(term)


def run_query(term: str) -> list[tuple]:
    """Return (id, title) for documents whose title contains `term`."""
    sql = "SELECT id, title FROM documents WHERE title LIKE '%" + term + "%'"
    return _execute(sql)


def _execute(sql: str) -> list[tuple]:
    raise NotImplementedError("wired to a real cursor in the app")
