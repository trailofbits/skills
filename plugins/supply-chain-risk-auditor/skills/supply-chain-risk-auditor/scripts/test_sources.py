"""Source-adapter tests: identifier parsing, the caching client, and OSV batching.

The redirect test is load-bearing per the collector's history: `jrburke/r.js` 301s to
`requirejs/r.js`, and an HTTP client that stopped at the 301 reported the repository
missing. Any replacement client must keep following redirects, so a local server proves
this one does.
"""

from __future__ import annotations

import json
import os
import threading
import time
from email.message import Message
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import sources
from sources import (
    Http,
    NotFound,
    RepoIdentifierError,
    Unavailable,
    _Response,
    _security_policy,
    github_repo,
    looks_automated,
    normalize_repo,
    osv_advisories,
)

# --------------------------------------------------------------- repo identifiers


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("git+https://github.com/a/b.git", "github.com/a/b"),
        ("git@github.com:a/b.git", "github.com/a/b"),
        ("ssh://git@github.com/a/b", "github.com/a/b"),
        ("a/b", "github.com/a/b"),
        ("github:a/b", "github.com/a/b"),
        ("gitlab:a/b", "gitlab.com/a/b"),
        ("https://github.com/psf/requests/blob/main/README.md", "github.com/psf/requests"),
        ("https://www.GitHub.com/a/b/", "github.com/a/b"),
        ("https://example.com/foo", "example.com/foo"),
    ],
)
def test_normalize_repo(raw: str, expected: str):
    assert normalize_repo(raw) == expected


def test_non_github_repo_is_an_identifier_error_not_an_api_failure(tmp_path: Path):
    http = Http(tmp_path, offline=True)
    with pytest.raises(RepoIdentifierError):
        github_repo(http, "https://sr.ht/~someone/project", None)


def test_bot_heuristic_is_conservative():
    for account in ("dependabot", "renovate", "github-actions", "release-bot", "ci"):
        assert looks_automated(account), account
    for account in ("alice", "robotics-lab", "botanist"):
        assert not looks_automated(account), account


# ------------------------------------------------------------------- OSV batching


class RecordingHttp:
    def __init__(self, responses: list[dict]):
        self.responses = list(responses)
        self.payloads: list[dict] = []

    def post_json(self, url: str, payload: dict) -> dict:
        self.payloads.append(payload)
        return self.responses.pop(0)


def test_osv_results_are_positional_so_same_name_twice_works():
    http = RecordingHttp([{"results": [{"vulns": [{"id": "GHSA-1"}]}, {}]}])
    ids = osv_advisories(http, [("npm", "inner", "3.0.0"), ("npm", "inner", "3.1.0")])
    assert ids == [["GHSA-1"], []]


def test_osv_result_count_mismatch_is_refused():
    http = RecordingHttp([{"results": [{}]}])
    with pytest.raises(Unavailable, match="positional"):
        osv_advisories(http, [("npm", "a", "1"), ("npm", "b", "2")])


def test_osv_batches_chunk_at_500():
    http = RecordingHttp([{"results": [{}] * 500}, {"results": [{}]}])
    queries = [("npm", f"pkg-{i}", "1.0.0") for i in range(501)]
    assert len(osv_advisories(http, queries)) == 501
    assert [len(p["queries"]) for p in http.payloads] == [500, 1]


# ----------------------------------------------------------------- caching client


def seed(http: Http, method: str, url: str, payload: object, body: str = "") -> Path:
    path = http._path(method, url, body)
    if payload is None:
        http._write_cache(path, {}, 404)
    else:
        http._write_cache(path, payload, 200)
    return path


def test_offline_serves_seeded_entries(tmp_path: Path):
    http = Http(tmp_path, offline=True)
    seed(http, "GET", "https://example.com/x", {"ok": 1})
    assert http.get_json("https://example.com/x") == {"ok": 1}
    assert http.stats["hits"] == 1


def test_cached_404_stays_not_found(tmp_path: Path):
    http = Http(tmp_path, offline=True)
    seed(http, "GET", "https://example.com/gone", None)
    with pytest.raises(NotFound):
        http.get_json("https://example.com/gone")


def test_offline_miss_is_unavailable_not_a_verdict(tmp_path: Path):
    http = Http(tmp_path, offline=True)
    with pytest.raises(Unavailable, match="offline"):
        http.get_json("https://example.com/never-fetched")


def test_truncated_cache_entry_is_dropped(tmp_path: Path):
    http = Http(tmp_path, offline=True)
    path = seed(http, "GET", "https://example.com/x", {"ok": 1})
    path.write_text('{"__meta": {"fetched_at"')
    with pytest.raises(Unavailable):
        http.get_json("https://example.com/x")
    assert not path.exists()


def test_cache_owner_is_verified_on_posix(tmp_path: Path):
    """The usual case: ownership checks out, so there is no caveat to report."""
    http = Http(tmp_path, offline=True)
    assert http.cache_owner_caveat is None


def test_foreign_cache_owner_still_aborts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The control this caveat exists to protect must keep biting on POSIX.

    A cache another user can write turns a compromised package into a clean
    "no advisories" verdict, so a foreign owner has to stop the run outright.
    """
    monkeypatch.setattr(sources.os, "getuid", lambda: os.stat(tmp_path).st_uid + 1)
    with pytest.raises(SystemExit, match="owned by another user"):
        Http(tmp_path, offline=True)


def test_missing_getuid_reports_a_caveat_instead_of_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Windows has no os.getuid, and st_uid is always 0 there (issue #273).

    The client must construct rather than raise AttributeError, and must hand back a
    caveat naming what went unchecked — dropping the control silently would let the
    report claim a verified cache it never verified.
    """
    monkeypatch.delattr(sources.os, "getuid", raising=True)

    http = Http(tmp_path, offline=True)

    assert http.cache_owner_caveat is not None
    assert "not verified" in http.cache_owner_caveat
    assert str(tmp_path) in http.cache_owner_caveat
    # Still usable: the caveat is a report line, not a degraded client.
    seed(http, "GET", "https://example.com/x", {"ok": 1})
    assert http.get_json("https://example.com/x") == {"ok": 1}


def test_auth_marker_partitions_the_cache(tmp_path: Path):
    anon = Http(tmp_path, offline=True, auth_marker="anon")
    seed(anon, "GET", "https://api.github.com/repos/a/b", None)
    authed = Http(tmp_path, offline=True, auth_marker="gh")
    # The anonymous 404 must not be served to the authenticated run.
    with pytest.raises(Unavailable) as excinfo:
        authed.get_json("https://api.github.com/repos/a/b")
    assert not isinstance(excinfo.value, NotFound)


def test_stale_entries_refetch_when_online(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    http = Http(tmp_path, offline=False)
    path = seed(http, "GET", "https://example.com/x", {"old": True})
    stored = json.loads(path.read_text())
    stored["__meta"]["fetched_at"] = time.time() - sources.CACHE_MAX_AGE_SECONDS - 60
    path.write_text(json.dumps(stored))
    monkeypatch.setattr(http, "_send", lambda *a: {"fresh": True})
    assert http.get_json("https://example.com/x") == {"fresh": True}
    assert http.stats["stale"] == 1


def test_rate_limit_retries_once_then_gives_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    limited = Message()
    limited["x-ratelimit-remaining"] = "0"
    responses = [
        _Response(403, "", limited),
        _Response(200, '{"ok": 1}'),
    ]
    http = Http(tmp_path, offline=False)
    monkeypatch.setattr(http, "_open", lambda *a: responses.pop(0))
    monkeypatch.setattr(sources.time, "sleep", lambda s: None)
    assert http.get_json("https://api.github.com/repos/a/b") == {"ok": 1}

    responses.extend([_Response(429, ""), _Response(429, "")])
    with pytest.raises(Unavailable, match="rate limited"):
        http.get_json("https://api.github.com/repos/a/b2")


# ------------------------------------------------------- redirects (load-bearing)


class _RedirectingHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's required casing
        if self.path == "/old":
            self.send_response(301)
            self.send_header("Location", "/new")
            self.end_headers()
        else:
            body = json.dumps({"moved": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args):  # silence per-request stderr noise
        pass


def test_client_follows_redirects(tmp_path: Path):
    server = HTTPServer(("127.0.0.1", 0), _RedirectingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        http = Http(tmp_path, offline=False)
        url = f"http://127.0.0.1:{server.server_port}/old"
        assert http.get_json(url) == {"moved": True}
    finally:
        server.shutdown()
        thread.join(timeout=5)


# ----------------------------------------------------------------- security policy


class PolicyHttp:
    """Duck-typed client that answers SECURITY.md probes from a script."""

    def __init__(self, outcomes: list[object]):
        self.outcomes = list(outcomes)

    def get_json(self, url: str, headers: dict | None = None) -> dict:
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_policy_found_at_the_first_candidate():
    assert _security_policy(PolicyHttp([{}]), "acme/repo", {}) is True


def test_policy_absent_only_when_every_probe_is_a_404():
    http = PolicyHttp([NotFound("404")] * 5)
    assert _security_policy(http, "acme/repo", {}) is False


def test_policy_unknown_when_any_probe_fails_for_other_reasons():
    http = PolicyHttp([NotFound("404"), Unavailable("rate limited")] + [NotFound("404")] * 3)
    assert _security_policy(http, "acme/repo", {}) is None
