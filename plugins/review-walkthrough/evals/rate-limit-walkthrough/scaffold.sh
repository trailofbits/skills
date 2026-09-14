#!/usr/bin/env bash
# Builds the fixture repository the rate-limit-walkthrough case reviews.
#
# Runs as `bash scaffold.sh` with cwd set to the eval sandbox cwd, so the
# repository is created in place: the agent's cwd *is* the repo, matching how a
# user actually invokes the skill.
#
# Two details keep the fixture deterministic:
#   - refs/remotes/origin/main and origin/HEAD are written by hand, so the skill
#     can discover the default branch without a remote or network access.
#   - The seeded bug sits at a fixed line of ratelimit/bucket.py. Editing that
#     file shifts the line documented in case.yaml.
set -euo pipefail

git init -q -b main .
git config user.name "Eval Fixture"
git config user.email "eval@example.invalid"
git config commit.gpgsign false

# ---------------------------------------------------------------- baseline ---
mkdir -p app

cat >README.md <<'EOF'
# demo-service

A deliberately tiny request dispatcher used as a rate-limiting fixture.
EOF

touch app/__init__.py

cat >app/server.py <<'EOF'
"""Minimal request dispatcher."""

ROUTES = {}


def route(path):
    """Register a handler for an exact path match."""

    def register(fn):
        ROUTES[path] = fn
        return fn

    return register


@route("/health")
def health(request):
    return {"status": 200, "body": "ok"}


def dispatch(request):
    handler = ROUTES.get(request.get("path"))
    if handler is None:
        return {"status": 404, "body": "not found"}
    return handler(request)


application = dispatch
EOF

git add -A
git commit -qm "Add minimal request dispatcher"
git update-ref refs/remotes/origin/main HEAD
git symbolic-ref refs/remotes/origin/HEAD refs/remotes/origin/main

# ------------------------------------------------------- feature under review ---
git checkout -q -b feature/rate-limit

mkdir -p ratelimit tests
touch ratelimit/__init__.py tests/__init__.py

cat >ratelimit/config.py <<'EOF'
"""Configuration for the token-bucket rate limiter."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitConfig:
    """Per-client rate limit settings.

    ``capacity`` is the maximum burst size a client may spend at once;
    ``refill_per_second`` is the sustained rate once that burst is exhausted.
    """

    capacity: int
    refill_per_second: float

    def __post_init__(self) -> None:
        if self.capacity <= 0:
            raise ValueError("capacity must be positive")
        if self.refill_per_second <= 0:
            raise ValueError("refill_per_second must be positive")
EOF

# The bug is on the `self._tokens +=` line: refill is never clamped to
# config.capacity, so an idle client accrues unbounded tokens and can later
# burst straight through the limit. Keep it where it is; graders anchor to it.
cat >ratelimit/bucket.py <<'EOF'
"""Token-bucket rate limiting, one bucket per client key."""

import time
from threading import Lock

from ratelimit.config import RateLimitConfig


class TokenBucket:
    """A refill-on-read token bucket.

    Tokens accrue at ``config.refill_per_second`` and each request spends one.
    ``consume`` is the only public entry point.
    """

    def __init__(self, config: RateLimitConfig) -> None:
        self._config = config
        self._tokens = float(config.capacity)
        self._updated_at = time.monotonic()
        self._lock = Lock()

    def _refill(self, now: float) -> None:
        elapsed = now - self._updated_at
        if elapsed <= 0:
            return
        self._tokens += elapsed * self._config.refill_per_second
        self._updated_at = now

    def consume(self, cost: int = 1) -> bool:
        """Spend ``cost`` tokens, returning False when the client is limited."""
        with self._lock:
            now = time.monotonic()
            self._refill(now)
            if self._tokens < cost:
                return False
            self._tokens -= cost
            return True
EOF

cat >app/middleware.py <<'EOF'
"""Per-client rate limiting applied in front of the dispatcher."""

from ratelimit.bucket import TokenBucket
from ratelimit.config import RateLimitConfig

DEFAULT_CONFIG = RateLimitConfig(capacity=20, refill_per_second=5.0)


class RateLimitMiddleware:
    """Wraps a handler and rejects clients that exceed their bucket."""

    def __init__(self, app, config=DEFAULT_CONFIG):
        self._app = app
        self._config = config
        self._buckets = {}

    def _bucket_for(self, key):
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = TokenBucket(self._config)
            self._buckets[key] = bucket
        return bucket

    def __call__(self, request):
        key = request.get("client_ip", "unknown")
        if not self._bucket_for(key).consume():
            return {"status": 429, "body": "rate limited"}
        return self._app(request)
EOF

cat >tests/test_bucket.py <<'EOF'
from ratelimit.bucket import TokenBucket
from ratelimit.config import RateLimitConfig


def test_allows_burst_up_to_capacity():
    bucket = TokenBucket(RateLimitConfig(capacity=3, refill_per_second=1.0))
    assert bucket.consume()
    assert bucket.consume()
    assert bucket.consume()
    assert not bucket.consume()


def test_rejects_invalid_config():
    try:
        RateLimitConfig(capacity=0, refill_per_second=1.0)
    except ValueError:
        return
    raise AssertionError("expected ValueError")
EOF

python3 - <<'EOF'
from pathlib import Path

path = Path("app/server.py")
text = path.read_text()
text = text.replace(
    '"""Minimal request dispatcher."""\n',
    '"""Minimal request dispatcher."""\n\nfrom app.middleware import RateLimitMiddleware\n',
)
text = text.replace(
    "application = dispatch\n",
    "application = RateLimitMiddleware(dispatch)\n",
)
path.write_text(text)
EOF

git add -A
git commit -qm "Add per-client token-bucket rate limiting"
