#!/usr/bin/env python3
"""Strip local identity and machine paths from a captured run.

Captures are checked in, so they must not carry a username, a home directory or
a scratch path. Run over both the stream and the journal.

Usage:
    scrub_capture.py FILE [FILE...]
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Order matters, and so does what each rule KEEPS.
#
# The first rule exists because the naive version destroyed evidence: a layer
# agent reported its location as an absolute path, and a greedy
# `/private/tmp/claude-\d+/[^"\\ ]*` -> "/SCRATCH" swallowed the whole thing,
# `search.py:27` included. The regrade then failed and looked like model
# variance. Anything at or below the repo root must survive scrubbing.
SUBSTITUTIONS = (
    # Absolute prefix up to a repo-relative path: keep everything from `plugins/`.
    (re.compile(r"/(?:private/tmp|Users|home)/[^\s\"']*?/(?=plugins/)"), "REPO/"),
    # Encoded project-dir slugs, e.g. -Users-gros-ToB-tools-...
    (re.compile(r"-Users-[A-Za-z0-9]+-[A-Za-z0-9\-]*"), "-PROJECT"),
    # Any remaining scratch path: collapse the directories, keep the basename so
    # a `file.py:LINE` reference is still legible.
    (re.compile(r"/private/tmp/claude-\d+/[^\s\"']*/(?=[^/\s\"']+$)"), "/SCRATCH/"),
    (re.compile(r"/private/tmp/claude-\d+/[^\s\"']*"), "/SCRATCH"),
    (re.compile(r"/(?:User[s]|hom[e])/[A-Za-z0-9._-]+"), "/" + "home" + "/USER"),
)


# Usernames that are also ordinary words, where a blanket substitution would
# destroy the capture instead of anonymising it. `\broot\b` -> "USER" rewrites
# "root cause is a missing check" as "USER cause is a missing check" — the same
# class of bug as the greedy path rule above, applied to identity rather than to
# paths. Length is part of the test because a two- or three-letter login
# (`ci`, `dev`, `abc`) collides with far too much ordinary text.
AMBIGUOUS_USERNAMES = frozenset(
    {"root", "admin", "user", "users", "test", "build", "runner", "ubuntu", "dev", "ci", "node"}
)


def username_patterns(username: str) -> list[re.Pattern[str]]:
    """The patterns that scrub `username`, and the ones the leak check must use.

    Returning them from one place is the point: the substitution used a
    word-bounded regex while the leak check used a plain `in`, so the two
    disagreed. A username that is a substring of an ordinary word ("max" inside
    "maximum") survived the substitution, tripped the check, and aborted the
    scrub *after* the file had been written — under `set -e` in capture-runs.sh
    that killed the whole N-run batch.
    """
    if not username:
        return []
    escaped = re.escape(username)
    if len(username) < 4 or username.lower() in AMBIGUOUS_USERNAMES:
        # Identity-bearing contexts only. The path rules above already handle
        # /Users/<name> and /home/<name>; these cover ~name and name@host.
        return [
            re.compile(rf"(?<=[~@/]){escaped}(?![A-Za-z0-9_-])"),
            re.compile(rf"(?<![A-Za-z0-9_-]){escaped}(?=@)"),
        ]
    return [re.compile(rf"(?<![A-Za-z0-9_-]){escaped}(?![A-Za-z0-9_-])")]


def scrub(text: str, username: str) -> str:
    for pattern, replacement in SUBSTITUTIONS:
        text = pattern.sub(replacement, text)
    for pattern in username_patterns(username):
        text = pattern.sub("USER", text)
    return text


def main() -> int:
    paths = [Path(p) for p in sys.argv[1:]]
    if not paths:
        print("usage: scrub_capture.py FILE [FILE...]", file=sys.stderr)
        return 2

    # An empty username is not "nothing to scrub", it is "the scrubber does not
    # know what to remove". `username_patterns("")` returns [], the leak check
    # then reads `any(... for pat in [])` — vacuously false over an empty list —
    # and the file is written back and reported as scrubbed with the identity
    # still in it. Verified: `HOME=/ scrub_capture.py leak.jsonl` printed
    # "scrubbed 1 file(s)", exit 0, content unchanged. Refuse instead.
    try:
        home = Path.home()
    except RuntimeError as exc:
        print(f"scrub_capture: cannot resolve a home directory: {exc}", file=sys.stderr)
        return 1
    username = home.name
    if not username:
        print(
            f"scrub_capture: HOME is {str(home)!r}, which yields no username. With none, "
            f"there is nothing to match on and every file would be reported clean without "
            f"being checked. Set HOME to the real home directory and re-run.",
            file=sys.stderr,
        )
        return 1

    for path in paths:
        if not path.is_file():
            print(f"scrub_capture: {path} is not a file", file=sys.stderr)
            return 1
        cleaned = scrub(path.read_text(), username)
        # Must remain valid JSONL, or the regrade cannot read it.
        for lineno, line in enumerate(cleaned.splitlines(), 1):
            if line.strip():
                try:
                    json.loads(line)
                except json.JSONDecodeError as exc:
                    print(f"scrub_capture: {path}:{lineno} broke: {exc}", file=sys.stderr)
                    return 1
        path.write_text(cleaned)

    # Re-run the WHOLE rule set over what was written. Two reasons for this
    # shape rather than an independent test:
    #
    #   - it cannot disagree with the substitution, because it *is* the
    #     substitution. A plain `username in text` disagreed with the
    #     word-bounded regex and failed on ordinary words that merely contain
    #     the login, aborting the batch after the file had been written.
    #   - it covers all three categories the module docstring promises. The
    #     previous check ran `username_patterns` only, so the five path
    #     SUBSTITUTIONS were never verified at all.
    #
    # What it can catch is a write that does not reflect the substitution — the
    # cleaned text not reaching disk, the wrong variable written, a partial
    # write. It cannot catch a rule that fails to match, because the rules are
    # idempotent (test_scrubbing_is_idempotent) and a second pass over
    # already-scrubbed text is a no-op by construction. That is what the
    # per-rule tests in test_scrub.py are for.
    leaked = [p for p in paths if (written := p.read_text()) != scrub(written, username)]
    if leaked:
        print(
            f"scrub_capture: identity or machine path still present in {leaked}",
            file=sys.stderr,
        )
        return 1
    print(f"scrubbed {len(paths)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
