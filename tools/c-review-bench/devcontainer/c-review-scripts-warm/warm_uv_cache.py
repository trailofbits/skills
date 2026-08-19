#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["tree-sitter>=0.23", "tree-sitter-c>=0.23", "tree-sitter-cpp>=0.23"]
# ///
"""Populate uv's package cache at image build time, while the network still exists.

Why this file exists. A cell runs `uv run enumerate_units.py`, and on a cold cache uv
resolves and downloads from pypi.org through **its own HTTP client** — not a curl or wget
subprocess. The bench's network guard is a PreToolUse hook that matches Bash command
patterns, so it cannot see that traffic at all: with `--network none` the run simply dies
with a DNS error, and with the network up it would reach out unobserved. Neither is
acceptable in a hermetic cell.

Running this at build time caches the wheels by content hash under the image's
`~/.cache/uv`, so the real script later resolves offline in about 0.1s even though it is
bind-mounted from the host and may be newer than anything baked into the image.

**The dependency list above is the only thing that matters here, and it must stay equal to
the one in `plugins/c-review/scripts/enumerate_units.py`.** This deliberately imports the
packages rather than copying that script: an earlier version of this directory held a
43 KB verbatim duplicate of `enumerate_units.py`, which is a second copy of real logic that
nothing keeps in step, and which the repo's own linter then flagged for a style issue in
code no one would ever run.
"""

import tree_sitter
import tree_sitter_c
import tree_sitter_cpp

# Touch each one so the import is not optimised away by a reader's assumption that it was
# unused, and so a broken wheel fails the build rather than the first real cell.
print(
    "uv cache warm:",
    tree_sitter.__name__,
    tree_sitter_c.__name__,
    tree_sitter_cpp.__name__,
)
