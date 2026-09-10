"""Make `stream.py` importable, and let the regrade point at any run directory."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def pytest_addoption(parser):
    parser.addoption(
        "--fixtures-dir",
        action="store",
        default=None,
        help=(
            "Directory holding run.stream.jsonl / run.journal.jsonl / run.meta.json. "
            "Defaults to tests/fixtures. Used by capture-runs.sh to regrade each run "
            "of a batch independently."
        ),
    )
