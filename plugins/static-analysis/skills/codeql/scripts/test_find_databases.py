"""Run find_databases.sh, which exists because bash arrays cannot cross Bash calls.

Discovery used to be a loop in SKILL.md whose `FOUND_DBS` array a *different* markdown
block then read. Each block runs in a fresh shell, so the consumer saw an empty array and
reported "No CodeQL database found" for a project that had one. Both callers now run this
and build their own array in their own block.

`codeql resolve database` is stubbed, so no CodeQL install is needed. The stub is what
separates a real database from the marker file a failed build leaves behind, which is the
whole point of the script.
"""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "find_databases.sh"


def _marker(directory: Path) -> Path:
    """A codeql-database.yml, as `codeql database create` writes it before the build."""
    directory.mkdir(parents=True, exist_ok=True)
    marker = directory / "codeql-database.yml"
    marker.write_text("primaryLanguage: cpp\n")
    return marker


def _fake_codeql(bin_dir: Path, *, valid: list[str]) -> None:
    """`codeql resolve database -- DIR` succeeds only for the named directories."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    script = bin_dir / "codeql"
    checks = "\n".join(f"  {name!r}) exit 0 ;;".replace("'", '"') for name in valid)
    script.write_text(
        "#!/bin/sh\n"
        'for arg in "$@"; do db="$arg"; done\n'
        'case "$(basename "$db")" in\n'
        f"{checks}\n"
        "  *) exit 1 ;;\n"
        "esac\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _invoke(tmp_path: Path, *roots: str) -> subprocess.CompletedProcess[str]:
    env = {"PATH": f"{tmp_path / 'bin'}:/usr/bin:/bin", "HOME": str(tmp_path)}
    return subprocess.run(
        [str(SCRIPT), *roots], capture_output=True, text=True, cwd=tmp_path, env=env
    )


def _run(tmp_path: Path, *roots: str) -> list[str]:
    result = _invoke(tmp_path, *roots)
    assert result.returncode == 0, result.stderr
    return result.stdout.split()


def test_a_failed_builds_marker_is_not_reported_as_a_database(tmp_path: Path) -> None:
    """`codeql database create` writes the marker before the build finishes.

    A bare `find` therefore reports a database that does not exist, and the run analyses
    it and finds nothing. Paths come back absolute, so a caller in a different working
    directory can still use them.
    """
    _marker(tmp_path / "good.db")
    _marker(tmp_path / "half-built.db")
    _fake_codeql(tmp_path / "bin", valid=["good.db"])

    assert _run(tmp_path, ".") == [str(tmp_path / "good.db")]


def test_every_database_is_reported_not_just_the_first(tmp_path: Path) -> None:
    """SKILL.md offers the user a choice, so discovery must not stop at one."""
    for name in ("first.db", "second.db", "third.db"):
        _marker(tmp_path / name)
    _fake_codeql(tmp_path / "bin", valid=["first.db", "second.db", "third.db"])

    assert len(_run(tmp_path, ".")) == 3


def test_overlapping_roots_do_not_produce_duplicates(tmp_path: Path) -> None:
    """Callers pass "$OUTPUT_DIR" and "." — the first is usually inside the second.

    Searched as written, the same database appears once as an absolute path and once as
    ./out/codeql.db, which a string dedup cannot collapse; the user is then offered the
    same database twice. Roots are resolved with `pwd -P` before the search.
    """
    _marker(tmp_path / "out" / "codeql.db")
    _fake_codeql(tmp_path / "bin", valid=["codeql.db"])

    assert _run(tmp_path, str(tmp_path / "out"), ".") == [str(tmp_path / "out" / "codeql.db")]


def test_a_database_under_a_dotted_ancestor_is_still_found(tmp_path: Path) -> None:
    """Roots are absolutised, so the old `-not -path '*/.*'` matched dotted *ancestors* too.

    `find` tests -path against the whole path. Once the root became absolute, a checkout
    under ~/.cache, ~/.local, or any dotted parent had every database filtered out: the
    script printed nothing and exited 0, and SKILL.md's auto-detection reads that as "no
    databases found" and rebuilds from scratch.
    """
    root = tmp_path / ".cache" / "builds" / "proj"
    database = root / "static_analysis_codeql_1" / "codeql.db"
    _marker(database)
    _fake_codeql(tmp_path / "bin", valid=["codeql.db"])

    assert _run(tmp_path, str(root)) == [str(database)]


def test_a_dot_directory_below_the_root_is_still_skipped(tmp_path: Path) -> None:
    """The fix must not widen into "search dot-directories".

    A database inside .git or .venv is a stray copy, not the project's own. Offering it in
    the selection prompt spends one of AskUserQuestion's four options on a database nobody
    asked to build.
    """
    _marker(tmp_path / ".git" / "stray.db")
    _marker(tmp_path / "real.db")
    _fake_codeql(tmp_path / "bin", valid=["stray.db", "real.db"])

    assert _run(tmp_path, ".") == [str(tmp_path / "real.db")]


def test_no_databases_prints_nothing_and_succeeds(tmp_path: Path) -> None:
    """The caller decides what an empty list means; this is not an error here."""
    _fake_codeql(tmp_path / "bin", valid=[])
    assert _run(tmp_path, ".") == []


def test_a_missing_codeql_is_an_error_not_an_empty_list(tmp_path: Path) -> None:
    """Otherwise "codeql is not installed" and "this project has no databases" look alike.

    The filter is `codeql resolve database`, so without the binary every candidate is
    rejected and the script prints nothing. SKILL.md's auto-detection table sends an empty
    result to "run the full pipeline", so the user gets a rebuild attempt rather than the
    one line that would have told them what to fix.
    """
    _marker(tmp_path / "good.db")
    (tmp_path / "bin").mkdir(parents=True, exist_ok=True)  # on PATH, but holding no codeql

    result = _invoke(tmp_path, ".")
    assert result.returncode != 0, "a missing codeql must not report success"
    assert "codeql not found" in result.stderr
    assert result.stdout == "", "no database may be reported when none could be validated"
