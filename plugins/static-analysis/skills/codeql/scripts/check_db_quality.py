# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Fail unless a CodeQL database extracted enough source to be worth analysing.

An empty database analyses without error and reports "0 findings", the same output a
clean codebase produces. These thresholds are enforced rather than printed.

Two kinds of failure, two exit codes, because they do not deserve the same response:

    1  Nothing to analyse. No baseline lines of code, no project files in the source
       archive, or the database is unreadable. Not a judgement call and not overridable —
       analysing would report zero findings for source nobody read.
    3  Extractor error ratio above the threshold. A heuristic. Partial C/C++ extraction
       over vendored dependencies or generated code exceeds it legitimately, so this one
       is a decision to record rather than a wall: re-run with --max-error-ratio once you
       have established the errors are confined to code you do not need analysed.
    4  The diagnostics format changed and this checker needs updating. Distinct from 1
       because the database itself may be fine.

Note the gap: argparse exits 2 on a usage error, so a typo'd flag must not be readable as
a threshold decision.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path

# Toolchain paths in src.zip. For compiled languages these outnumber project files
# 10-20x, so counting them would mask an extraction that captured nothing.
#
# Only used for a database whose codeql-database.yml records no source root. A blocklist
# cannot be complete — this one knows where macOS and Debian keep their toolchains, and a
# nix, Homebrew, or vendored-SDK build walks straight past it.
NON_PROJECT_PREFIXES = (
    "Applications/",
    "Library/",
    "Program Files/",
    "System/",
    "nix/store/",
    "opt/",
    "usr/",
)

SOURCE_LOCATION_PREFIX = re.compile(r"^sourceLocationPrefix:\s*(.+?)\s*$", re.MULTILINE)
# CodeQL spells it the British way. Checked on 2.25.6, where an interrupted build leaves
# the key absent rather than false.
FINALISED = re.compile(r"^finalised:\s*(\S+)\s*$", re.MULTILINE)

DEFAULT_MAX_ERROR_RATIO = 5.0


NOTHING_TO_ANALYSE = 1
# 2 belongs to argparse: `--max-error-ratio abc` exits 2, and a caller that reads 2 as
# "ratio exceeded" would raise the threshold for a database it never inspected.
ERROR_RATIO_EXCEEDED = 3
DIAGNOSTICS_FORMAT_CHANGED = 4


class QualityFailure(Exception):
    """A database that must not be analysed.

    `exit_code` separates the unarguable cases from the threshold. Callers that only
    check for non-zero keep working; the build workflow branches on the value.
    """

    def __init__(self, message: str, exit_code: int = NOTHING_TO_ANALYSE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def baseline_lines_of_code(database: Path) -> int:
    """Total baseline LoC across languages, from the database's own metadata."""
    info = database / "baseline-info.json"
    if not info.is_file():
        raise QualityFailure(
            f"{info} is missing. `codeql database create` writes it when it finalizes, "
            f"so the build did not get that far. (`print-baseline` prints a count to "
            f"stdout; it does not create this file.)"
        )
    try:
        data = json.loads(info.read_text())
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as error:
        raise QualityFailure(f"Could not read {info}: {error}") from error

    languages = data.get("languages")
    if not isinstance(languages, dict) or not languages:
        raise QualityFailure(f"{info} lists no languages — the database extracted nothing.")

    total = 0
    for language, entry in languages.items():
        if not isinstance(entry, dict):
            raise QualityFailure(f"{info}: entry for '{language}' is malformed.")
        try:
            total += int(entry.get("linesOfCode", 0))
        except (TypeError, ValueError) as error:
            raise QualityFailure(
                f"{info}: linesOfCode for '{language}' is not a number "
                f"({entry.get('linesOfCode')!r})."
            ) from error
    return total


def _archive_source_root(database: Path) -> str | None:
    """Where project source sits inside src.zip, from the database's own metadata.

    `codeql-database.yml` records the absolute source root, and src.zip stores every file
    at its absolute path minus the leading separator — so everything under that prefix is
    project source and everything else is toolchain, on any platform.

    Verified against a cpp database built by CodeQL 2.25.6: `sourceLocationPrefix: /…/proj`
    in the yml, `private/…/proj/src/main.c` in the archive, and the SDK headers alongside
    it under `Applications/Xcode.app/…`.
    """
    try:
        text = (database / "codeql-database.yml").read_text()
    except (OSError, UnicodeDecodeError):
        return None

    match = SOURCE_LOCATION_PREFIX.search(text)
    if not match:
        return None
    root = match.group(1).strip().strip("'\"").replace("\\", "/").strip("/")
    return f"{root}/" if root else None


def archive_file_count(database: Path) -> int:
    """Every file in the source archive, toolchain included.

    Reported so a caller does not have to run its own `unzip -Z1 | wc -l`. For a compiled
    language this is 10-20x project_file_count — 690 against 66 for an mbedtls cpp
    database on 2.25.6 — which is why it is not the quality signal on its own.
    """
    return len(_archive_files(database))


def _archive_files(database: Path) -> list[str]:
    """Non-directory entries in src.zip."""
    archive = database / "src.zip"
    if not archive.is_file():
        raise QualityFailure(f"{archive} is missing — the database has no source archive.")
    try:
        with zipfile.ZipFile(archive) as handle:
            names = handle.namelist()
    except (zipfile.BadZipFile, OSError) as error:
        raise QualityFailure(f"Could not read {archive}: {error}") from error
    return [name for name in names if not name.endswith("/")]


def is_finalised(database: Path) -> bool:
    """Whether `codeql database finalize` completed.

    A database that is not finalised resolves and analyses, and reports nothing.
    """
    try:
        text = (database / "codeql-database.yml").read_text()
    except (OSError, UnicodeDecodeError):
        return False
    match = FINALISED.search(text)
    return bool(match) and match.group(1).strip().strip("'\"").lower() == "true"


def project_file_count(database: Path) -> int:
    """Files in the source archive that belong to the project, not the toolchain."""
    archive = database / "src.zip"
    files = _archive_files(database)
    root = _archive_source_root(database)
    if root is None:
        return sum(1 for name in files if not name.startswith(NON_PROJECT_PREFIXES))

    under_root = sum(1 for name in files if name.startswith(root))
    if under_root == 0 and any(not name.startswith(NON_PROJECT_PREFIXES) for name in files):
        # Toolchain-only is a real answer, handled by the caller. Non-toolchain files that
        # sit outside the recorded root are not: the archive is laid out in some way this
        # check does not model, and guessing would report a number nobody can trust.
        raise QualityFailure(
            f"No file in {archive} is under the recorded source root ({root}), yet the "
            f"archive holds files that are not toolchain paths either. Its layout does not "
            f"match codeql-database.yml, so project source cannot be told from toolchain."
        )
    return under_root


def _load_records(path: Path) -> list[dict]:
    """Diagnostic records from one file.

    The `.jsonl` extension is not reliable. CodeQL writes some of these as a single
    pretty-printed object spanning many lines, and the directory also holds plain `.json`
    files. Try whole-file JSON first, then line-delimited.
    """
    try:
        text = path.read_text()
    except (OSError, UnicodeDecodeError) as error:
        raise QualityFailure(f"Could not read extractor diagnostics {path}: {error}") from error

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                records.append(json.loads(stripped))
            except json.JSONDecodeError:
                # Neither whole-file JSON nor JSONL. Skipping would under-count, so treat
                # it as a format change that needs handling rather than as zero errors.
                raise QualityFailure(
                    f"{path} is neither a JSON object nor JSON Lines. The diagnostic "
                    f"format has changed and this check needs updating.",
                    DIAGNOSTICS_FORMAT_CHANGED,
                ) from None
        return [r for r in records if isinstance(r, dict)]

    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return [data] if isinstance(data, dict) else []


def _errors_from_one_extractor(records: list[dict]) -> int:
    """CodeQL's own tally if this extractor wrote one, else its severity-`error` records."""
    reported: list[int] = []
    for record in records:
        attributes = record.get("attributes")
        if isinstance(attributes, dict) and "extractor-failures" in attributes:
            try:
                reported.append(int(attributes["extractor-failures"]))
            except (TypeError, ValueError):
                continue
    if reported:
        return sum(reported)

    return sum(1 for record in records if str(record.get("severity", "")).lower() == "error")


def _extractor_of(diagnostics: Path, path: Path) -> str:
    """Which extractor a diagnostic file belongs to.

    The layout is `diagnostic/extractors/<language>/…`. Files sitting directly in
    `extractors/` share one group, since they cannot be attributed further.
    """
    parts = path.relative_to(diagnostics).parts
    return parts[0] if len(parts) > 1 else ""


def extractor_error_count(database: Path) -> int:
    """Extractor failures recorded during the build, summed over extractors.

    Prefers CodeQL's own tally in `summary.jsonl` (`attributes.extractor-failures`), and
    falls back to counting records whose `severity` is `error`. That preference is
    resolved per extractor, not once for the tree: extractors are separate binaries that
    gained summary reporting in different releases, so in a multi-language database one
    may write a summary while another emits only error records. Deciding globally let a
    single `extractor-failures: 0` suppress the fallback for every other language,
    reporting a partially-failed database as clean.

    Counting lines that start with `{` reported 5 errors for a database where CodeQL
    recorded `extractor-failures: 0` and every record was severity `note`: the files are
    pretty-printed despite the `.jsonl` name, so nested braces each counted as a record.

    A missing directory genuinely means zero errors: the extractor creates it only when
    it has something to report.
    """
    diagnostics = database / "diagnostic" / "extractors"
    if not diagnostics.is_dir():
        return 0

    # Only the JSON-family files. `rglob("*")` handed every file to the parser, so a `.log`
    # or `.txt` dropped into this tree by a future release failed the whole gate as a
    # format change — on a database whose LoC and file counts were fine.
    by_extractor: dict[str, list[dict]] = {}
    for path in sorted(p for p in diagnostics.rglob("*.json*") if p.is_file()):
        by_extractor.setdefault(_extractor_of(diagnostics, path), []).extend(_load_records(path))

    return sum(_errors_from_one_extractor(records) for records in by_extractor.values())


def assess(database: Path, max_error_ratio: float = DEFAULT_MAX_ERROR_RATIO) -> dict[str, object]:
    """Return quality metrics, raising QualityFailure if the database is unusable."""
    if not (database / "codeql-database.yml").is_file():
        raise QualityFailure(
            f"{database} is not a CodeQL database (no codeql-database.yml marker)."
        )

    loc = baseline_lines_of_code(database)
    files = project_file_count(database)
    errors = extractor_error_count(database)

    if loc == 0:
        raise QualityFailure(
            "Baseline lines of code is 0 — the database contains no analysable source. "
            "Analysing it would report zero findings for a codebase that was never read."
        )
    if files == 0:
        raise QualityFailure(
            "Zero project files in the source archive (only toolchain paths). "
            "This is the strongest signal that build tracing captured nothing."
        )

    ratio = errors / files * 100
    if ratio > max_error_ratio:
        raise QualityFailure(
            f"Extractor error ratio {ratio:.1f}% exceeds the {max_error_ratio:.1f}% "
            f"threshold ({errors} errors across {files} project files). Findings from "
            f"this database would be incomplete in ways the results cannot show. If the "
            f"failures are confined to code that does not need analysing, re-run with "
            f"--max-error-ratio and record why.",
            ERROR_RATIO_EXCEEDED,
        )

    return {
        "baseline_loc": loc,
        "project_files": files,
        "archive_files": archive_file_count(database),
        "extractor_errors": errors,
        "error_ratio": round(ratio, 1),
        "finalised": is_finalised(database),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path, help="Path to the CodeQL database directory")
    parser.add_argument(
        "--max-error-ratio",
        type=float,
        default=DEFAULT_MAX_ERROR_RATIO,
        help="Percent of project files that may fail extraction "
        f"(default: {DEFAULT_MAX_ERROR_RATIO})",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="json emits the metrics for a caller to read, so nothing has to recompute "
        "them with a second, differently-written shell pipeline",
    )
    args = parser.parse_args(argv)

    try:
        metrics = assess(args.database, args.max_error_ratio)
    except QualityFailure as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return error.exit_code

    if args.format == "json":
        print(json.dumps(metrics))
        return 0

    print(
        f"Database OK: {metrics['baseline_loc']} baseline LoC, "
        f"{metrics['project_files']} project files, "
        f"{metrics['extractor_errors']} extractor errors ({metrics['error_ratio']}%)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
