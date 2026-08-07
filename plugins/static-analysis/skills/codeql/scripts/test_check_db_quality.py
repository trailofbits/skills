"""Regression tests for the database quality gate.

The workflow used to compute these metrics and print them, special-casing zero files to
"N/A (no files)" — so a database that extracted nothing still got analysed. These pin
the thresholds that now stop it.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from check_db_quality import (
    DIAGNOSTICS_FORMAT_CHANGED,
    ERROR_RATIO_EXCEEDED,
    QualityFailure,
    assess,
    is_finalised,
    main,
)

PROJECT_FILES = ["src/app.c", "src/util.c", "include/app.h"]
TOOLCHAIN_FILES = ["usr/include/stdio.h", "Library/Developer/SDK/string.h", "System/x.h"]


def _database(
    tmp_path: Path,
    *,
    loc: int = 1200,
    project_files: list[str] | None = None,
    toolchain_files: list[str] | None = None,
    source_prefix: str | None = None,
    extractor_errors: int = 0,
    baseline: bool = True,
    archive: bool = True,
) -> Path:
    """Build a directory shaped like a finalized CodeQL database.

    With `source_prefix`, the yml records a source root and the archive stores project
    files beneath it, as CodeQL does. Without one, it falls back to the toolchain
    blocklist — which is what a database from a CLI old enough to omit the key gets.
    """
    database = tmp_path / "codeql.db"
    database.mkdir(parents=True, exist_ok=True)
    marker = "primaryLanguage: cpp\nfinalised: true\n"
    if source_prefix:
        marker += f"sourceLocationPrefix: {source_prefix}\n"
    (database / "codeql-database.yml").write_text(marker)

    if baseline:
        files = project_files if project_files is not None else PROJECT_FILES
        (database / "baseline-info.json").write_text(
            json.dumps({"languages": {"cpp": {"linesOfCode": loc, "files": files}}})
        )

    if archive:
        root = (source_prefix or "").replace("\\", "/").strip("/")
        sources = project_files if project_files is not None else PROJECT_FILES
        names = [f"{root}/{name}" if root else name for name in sources]
        names += toolchain_files if toolchain_files is not None else TOOLCHAIN_FILES
        with zipfile.ZipFile(database / "src.zip", "w") as handle:
            for name in names:
                handle.writestr(name, "// source\n")

    if extractor_errors:
        diagnostics = database / "diagnostic" / "extractors" / "cpp"
        diagnostics.mkdir(parents=True)
        (diagnostics / "errors.jsonl").write_text(
            "".join(f'{{"severity":"error","n":{i}}}\n' for i in range(extractor_errors))
        )

    return database


def _diag(database: Path, name: str, payload: str) -> Path:
    directory = database / "diagnostic" / "extractors" / "cpp"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(payload)
    return path


# --- the thresholds that did not previously exist ---------------------------------


def test_zero_baseline_loc_fails(tmp_path: Path) -> None:
    """No analysable source must halt the run, not produce a clean report."""
    with pytest.raises(QualityFailure, match="Baseline lines of code is 0"):
        assess(_database(tmp_path, loc=0))


def test_zero_project_files_fails(tmp_path: Path) -> None:
    """Only toolchain paths in src.zip means build tracing captured nothing.

    The case the old shell forgave with "N/A (no files)".
    """
    with pytest.raises(QualityFailure, match="Zero project files"):
        assess(_database(tmp_path, project_files=[]))


def test_error_ratio_over_threshold_fails(tmp_path: Path) -> None:
    with pytest.raises(QualityFailure, match="error ratio"):
        assess(_database(tmp_path, extractor_errors=3))  # 3/3 files = 100%


def test_error_ratio_under_threshold_passes(tmp_path: Path) -> None:
    many = [f"src/f{i}.c" for i in range(100)]
    metrics = assess(_database(tmp_path, project_files=many, extractor_errors=2))
    assert metrics["error_ratio"] == 2.0


def test_threshold_is_configurable(tmp_path: Path) -> None:
    database = _database(tmp_path, extractor_errors=3)
    with pytest.raises(QualityFailure):
        assess(database, max_error_ratio=5.0)
    assert assess(database, max_error_ratio=100.0)["extractor_errors"] == 3


# --- toolchain files must not be mistaken for project source ----------------------


def test_toolchain_files_do_not_count_as_project_source(tmp_path: Path) -> None:
    """Counting SDK headers would let an extraction that captured only headers pass."""
    database = _database(
        tmp_path,
        project_files=[],
        toolchain_files=[f"usr/include/h{i}.h" for i in range(200)],
    )
    with pytest.raises(QualityFailure, match="Zero project files"):
        assess(database)


def test_the_source_root_beats_the_toolchain_blocklist(tmp_path: Path) -> None:
    """A Linux toolchain under `nix/store/` is not project source, and no list knows that.

    The blocklist was macOS-shaped, so these 200 headers counted as project files: the
    error-ratio denominator inflated and the gate softened. The recorded source root
    settles it without the list having to name every platform's toolchain location.
    """
    database = _database(
        tmp_path,
        source_prefix="/srv/build/proj",
        project_files=["src/app.c", "src/util.c"],
        toolchain_files=[f"nix/store/x-gcc-13/include/h{i}.h" for i in range(200)],
    )
    assert assess(database)["project_files"] == 2


def test_real_archive_layout_from_codeql_2_25_6(tmp_path: Path) -> None:
    """Pin the contract, copied from a cpp database this skill's own workflow built.

    src.zip stores each file at its absolute path minus the leading slash, so the source
    root from the yml is a literal prefix of the project's entries and of nothing else.
    """
    database = _database(
        tmp_path,
        source_prefix="/private/tmp/scan/proj",
        project_files=["src/main.c"],
        toolchain_files=[
            "Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/"
            "Developer/SDKs/MacOSX.sdk/usr/include/stdio.h"
        ],
    )
    with zipfile.ZipFile(database / "src.zip") as handle:
        assert "private/tmp/scan/proj/src/main.c" in handle.namelist()
    assert assess(database)["project_files"] == 1


def test_toolchain_only_archive_fails_even_with_a_source_root(tmp_path: Path) -> None:
    """Nothing under the root is the signal the gate exists for, not a layout problem."""
    database = _database(
        tmp_path,
        source_prefix="/srv/build/proj",
        project_files=[],
        toolchain_files=[f"usr/include/h{i}.h" for i in range(50)],
    )
    with pytest.raises(QualityFailure, match="Zero project files"):
        assess(database)


def test_archive_that_ignores_the_source_root_fails_loudly(tmp_path: Path) -> None:
    """Files outside the root that are not toolchain paths mean an unmodelled layout.

    Counting them as project source, or as zero, would both report a number nobody can
    check. Windows drive letters are the case most likely to land here.
    """
    database = _database(tmp_path, project_files=["src/app.c"], toolchain_files=[])
    (database / "codeql-database.yml").write_text(
        "primaryLanguage: cpp\nfinalised: true\nsourceLocationPrefix: /srv/build/proj\n"
    )
    with pytest.raises(QualityFailure, match="layout does not match"):
        assess(database)


def test_healthy_database_passes(tmp_path: Path) -> None:
    metrics = assess(_database(tmp_path))
    assert metrics["baseline_loc"] == 1200
    assert metrics["project_files"] == len(PROJECT_FILES)
    assert metrics["extractor_errors"] == 0


# --- malformed inputs are failures, not zeros -------------------------------------


def test_missing_marker_fails(tmp_path: Path) -> None:
    plain = tmp_path / "not-a-db"
    plain.mkdir()
    with pytest.raises(QualityFailure, match="not a CodeQL database"):
        assess(plain)


def test_missing_baseline_info_fails(tmp_path: Path) -> None:
    with pytest.raises(QualityFailure, match="baseline-info.json"):
        assess(_database(tmp_path, baseline=False))


def test_missing_source_archive_fails(tmp_path: Path) -> None:
    with pytest.raises(QualityFailure, match="src.zip"):
        assess(_database(tmp_path, archive=False))


def test_empty_language_map_fails(tmp_path: Path) -> None:
    database = _database(tmp_path)
    (database / "baseline-info.json").write_text(json.dumps({"languages": {}}))
    with pytest.raises(QualityFailure, match="no languages"):
        assess(database)


def test_parses_baseline_info_as_codeql_actually_writes_it(tmp_path: Path) -> None:
    """Pin the real contract, copied verbatim from a database built by CodeQL 2.25.6.

    `codeql database create` writes baseline-info.json when it finalizes. `print-baseline`
    prints a count to stdout and creates nothing, so the file is the only machine-readable
    source. Extra keys (displayName, name) must not break parsing.
    """
    database = _database(tmp_path, baseline=False)
    (database / "baseline-info.json").write_text(
        json.dumps(
            {
                "languages": {
                    "python": {
                        "displayName": "Python",
                        "files": ["app.py"],
                        "linesOfCode": 5,
                        "name": "python",
                    }
                }
            }
        )
    )
    assert assess(database)["baseline_loc"] == 5


def test_sums_lines_of_code_across_languages(tmp_path: Path) -> None:
    """`languages` is a map, so a multi-language database has more than one entry."""
    database = _database(tmp_path, baseline=False)
    (database / "baseline-info.json").write_text(
        json.dumps(
            {
                "languages": {
                    "python": {"linesOfCode": 5, "files": ["a.py"]},
                    "cpp": {"linesOfCode": 7, "files": ["b.c"]},
                }
            }
        )
    )
    assert assess(database)["baseline_loc"] == 12


# --- diagnostics: severity, not brace count ---------------------------------------


def test_pretty_printed_notes_are_not_errors(tmp_path: Path) -> None:
    """The regression. Verbatim from a healthy database built by CodeQL 2.25.6.

    Despite the `.jsonl` name this is one pretty-printed object. Counting lines starting
    with `{` scored its nested braces as records and failed the database at a 500% error
    ratio, while CodeQL reported extractor-failures: 0.
    """
    database = _database(tmp_path)
    _diag(
        database,
        "autobuilder-41150.jsonl",
        json.dumps(
            {
                "timestamp": "2026-07-30T23:47:17Z",
                "source": {
                    "id": "cpp/autobuilder/buildless/mode-active",
                    "name": "C/C++ was extracted with build-mode set to 'none'",
                    "extractorName": "cpp",
                },
                "severity": "note",
                "visibility": {"statusPage": False, "telemetry": True},
                "attributes": {"tried": []},
            },
            indent=2,
        ),
    )
    assert assess(database)["extractor_errors"] == 0


def test_codeql_own_failure_count_wins(tmp_path: Path) -> None:
    """summary.jsonl carries `extractor-failures`, which is authoritative."""
    database = _database(tmp_path, project_files=[f"src/f{i}.c" for i in range(100)])
    _diag(
        database,
        "summary.jsonl",
        json.dumps({"attributes": {"extractor-failures": 3, "extractor-successes": 97}}, indent=4),
    )
    assert assess(database)["extractor_errors"] == 3


def test_failure_counts_sum_across_extractors(tmp_path: Path) -> None:
    database = _database(tmp_path, project_files=[f"src/f{i}.c" for i in range(100)])
    for lang, failures in (("cpp", 2), ("python", 1)):
        directory = database / "diagnostic" / "extractors" / lang
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "summary.jsonl").write_text(
            json.dumps({"attributes": {"extractor-failures": failures}})
        )
    assert assess(database)["extractor_errors"] == 3


def test_a_summary_from_one_extractor_does_not_mask_another(tmp_path: Path) -> None:
    """The summary-vs-severity preference is per extractor, not per database.

    Resolved globally, cpp's `extractor-failures: 0` returned 0 for the whole tree and
    python's four error records vanished — a database whose python extraction largely
    failed passed the ratio gate at 0.0%.
    """
    database = _database(tmp_path, project_files=[f"src/f{i}.c" for i in range(100)])
    extractors = database / "diagnostic" / "extractors"
    (extractors / "cpp").mkdir(parents=True)
    (extractors / "cpp" / "summary.jsonl").write_text(
        json.dumps({"attributes": {"extractor-failures": 0, "extractor-successes": 40}})
    )
    (extractors / "python").mkdir(parents=True)
    (extractors / "python" / "errors.jsonl").write_text(
        "\n".join(json.dumps({"severity": "error", "n": i}) for i in range(4))
    )
    assert assess(database)["extractor_errors"] == 4


def test_summary_and_severity_extractors_are_both_counted(tmp_path: Path) -> None:
    """Each extractor contributes by whichever measure it recorded."""
    database = _database(tmp_path, project_files=[f"src/f{i}.c" for i in range(100)])
    extractors = database / "diagnostic" / "extractors"
    (extractors / "cpp").mkdir(parents=True)
    (extractors / "cpp" / "summary.jsonl").write_text(
        json.dumps({"attributes": {"extractor-failures": 2}})
    )
    (extractors / "python").mkdir(parents=True)
    (extractors / "python" / "errors.jsonl").write_text(
        "\n".join(json.dumps({"severity": s}) for s in ("error", "note", "error", "error"))
    )
    assert assess(database)["extractor_errors"] == 5


def test_severity_fallback_counts_only_errors(tmp_path: Path) -> None:
    """With no summary present, count severity `error` and ignore note/warning."""
    database = _database(tmp_path, project_files=[f"src/f{i}.c" for i in range(100)])
    _diag(
        database,
        "records.jsonl",
        "\n".join(
            json.dumps({"severity": s}) for s in ("note", "error", "warning", "error", "note")
        ),
    )
    assert assess(database)["extractor_errors"] == 2


def test_plain_json_diagnostics_are_read_too(tmp_path: Path) -> None:
    """The directory holds `.json` files as well; globbing `*.jsonl` skipped them."""
    database = _database(tmp_path, project_files=[f"src/f{i}.c" for i in range(100)])
    _diag(database, "standalone-extraction.0.json", json.dumps({"severity": "error"}))
    assert assess(database)["extractor_errors"] == 1


def test_unparseable_diagnostics_fail_rather_than_count_zero(tmp_path: Path) -> None:
    """A format change must be visible, not silently reported as a healthy database."""
    database = _database(tmp_path)
    _diag(database, "weird.jsonl", "not json at all\nnor this")
    with pytest.raises(QualityFailure, match="format has changed"):
        assess(database)


def test_absent_extractor_diagnostics_mean_zero_errors(tmp_path: Path) -> None:
    """Absent is genuinely zero here, unlike the cases above where absent data fails.

    Pinned so nobody "fixes" it into a spurious error.
    """
    database = _database(tmp_path)
    assert not (database / "diagnostic").exists()
    assert assess(database)["extractor_errors"] == 0


# --- CLI ---------------------------------------------------------------------------


def test_cli_exits_nonzero_on_bad_database(tmp_path: Path) -> None:
    assert main([str(_database(tmp_path, loc=0))]) == 1


def test_nothing_to_analyse_and_ratio_exceeded_get_different_exits(tmp_path: Path) -> None:
    """The build workflow branches on these, so they must not collapse to "non-zero".

    Exit 1 is unarguable — there is no source to analyse. Exit 2 is a threshold a
    legitimate partial extraction can exceed, and the workflow is allowed to override it
    with --max-error-ratio. Reporting both as 1 would make that override look like the
    same decision as ignoring an empty database.
    """
    assert main([str(_database(tmp_path, project_files=[]))]) == 1
    assert main([str(_database(tmp_path, extractor_errors=3))]) == ERROR_RATIO_EXCEEDED


def test_raising_the_threshold_clears_only_the_ratio_failure(tmp_path: Path) -> None:
    """The escape hatch must not also wave through a database with nothing in it."""
    assert main([str(_database(tmp_path, extractor_errors=3)), "--max-error-ratio", "100"]) == 0
    assert main([str(_database(tmp_path, loc=0)), "--max-error-ratio", "100"]) == 1


def test_json_output_carries_the_metrics_the_docs_read(tmp_path: Path, capsys) -> None:
    """quality-assessment.md reads these keys with jq instead of recomputing them.

    A second hand-written pipeline is how the doc came to log 202 project files while the
    script reported 2 — it filtered a macOS-shaped prefix list rather than the source root.
    """
    assert main([str(_database(tmp_path)), "--format=json"]) == 0
    metrics = json.loads(capsys.readouterr().out)
    assert set(metrics) == {
        "baseline_loc",
        "project_files",
        "archive_files",
        "extractor_errors",
        "error_ratio",
        "finalised",
    }
    assert metrics["project_files"] == len(PROJECT_FILES)
    # archive_files counts the toolchain too, so it is the larger of the two. The doc used
    # to get this from its own `unzip -Z1 | wc -l`.
    assert metrics["archive_files"] > metrics["project_files"]
    assert metrics["finalised"] is True


def test_cli_exits_zero_on_healthy_database(tmp_path: Path) -> None:
    assert main([str(_database(tmp_path))]) == 0


def test_cli_accepts_max_error_ratio(tmp_path: Path) -> None:
    database = _database(tmp_path, extractor_errors=3)
    assert main([str(database)]) == ERROR_RATIO_EXCEEDED
    assert main([str(database), "--max-error-ratio", "100"]) == 0


def test_exit_codes_avoid_argparses_usage_status(tmp_path: Path) -> None:
    """argparse exits 2 on a bad command line, so no verdict of ours may use 2.

    build-database.md tells the reader that the ratio exit means "re-run with a raised
    --max-error-ratio". Sharing 2 with argparse made `--max-error-ratio abc` — which
    inspects nothing — indistinguishable from that verdict.
    """
    assert 2 not in {ERROR_RATIO_EXCEEDED, DIAGNOSTICS_FORMAT_CHANGED}
    with pytest.raises(SystemExit) as usage_error:
        main([str(_database(tmp_path)), "--max-error-ratio", "not-a-number"])
    assert usage_error.value.code == 2


def test_a_non_json_file_in_the_diagnostics_tree_is_ignored(tmp_path: Path) -> None:
    """A future release dropping a .log there must not fail an otherwise good database.

    Every file under diagnostic/extractors used to be handed to the JSON parser, and the
    resulting failure carried the non-overridable "nothing to analyse" code.
    """
    database = _database(tmp_path, project_files=[f"src/f{i}.c" for i in range(100)])
    _diag(database, "records.jsonl", json.dumps({"severity": "error"}))
    (database / "diagnostic" / "extractors" / "cpp" / "extractor.log").write_text(
        "2026-07-31 building ...\nnot json at all\n"
    )
    assert assess(database)["extractor_errors"] == 1


def test_a_malformed_json_diagnostic_still_fails_with_its_own_code(tmp_path: Path) -> None:
    """Narrowing the glob must not silence the format-change signal it was added for."""
    database = _database(tmp_path)
    _diag(database, "weird.jsonl", "not json at all\nnor this")
    assert main([str(database)]) == DIAGNOSTICS_FORMAT_CHANGED


def test_an_unfinalised_database_is_reported_as_such(tmp_path: Path) -> None:
    """An interrupted build leaves the key absent, not false.

    `codeql database finalize` after a failed trace-command is the case: the database
    resolves, analyses, and reports nothing.
    """
    database = _database(tmp_path)
    marker = database / "codeql-database.yml"
    marker.write_text(marker.read_text().replace("finalised: true\n", ""))
    assert is_finalised(database) is False
    assert assess(database)["finalised"] is False
