# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Measure post-campaign corpus coverage using configured coverage infrastructure."""

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import calcifier as c


def execute(
    argv: list[str],
    directory: Path,
    records: list[dict[str, Any]],
    *,
    mutating: bool,
    allow_failure: bool = False,
) -> c.CommandResult:
    result = c.run_command(
        argv, working_directory=directory, mutating=mutating, timeout_seconds=3600
    )
    record: dict[str, Any] = {"argv": argv, "exit_code": result.exit_code}
    record.update(stdout=result.stdout, stderr=result.stderr)
    records.append(record)
    if result.exit_code != 0 and not allow_failure:
        c.emit(records, name="failed-commands")
        c.fail(f"Coverage command failed: {argv!r}\n{result.stderr}\n{result.stdout}")
    return result


@c.step
def coverage_counts(text: str, backend: str) -> dict[str, dict[str, int]]:
    document = json.loads(text)
    if backend == "gcc":
        entries = [
            (row["filename"], row["line_total"], row["line_covered"]) for row in document["files"]
        ]
    else:
        entries = [
            (row["filename"], row["summary"]["lines"]["count"], row["summary"]["lines"]["covered"])
            for group in document["data"]
            for row in group["files"]
        ]
    counts: dict[str, dict[str, int]] = {}
    for filename, total, covered in entries:
        if not filename or filename in counts or not 0 <= covered <= total:
            c.fail("Coverage contains an invalid count, empty filename, or duplicate file.")
        counts[filename] = {"lines_total": total, "lines_covered": covered}
    if not counts or not any(row["lines_total"] for row in counts.values()):
        c.fail("Coverage inspection scope contains no instrumented source lines.")
    return counts


@c.recipe(
    name="coverage-analysis",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=c.Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="coverage-analysis",
)
def coverage_analysis(
    project_directory: str,
    corpus_directory: str,
    toolchain: Literal["llvm", "gcc", "rust"] = "llvm",
    coverage_binary: str = "",
    gcov_directory: str = ".",
    rust_target: str = "",
    build_argv: list[str] | None = None,
    source_filters: list[str] | None = None,
    exclude_regex: str = r"(^|.*/)(harness\.cc|execute-rt\.cc)$",
    gcov_mode: Literal["fresh", "incremental"] = "fresh",
    baseline_measurement: str = "",
    task: str = "Analyze this completed fuzzing campaign and recommend coverage improvements.",
) -> str:
    """Native binaries use the skill's corpus-directory runtime; tools must be installed."""
    project = Path(project_directory).resolve()
    corpus = Path(corpus_directory).resolve()
    if not project.is_dir() or not corpus.is_dir():
        c.fail("Project and post-campaign corpus must be existing directories.")
    entries = sorted(corpus.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in entries):
        c.fail("Use a flat corpus of regular files; nested directories and symlinks need review.")
    if not entries:
        c.fail("Cannot inspect an empty corpus: no test cases would be replayed.")
    manifest = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in entries}
    if source_filters == []:
        c.fail("The explicitly requested source inspection scope is empty.")
    filters = [(project / name).resolve() for name in source_filters or ["."]]
    if any(not path.is_relative_to(project) or not path.exists() for path in filters):
        c.fail("Source filters must identify existing files or directories inside the project.")
    names = (
        "coverage.profraw",
        "coverage.profdata",
        "coverage.json",
        "summary.json",
        "report.txt",
        "report.html",
        "measurement.json",
        "commands.json",
        "analysis.md",
    )
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    folder = c.ensure_directory(stamp, output_files=names, exclude_roots=(corpus,))
    records: list[dict[str, Any]] = []
    if build_argv:
        execute(build_argv, project, records, mutating=True)
    profile = folder / "coverage.profdata"
    binary = (project / coverage_binary).resolve()
    gcov = (project / gcov_directory).resolve()
    if toolchain == "rust":
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]*", rust_target):
            c.fail("Rust coverage requires a fuzz target name without path components.")
        version = execute(["rustc", "+nightly", "-vV"], project, records, mutating=False)
        hosts = [
            line[6:].strip() for line in version.stdout.splitlines() if line.startswith("host: ")
        ]
        if len(hosts) != 1:
            c.fail("Could not determine the nightly Rust host triple.")
        replay = execute(
            ["cargo", "+nightly", "fuzz", "coverage", rust_target, str(corpus)],
            project,
            records,
            mutating=True,
        )
        if not coverage_binary:
            binary = project / "target" / hosts[0] / "coverage" / hosts[0] / "release" / rust_target
        raw_profile = project / "fuzz" / "coverage" / rust_target / "coverage.profdata"
        profdata = ["cargo", "+nightly", "profdata", "--"]
        cov = ["cargo", "+nightly", "cov", "--"]
    else:
        if not coverage_binary or not binary.is_file():
            c.fail("Provide an instrumented corpus-directory runner; build_argv can build it.")
        if toolchain == "gcc":
            if not gcov.is_dir() or not any(gcov.rglob("*.gcno")):
                c.fail("GCC coverage infrastructure has no .gcno files in gcov_directory.")
            if gcov_mode == "fresh":
                execute(
                    ["gcovr", "--root", str(project), "--object-directory", str(gcov), "--delete"],
                    project,
                    records,
                    mutating=True,
                )
                if any(gcov.rglob("*.gcda")):
                    c.fail("Stale .gcda files remain; review the fresh GCC reset scope.")
        argv = [str(binary), str(corpus)]
        if toolchain == "llvm":
            argv = ["env", f"LLVM_PROFILE_FILE={folder / 'coverage.profraw'}", *argv]
        replay = execute(argv, project, records, mutating=True, allow_failure=True)
        raw_profile = folder / "coverage.profraw"
        profdata = ["llvm-profdata"]
        cov = ["llvm-cov"]
    if toolchain != "gcc":
        execute(
            [*profdata, "merge", "-sparse", str(raw_profile), "-o", str(profile)],
            project,
            records,
            mutating=True,
        )
    if toolchain == "gcc":
        base = ["gcovr", "--root", str(project), "--object-directory", str(gcov)]
        base += ["--exclude", exclude_regex]
        for path in filters:
            base += ["--filter", re.escape(str(path))]
        jobs = {
            "coverage.json": [*base, "--json"],
            "summary.json": [*base, "--json-summary"],
            "report.txt": base,
            "report.html": [*base, "--html", "--html-self-contained"],
        }
    else:
        base = [str(binary), f"-instr-profile={profile}", f"-ignore-filename-regex={exclude_regex}"]
        if toolchain == "rust":
            base += ["-Xdemangler=rustfilt"]
        selected = [str(path) for path in filters]
        jobs = {
            "coverage.json": [*cov, "export", *base, *selected],
            "report.txt": [*cov, "report", *base, *selected],
            "report.html": [
                *cov,
                "show",
                *base,
                "-format=html",
                "-show-line-counts-or-regions",
                "-show-instantiations",
                *selected,
            ],
        }
    reports: dict[str, str] = {}
    for name, argv in jobs.items():
        reports[name] = execute(argv, project, records, mutating=toolchain == "gcc").stdout
        if not reports[name].strip():
            c.fail(f"Coverage tool returned an empty required report: {name}")
        c.write_text(folder / name, reports[name])
    counts = coverage_counts(reports.get("summary.json", reports["coverage.json"]), toolchain)
    after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in corpus.iterdir()}
    if after != manifest:
        c.fail("Corpus changed during coverage collection; this measurement is not reproducible.")
    totals = {
        key: sum(row[key] for row in counts.values()) for key in ("lines_total", "lines_covered")
    }
    percentage = 100.0 * totals["lines_covered"] / totals["lines_total"]
    measurement: dict[str, Any] = {
        "schema_version": 1,
        "timestamp": stamp,
        "toolchain": toolchain,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "corpus": manifest,
        "source_filters": [str(path) for path in filters],
        "exclude_regex": exclude_regex,
        "files": counts,
        "totals": totals,
        "line_percent": percentage,
        "replay_exit_code": replay.exit_code,
        "incremental_gcc": toolchain == "gcc" and gcov_mode == "incremental",
    }
    baseline_files = (Path(baseline_measurement).resolve(),) if baseline_measurement else ()
    if baseline_files:
        previous = json.loads(baseline_files[0].read_text(encoding="utf-8"))
        if previous.get("schema_version") != 1 or not previous.get("files"):
            c.fail("Baseline must be a nonempty measurement.json produced by this recipe.")
        measurement["comparison"] = {
            "deltas": {key: totals[key] - previous["totals"][key] for key in totals},
            "percentage_point_delta": percentage - previous["line_percent"],
        }
    c.write_json(folder / "measurement.json", measurement)
    c.write_json(folder / "commands.json", records)
    c.emit(measurement, name="measurement")
    context_names = ("coverage.json", "report.txt", "measurement.json", "commands.json")
    if toolchain == "gcc":
        context_names += ("summary.json",)
    context = c.prepare_context(
        task,
        instructions=(
            "Interpret the complete campaign evidence and project using the authoritative skill. "
            "Host commands and parsed counts are observations, not completed understanding. "
            "Preserve the original reasoning workflow and checks, including applicability. "
            "Review scoped coverage records, relevant source, baseline changes, and limitations. "
            "Exit codes alone do not prove full replay; identify partial or cumulative evidence. "
            "Return the final analysis and next steps; use embedded context when complete."
        ),
        files=tuple(folder / name for name in context_names) + baseline_files,
        readable_roots=(project, corpus, folder, *baseline_files),
    )
    interpretation = c.agent(
        "worker",
        "Interpret the complete evidence using the assigned task and source skill.",
        working_directory=project,
        readable_paths=(project, corpus, folder, *baseline_files),
        context=context,
        output=str,
        timeout=3600,
    )
    if not interpretation.strip():
        c.fail("Coverage interpretation was empty; no completed analysis can be reported.")
    report = (
        f"Corpus files supplied: {len(entries)}; runner exit code: {replay.exit_code}.\n"
        f"Covered source lines: {totals['lines_covered']}/{totals['lines_total']} "
        f"({percentage:.2f}%).\n\n{interpretation}"
    )
    c.write_text(folder / "analysis.md", report)
    artifacts = [str(folder / name) for name in context_names + ("report.html", "analysis.md")]
    if toolchain != "gcc":
        artifacts.append(str(profile))
    c.emit(artifacts, name="coverage-artifacts")
    return c.emit(report, name="coverage-analysis")


if __name__ == "__main__":
    raise SystemExit(coverage_analysis.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("9f71cfaffec44f159aa333924a25cdbe3eebd221cc7c0b0175fb93794d3ecacc"),
}
_CALCIFIER_RESOURCES = []
_CALCIFIER_INTERFACE = {
    "text": (
        "The destination repository uses Ruff rules E, F, I, UP, B,"
        " and SIM, target-version py311, and line-length 100. The g"
        "enerated recipe must satisfy those checks, including B007,"
        " B905, and SIM102. Keep the Python 3.13 minimum required b"
        "y Calcifier in its generated PEP 723 header. This skill is"
        " distributed independently: do not require another unmerge"
        "d skill recipe. Referenced prose and explicitly provided r"
        "esources may be packaged, while the generated recipe belon"
        "gs only to the requested skill. Repository contribution ru"
        "le: a checker that inspects zero items must fail with an e"
        "xplanation rather than return a successful clean report. T"
        "his applies to an empty inspection scope, not to a complet"
        "ed inspection that finds zero issues."
    ),
    "sha256": ("12c73b0662a6bdb615688c499f4e3e22540e4788549e5ad24bb7e01f76c25fcc"),
}
_CALCIFIER_SUBRECIPES = []
