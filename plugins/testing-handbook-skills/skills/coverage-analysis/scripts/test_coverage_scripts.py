"""Tests for the coverage-analysis helper scripts.

The query-tool tests run anywhere (they use a synthetic llvm-cov export). The replay/report
tests build a tiny instrumented target and are skipped when clang++ or the LLVM coverage tools
are not available.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
REPORT = SCRIPTS / "coverage-report.sh"
QUERY = SCRIPTS / "coverage-query.py"
RUNTIME = SCRIPTS / "execute-rt.cc"

TARGET = """#include <cstdint>
#include <cstdlib>
#include <cstring>
static int guarded(const uint8_t *d, size_t n) { return n > 4 && d[4] == 'X' ? 2 : 1; }
int parse(const uint8_t *d, size_t n) {
  if (n < 4) return -1;
  if (memcmp(d, "\\x7F" "ELF", 4) == 0) return guarded(d, n);   // gate
  if (memcmp(d, "CRSH", 4) == 0) abort();                       // crash path
  return (int)n;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { parse(d, n); return 0; }
"""

SYNTHETIC_EXPORT = {
    "version": "2.0.1",
    "type": "llvm.coverage.json.export",
    "data": [
        {
            "files": [
                {
                    "filename": "/src/a.cc",
                    "summary": {
                        "lines": {"count": 10, "covered": 6, "percent": 60.0},
                        "functions": {"count": 2, "covered": 1, "percent": 50.0},
                        "regions": {"count": 4, "covered": 2, "percent": 50.0},
                        "branches": {"count": 2, "covered": 1, "percent": 50.0},
                    },
                    "segments": [
                        [3, 1, 5, True, True, False],
                        [7, 1, 0, True, True, False],
                        [9, 1, 0, True, True, True],
                    ],
                    "branches": [[3, 5, 3, 9, 5, 0, 0, 0, 4]],
                }
            ],
            "functions": [
                {
                    "name": "a.cc:never",
                    "count": 0,
                    "regions": [[7, 1, 8, 2, 0, 0, 0, 0]],
                    "filenames": ["/src/a.cc"],
                    "branches": [],
                },
                {
                    "name": "run",
                    "count": 5,
                    "regions": [[3, 1, 6, 2, 5, 0, 0, 0], [4, 1, 4, 9, 0, 0, 0, 0]],
                    "filenames": ["/src/a.cc"],
                    "branches": [],
                },
                {
                    "name": "ignored_runtime_fn",
                    "count": 0,
                    "regions": [[1, 1, 2, 2, 0, 1, 0, 0]],
                    "filenames": ["/src/execute-rt.cc"],
                    "branches": [],
                },
            ],
            "totals": {
                "lines": {"count": 10, "covered": 6, "percent": 60.0},
                "functions": {"count": 2, "covered": 1, "percent": 50.0},
                "regions": {"count": 4, "covered": 2, "percent": 50.0},
                "branches": {"count": 2, "covered": 1, "percent": 50.0},
            },
        }
    ],
}


def query(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["uv", "run", "--no-project", str(QUERY), *args], capture_output=True, text=True
    )


@pytest.fixture
def export_file(tmp_path: Path) -> Path:
    p = tmp_path / "coverage.json"
    p.write_text(json.dumps(SYNTHETIC_EXPORT))
    return p


def test_totals_and_files(export_file):
    out = query("--json", str(export_file), "totals").stdout
    assert "lines          6 /     10" in out and "branches       1 /      2" in out
    assert "/src/a.cc  lines 6/10" in query("--json", str(export_file), "files").stdout


def test_functions_lists_all_but_filters_ignored_files(export_file):
    lines = query("--json", str(export_file), "functions").stdout.strip().splitlines()
    assert len(lines) == 2 and not any("ignored_runtime_fn" in line for line in lines)
    unc = query("--json", str(export_file), "functions", "--only-uncovered").stdout
    assert "never" in unc and "NEVER RUN" in unc and "run" not in unc.replace("NEVER RUN", "")
    first = query(
        "--json", str(export_file), "functions", "--uncovered-first", "--limit", "1"
    ).stdout
    assert "never" in first


def test_uncovered_lines_and_branches(export_file):
    out = query("--json", str(export_file), "uncovered-lines", "--file", "a.cc").stdout
    assert "a.cc:7:" in out and "a.cc:9:" not in out  # gap regions are not reported
    branches = query(
        "--json", str(export_file), "branches", "--file", "a.cc", "--only-untaken"
    ).stdout
    assert "a.cc:3:5  true=5  false=0" in branches


def test_query_rejects_bad_or_missing_input(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    assert query("--json", str(bad), "totals").returncode != 0
    assert query("--json", str(tmp_path / "missing.json"), "totals").returncode != 0


def have_toolchain() -> bool:
    if shutil.which("clang++") is None:
        return False
    for tool in ("llvm-profdata", "llvm-cov"):
        on_path = shutil.which(tool) is not None
        via_xcrun = (
            shutil.which("xcrun") is not None
            and subprocess.run(["xcrun", "-f", tool], capture_output=True).returncode == 0
        )
        if not on_path and not via_xcrun:
            return False
    return True


needs_toolchain = pytest.mark.skipif(
    not have_toolchain(), reason="clang++ and llvm-profdata/llvm-cov are required"
)


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("target")
    (d / "target.cc").write_text(TARGET)
    binary = d / "fuzz_exec"
    subprocess.run(
        [
            "clang++",
            "-O0",
            "-g",
            "-fprofile-instr-generate",
            "-fcoverage-mapping",
            str(d / "target.cc"),
            str(RUNTIME),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return binary


def report(binary: Path, corpus: Path, out: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "bash",
            str(REPORT),
            "--binary",
            str(binary),
            "--corpus",
            str(corpus),
            "--out",
            str(out),
            "--ignore",
            "execute-rt.cc",
            "--no-html",
            *extra,
        ],
        capture_output=True,
        text=True,
    )


def totals(out: Path) -> dict:
    t = json.loads((out / "coverage.json").read_text())["data"][0]["totals"]
    return {k: (t[k]["covered"], t[k]["count"]) for k in ("lines", "functions")}


@needs_toolchain
def test_replay_writes_every_artifact_and_reaches_the_gate(built, tmp_path):
    corpus = tmp_path / "corpus with space"
    corpus.mkdir()
    (corpus / "plain").write_bytes(b"hello")
    (corpus / "empty").write_bytes(b"")
    (corpus / "elf").write_bytes(b"\x7fELFX")
    out = tmp_path / "out"
    proc = report(built, corpus, out)
    assert proc.returncode == 0, proc.stderr
    assert totals(out)["functions"] == (3, 3)
    for name in ("coverage.json", "coverage.lcov", "report.txt", "merged.profdata", "summary.txt"):
        assert (out / name).is_file(), name
    assert "NEVER RUN" not in query("--json", str(out / "coverage.json"), "functions").stdout


@needs_toolchain
def test_isolated_replay_records_the_crash_and_keeps_safe_coverage(built, tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "plain").write_bytes(b"hello")
    (corpus / "boom").write_bytes(b"CRSH!")
    out = tmp_path / "out"
    proc = report(built, corpus, out, "--isolate")
    assert proc.returncode == 0, proc.stderr
    crashes = (out / "crashes.txt").read_text()
    assert "boom" in crashes and "signal" in crashes
    assert "crashing inputs: 1" in (out / "summary.txt").read_text()
    assert totals(out)["functions"] == (2, 3)  # `guarded` never ran; the safe input was measured
    plain = report(
        built, corpus, tmp_path / "out2"
    )  # in-process replay of a crashing corpus must not fake a report
    assert plain.returncode == 4 and not (tmp_path / "out2" / "coverage.json").exists()


@needs_toolchain
def test_empty_corpus_is_an_error(built, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    proc = report(built, empty, tmp_path / "out")
    assert proc.returncode == 3 and "nothing was executed" in proc.stderr
