"""Executable checks for the build guards and checksum-triage examples."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, check=False)


def test_repaired_unkeyed_checksum_reaches_the_same_production_bug(tmp_path):
    compiler = shutil.which("clang") or shutil.which("cc")
    if not compiler:
        pytest.skip("requires a C compiler")
    source = tmp_path / "checksum.c"
    source.write_text("""
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    unsigned value = (unsigned)strtoul(argv[1], 0, 10);
    unsigned checksum = (unsigned)strtoul(argv[2], 0, 10);
    if (checksum != ((value + 1) & 255)) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        return 3;
#endif
    }
    /* Exit 9 models reaching the identical faulty processing state. */
    return value == 42 ? 9 : 0;
}
""")
    production = tmp_path / "production"
    fuzzing = tmp_path / "fuzzing"
    assert run(compiler, str(source), "-o", str(production)).returncode == 0
    assert (
        run(
            compiler, "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION", str(source), "-o", str(fuzzing)
        ).returncode
        == 0
    )
    assert run(str(fuzzing), "42", "0").returncode == 9
    assert run(str(production), "42", "0").returncode == 3
    assert run(str(production), "42", "43").returncode == 9
    assert run(str(production), "1", "2").returncode == 0


def test_declared_rust_cfg_is_checked_without_enabling_production_bypass(tmp_path):
    compiler = shutil.which("rustc")
    if not compiler:
        pytest.skip("requires rustc with check-cfg support")
    source = tmp_path / "guard.rs"
    source.write_text('fn main() { println!("{}", cfg!(fuzzing)); }\n')
    production = tmp_path / "production"
    fuzzing = tmp_path / "fuzzing"
    flags = ("--check-cfg", "cfg(fuzzing)", "-D", "warnings")
    assert run(compiler, *flags, str(source), "-o", str(production)).returncode == 0
    assert (
        run(compiler, *flags, "--cfg", "fuzzing", str(source), "-o", str(fuzzing)).returncode == 0
    )
    assert run(str(production)).stdout.strip() == "false"
    assert run(str(fuzzing)).stdout.strip() == "true"


def test_skill_retains_production_replay_and_no_blanket_dismissal():
    skill = Path(__file__).resolve().parents[1] / "skills/fuzzing-obstacles/SKILL.md"
    text = skill.read_text()
    assert "Recompute unkeyed checksums" in text
    assert "mark the finding unresolved" in text
    assert "A crash that needs a bypassed check is not a production bug" not in text


def test_state_critical_validation_is_not_equivalent_to_an_unkeyed_checksum(tmp_path):
    compiler = shutil.which("clang") or shutil.which("cc")
    if not compiler:
        pytest.skip("requires a C compiler")
    source = tmp_path / "validation.c"
    source.write_text("""
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    unsigned divisor = (unsigned)strtoul(argv[1], 0, 10);
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if (!divisor) return 3;
#endif
    /* Exit 9 models the impossible division-by-zero state. */
    return divisor == 0 ? 9 : 0;
}
""")
    production = tmp_path / "production"
    fuzzing = tmp_path / "fuzzing"
    assert run(compiler, str(source), "-o", str(production)).returncode == 0
    assert (
        run(
            compiler, "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION", str(source), "-o", str(fuzzing)
        ).returncode
        == 0
    )
    assert run(str(fuzzing), "0").returncode == 9
    assert run(str(production), "0").returncode == 3
    assert run(str(production), "1").returncode == 0
