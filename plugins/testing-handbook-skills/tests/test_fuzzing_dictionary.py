"""Regression tests for dictionary extraction and byte-level validation."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "fuzzing-dictionary" / "scripts"


def validate(path, *args):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "validate-dict.py"), str(path), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def extract(mode, source, env=None):
    return subprocess.run(
        ["bash", str(SCRIPTS / "make-dict.sh"), mode, str(source)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


@pytest.mark.parametrize(
    "contents",
    [
        "",
        "# Only comments\n",
        '""\n',
        '"same"\n"same"\n',
        '"A"\n"\\x41"\n',
        '"\\xFF"\n"\\xff"\n',
        '"\\n"\n',
        '"\\r"\n',
        '"\\t"\n',
        '"\\xQZ"\n',
        '"\\x0"\n',
        '"\\q"\n',
        '"unterminated\n',
    ],
)
def test_invalid_dictionaries_are_rejected(tmp_path, contents):
    path = tmp_path / "invalid.dict"
    path.write_text(contents)
    result = validate(path)
    assert result.returncode != 0, result.stdout
    assert result.stderr


def test_escaped_backslash_is_not_an_invalid_hex_escape(tmp_path):
    path = tmp_path / "escapes.dict"
    path.write_text('quote="\\""\nslash="\\\\xQZ"\nbytes="\\x00\\xff"\n')
    result = validate(path, "--min-entries", "3", "--max-entries", "3")
    assert result.returncode == 0, result.stderr
    assert "3 entries" in result.stdout
    assert validate(path, "--max-entries", "2").returncode != 0
    assert validate(path, "--min-entries", "4").returncode != 0


def test_missing_dictionary_reports_error(tmp_path):
    result = validate(tmp_path / "missing.dict")
    assert result.returncode != 0
    assert "Traceback" not in result.stderr


def test_header_escapes_preserve_bytes_and_long_literals(tmp_path):
    path = tmp_path / "protocol.h"
    long_token = "z" * 300
    path.write_text(
        '#define MAGIC "\\x89PNG\\r\\n\\x1a\\n"\n'
        '#define REQUEST "GET"\n'
        '#define OTHER "POST"\n'
        '#define OCTAL "\\101\\0"\n'
        '#define ESCAPED "\\\\n"\n'
        '#define DUPLICATE "GET"\n'
        f'#define LONG "{long_token}"\n'
    )
    result = extract("header", path)
    assert result.returncode == 0, result.stderr
    assert set(result.stdout.splitlines()) == {
        '"\\x89PNG\\x0D\\x0A\\x1A\\x0A"',
        '"GET"',
        '"POST"',
        '"A\\x00"',
        '"\\\\n"',
        f'"{long_token}"',
    }
    dictionary = tmp_path / "protocol.dict"
    dictionary.write_text(result.stdout)
    assert validate(dictionary, "--min-entries", "6", "--max-entries", "6").returncode == 0


def test_binary_escapes_and_long_strings(tmp_path):
    path = tmp_path / "input.bin"
    path.write_bytes(b'ABC\0quote"slash\\\0ABC\0' + b"x" * 300 + b"\0")
    result = extract("binary", path)
    assert result.returncode == 0, result.stderr
    assert set(result.stdout.splitlines()) == {
        '"ABC"',
        '"quote\\"slash\\\\"',
        '"' + "x" * 300 + '"',
    }


@pytest.mark.parametrize("mode", ["header", "binary"])
def test_empty_and_missing_input_fail(tmp_path, mode):
    path = tmp_path / "empty"
    path.touch()
    assert extract(mode, path).returncode != 0
    assert extract(mode, tmp_path / "missing").returncode != 0


def test_man_flags_and_no_flags(tmp_path):
    binaries = tmp_path / "bin"
    binaries.mkdir()
    man = binaries / "man"
    man.write_text("#!/bin/sh\nprintf '  -v, --verbose  enable logging\\n  --help  help\\n'\n")
    col = binaries / "col"
    col.write_text("#!/bin/sh\ncat\n")
    for program in (man, col):
        program.chmod(0o755)
    env = {**os.environ, "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}"}
    result = extract("man", "target", env)
    assert result.returncode == 0, result.stderr
    assert set(result.stdout.splitlines()) == {'"-v"', '"--verbose"', '"--help"'}
    man.write_text("#!/bin/sh\nprintf 'No options here\\n'\n")
    assert extract("man", "target", env).returncode != 0
