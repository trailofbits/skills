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


def extract(mode, source, env=None, backend="libfuzzer"):
    return subprocess.run(
        ["bash", str(SCRIPTS / "make-dict.sh"), mode, str(source), "--backend", backend],
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


def test_header_escapes_preserve_bytes_and_flag_overlong_literals(tmp_path):
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
    assert result.returncode == 2, result.stderr
    assert f'candidate "{long_token}"' in result.stdout
    assert set(line for line in result.stdout.splitlines() if not line.startswith("#")) == {
        '"\\x89PNG\\x0D\\x0A\\x1A\\x0A"',
        '"GET"',
        '"POST"',
        '"A\\x00"',
        '"\\\\n"',
    }
    dictionary = tmp_path / "protocol.dict"
    dictionary.write_text(result.stdout)
    assert "unresolved partial extraction" in validate(dictionary).stderr
    dictionary.write_text(
        "\n".join(line for line in result.stdout.splitlines() if not line.startswith("#"))
    )
    assert validate(dictionary, "--min-entries", "5", "--max-entries", "5").returncode == 0


def test_binary_escapes_and_long_strings(tmp_path):
    path = tmp_path / "input.bin"
    path.write_bytes(b'ABC\0quote"slash\\\0ABC\0' + b"x" * 300 + b"\0")
    result = extract("binary", path)
    assert result.returncode == 2, result.stderr
    assert "300 bytes exceeds libfuzzer limit 64" in result.stdout
    assert set(line for line in result.stdout.splitlines() if not line.startswith("#")) == {
        '"ABC"',
        '"quote\\"slash\\\\"',
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


@pytest.mark.parametrize("backend,limit", [("libfuzzer", 64), ("afl++", 128)])
def test_backend_limits_count_decoded_bytes(tmp_path, backend, limit):
    path = tmp_path / "boundary.dict"
    path.write_text('"' + r"\x41" * limit + '"\n')
    assert validate(path, "--backend", backend).returncode == 0
    path.write_text('"' + r"\x41" * (limit + 1) + '"\n')
    result = validate(path, "--backend", backend)
    assert result.returncode == 1
    assert f"{limit}-byte" in result.stderr


def test_single_entry_levels_spaces_and_numeric_labels(tmp_path):
    path = tmp_path / "small.dict"
    for entry in ['"GET"', 'keyword@1 = "GET"', '123 = "GET"']:
        path.write_text(entry + "\n")
        assert validate(path).returncode == 0


def test_duplicate_error_names_both_source_lines(tmp_path):
    path = tmp_path / "duplicates.dict"
    path.write_text('# header\n"GET"\n"\\x47ET"\n')
    assert "line 3 duplicates line 2" in validate(path).stderr


def test_partial_header_preserves_good_literals_and_original_non_utf8_bytes(tmp_path):
    path = tmp_path / "protocol.h"
    path.write_bytes(
        b'// "COMMENT"\nchar *a="GET";\nchar *bad="\\q";\nchar *b="\\r\\n";\nchar *c="\xffPNG";\n'
    )
    result = extract("header", path)
    assert result.returncode == 2
    assert "line 3: unsupported C escape" in result.stdout
    assert '"GET"' in result.stdout
    assert '"\\x0D\\x0A"' in result.stdout
    assert '"\\xFFPNG"' in result.stdout
    assert "COMMENT" not in result.stdout


def test_raw_prefixed_and_unterminated_literals_are_explicitly_partial(tmp_path):
    path = tmp_path / "protocol.h"
    path.write_text('auto a=R"(raw)";\nauto b=L"wide";\nchar *c="unterminated\nchar *d="OK";\n')
    result = extract("header", path)
    assert result.returncode == 2
    assert result.stdout.count("# PARTIAL:") == 3
    assert '"OK"' in result.stdout


def test_binary_control_bytes_are_escaped(tmp_path):
    # Mock strings to make its platform-specific byte-selection policy irrelevant.
    binaries = tmp_path / "bin"
    binaries.mkdir()
    program = binaries / "strings"
    program.write_text("#!/bin/sh\nprintf 'A\\tB\\rC\\n'\n")
    program.chmod(0o755)
    source = tmp_path / "binary"
    source.touch()
    env = {**os.environ, "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}"}
    result = extract("binary", source, env)
    assert result.returncode == 0, result.stderr
    assert result.stdout == '"A\\x09B\\x0DC"\n'


def test_extraction_backend_limits_do_not_truncate(tmp_path):
    source = tmp_path / "protocol.h"
    source.write_text('"' + "z" * 65 + '"\n')
    assert extract("header", source).returncode != 0
    afl = extract("header", source, backend="afl++")
    assert afl.returncode == 0
    assert afl.stdout == '"' + "z" * 65 + '"\n'
