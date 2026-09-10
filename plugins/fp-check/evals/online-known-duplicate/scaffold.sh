#!/usr/bin/env bash
# Writes the case's target into the eval's empty working directory.
# The eval runs each case in a fresh scaffold dir, so a repo-relative path in the
# prompt resolves to nothing; the fixture has to be materialised here.
#
# Kept byte-identical to fixtures/case9_dotenv/ by
# tests/test_eval_suite.py::test_scaffold_fixture_matches_the_checked_in_copy.
#
# Committed for the same reason the other scaffolds are: the already-fixed search
# runs `git log` against this tree, and an uninitialised directory makes that
# agent report a tooling failure instead of "nothing in this history".
set -euo pipefail

mkdir -p dotenv

cat >dotenv/main.py <<'CONCEPT_PROVER_FIXTURE_EOF'
"""Read and write .env files.

Excerpted from python-dotenv 1.2.1 (https://github.com/theskumar/python-dotenv),
Copyright (c) 2014 Saurabh Kumar, BSD-3-Clause. Trimmed to the file-rewriting
path: the parser, the `dotenv_values` readers and the CLI are omitted, and
`parse_stream` is stubbed to keep this excerpt self-contained.
"""

import os
import pathlib
import shutil
import tempfile
from contextlib import contextmanager
from typing import IO, Iterator, NamedTuple, Optional, Tuple, Union

StrPath = Union[str, "os.PathLike[str]"]


class Original(NamedTuple):
    string: str
    line: int


class Binding(NamedTuple):
    key: Optional[str]
    value: Optional[str]
    original: Original
    error: bool


def parse_stream(stream: IO[str]) -> Iterator[Binding]:
    """Yield one Binding per line of `stream`, preserving the original text."""
    for lineno, line in enumerate(stream, start=1):
        original = Original(string=line, line=lineno)
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            yield Binding(key=None, value=None, original=original, error=False)
            continue
        key, _, value = stripped.partition("=")
        yield Binding(key=key.strip(), value=value.strip(), original=original, error=False)


def with_warn_for_invalid_lines(mappings: Iterator[Binding]) -> Iterator[Binding]:
    for mapping in mappings:
        yield mapping


@contextmanager
def rewrite(
    path: StrPath,
    encoding: Optional[str],
) -> Iterator[Tuple[IO[str], IO[str]]]:
    pathlib.Path(path).touch()

    with tempfile.NamedTemporaryFile(mode="w", encoding=encoding, delete=False) as dest:
        error = None
        try:
            with open(path, encoding=encoding) as source:
                yield (source, dest)
        except BaseException as err:
            error = err

    if error is None:
        shutil.move(dest.name, path)
    else:
        os.unlink(dest.name)
        raise error from None


def set_key(
    dotenv_path: StrPath,
    key_to_set: str,
    value_to_set: str,
    quote_mode: str = "always",
    export: bool = False,
    encoding: Optional[str] = "utf-8",
) -> Tuple[Optional[bool], str, str]:
    """
    Adds or Updates a key/value to the given .env

    If the .env path given doesn't exist, fails instead of risking creating
    an orphan .env somewhere in the filesystem
    """
    if quote_mode not in ("always", "auto", "never"):
        raise ValueError(f"Unknown quote_mode: {quote_mode}")

    quote = quote_mode == "always" or (
        quote_mode == "auto" and not value_to_set.isalnum()
    )

    if quote:
        value_out = "'{}'".format(value_to_set.replace("'", "\\'"))
    else:
        value_out = value_to_set
    if export:
        line_out = f"export {key_to_set}={value_out}\n"
    else:
        line_out = f"{key_to_set}={value_out}\n"

    with rewrite(dotenv_path, encoding=encoding) as (source, dest):
        replaced = False
        missing_newline = False
        for mapping in with_warn_for_invalid_lines(parse_stream(source)):
            if mapping.key == key_to_set:
                dest.write(line_out)
                replaced = True
            else:
                dest.write(mapping.original.string)
                missing_newline = not mapping.original.string.endswith("\n")
        if not replaced:
            if missing_newline:
                dest.write("\n")
            dest.write(line_out)

    return True, key_to_set, value_to_set


def unset_key(
    dotenv_path: StrPath,
    key_to_unset: str,
    quote_mode: str = "always",
    encoding: Optional[str] = "utf-8",
) -> Tuple[Optional[bool], str]:
    """
    Removes a given key from the given `.env` file.

    If the .env path given doesn't exist, fails.
    If the given key doesn't exist in the .env, fails.
    """
    if not os.path.exists(dotenv_path):
        return None, key_to_unset

    removed = False
    with rewrite(dotenv_path, encoding=encoding) as (source, dest):
        for mapping in with_warn_for_invalid_lines(parse_stream(source)):
            if mapping.key == key_to_unset:
                removed = True
            else:
                dest.write(mapping.original.string)

    return removed, key_to_unset
CONCEPT_PROVER_FIXTURE_EOF

git -c init.defaultBranch=main init -q
git add -A
GIT_AUTHOR_DATE='2026-03-02T11:20:00+00:00' \
  GIT_COMMITTER_DATE='2026-03-02T11:20:00+00:00' \
  git -c user.name='Vendored Dependency' -c user.email='deps@example.invalid' \
  -c commit.gpgsign=false \
  commit -q -m 'chore(deps): vendor python-dotenv 1.2.1 for review'
