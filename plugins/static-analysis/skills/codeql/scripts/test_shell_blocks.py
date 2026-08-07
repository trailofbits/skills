"""Lint the shell that lives inside this skill's markdown.

`make shell` covers `*.sh` files; this skill ships none, so nothing checked its
commands. That gap hid one bug class in nine places: a pipeline's exit status used as
a success test, which without `pipefail` belongs to the formatter, not the command.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).resolve().parent.parent
BASH_BLOCK = re.compile(r"^```bash\n(.*?)^```", re.MULTILINE | re.DOTALL)

# Defined in build_log.sh alongside `set -o pipefail`, so it preserves exit status by
# construction; callers need not repeat the setting.
SAFE_PIPE_WRAPPER = "run_logged"

# A single `|`. `if [ -f a ] || [ -f b ]` is a logical or, not a pipeline, and matching it
# made two blocks look like offenders that the whole-block exemption then waved through.
PIPE = r"(?<!\|)\|(?!\|)"
PIPED_TO_TEE = re.compile(PIPE + r"\s*tee\b")
PIPELINE_IN_CONDITION = re.compile(r"if\s+!?\s*[^|]*" + PIPE)
# The line itself runs under the wrapper, wherever it sits in the block.
WRAPPED = re.compile(r"^(if\s+!?\s*)?" + SAFE_PIPE_WRAPPER + r"\b")
# Sourcing the helpers sets pipefail for the rest of the block, exactly as writing it out
# would. Matching the bare token `run_logged` anywhere in the block did not mean that.
SOURCES_LOG_HELPERS = re.compile(r"^\s*(\.|source)\s+.*build_log\.sh")


def _status_consuming_pipelines(source: str) -> list[str]:
    """Lines whose pipeline *exit status* is consumed.

    `VAR=$(cmd | wc -l)` consumes output and is fine. `cmd | tee "$LOG"` as a statement,
    or a pipeline inside an `if`, decides what happens next.
    """
    found: list[str] = []
    for raw in source.splitlines():
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue
        # Output capture — status is not what is being used.
        if re.search(r"(\$\(|`|=\s*\$\()", stripped) and not stripped.startswith("if "):
            continue
        if PIPED_TO_TEE.search(stripped) or PIPELINE_IN_CONDITION.match(stripped):
            found.append(stripped)
    return found


def _sets_pipefail(source: str) -> bool:
    """pipefail is block-scoped, so set it directly or inherit it by sourcing the helpers."""
    return (
        "set -o pipefail" in source
        or "set -euo pipefail" in source
        or any(SOURCES_LOG_HELPERS.match(raw) for raw in source.splitlines())
    )


def _unpreserved_pipelines(source: str) -> list[str]:
    """Status-consuming pipelines in `source` that read the formatter's status instead.

    The wrapper exemption is applied per line. Applied per block — "does `run_logged`
    appear anywhere in this source" — a bare `cmd | tee "$LOG_FILE"` added later to a
    block that already used the wrapper elsewhere passed silently, which is the exact
    regression this check exists to catch.
    """
    if _sets_pipefail(source):
        return []
    return [line for line in _status_consuming_pipelines(source) if not WRAPPED.match(line)]


def _markdown_files() -> list[Path]:
    return sorted(p for p in SKILL_ROOT.rglob("*.md") if ".pytest_cache" not in p.parts)


def _blocks() -> list[tuple[Path, int, str]]:
    """Every bash block in the skill, as (file, line number, source)."""
    found: list[tuple[Path, int, str]] = []
    for path in _markdown_files():
        text = path.read_text(encoding="utf-8")
        for match in BASH_BLOCK.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            found.append((path, line, match.group(1)))
    return found


ALL_BLOCKS = _blocks()


def _ident(path: Path, line: int) -> str:
    return f"{path.relative_to(SKILL_ROOT)}:{line}"


def test_extraction_found_blocks() -> None:
    """Guard the guard: a broken regex would turn every test below into a no-op."""
    assert len(ALL_BLOCKS) >= 20, (
        f"only {len(ALL_BLOCKS)} bash blocks extracted from {SKILL_ROOT} — the extractor "
        f"is broken, not the skill"
    )


def test_every_block_is_syntactically_valid() -> None:
    """Every block must parse. Catches unterminated heredocs and quoting errors."""
    offenders = []
    for path, line, source in ALL_BLOCKS:
        # <BUILD_CMD>, <mode> etc. are documentation, not shell — neutralise before parsing.
        cleaned = re.sub(r"<[A-Za-z0-9_ .-]+>", "PLACEHOLDER", source)
        result = subprocess.run(["bash", "-n"], input=cleaned, capture_output=True, text=True)
        if result.returncode != 0:
            offenders.append(f"{_ident(path, line)}: {result.stderr.strip()}")

    assert not offenders, "a block is not valid bash:\n  " + "\n  ".join(offenders)


def test_no_block_consumes_an_unpreserved_pipeline_status() -> None:
    """A pipeline whose *exit status* is consumed must preserve the real one.

    Without pipefail that status is the formatter's, which is always 0. No block ships a
    bare pipeline today — every one goes through `run_logged` — so this is a tripwire for
    new markdown, and it scans every block in one test rather than parametrizing over all
    of them to skip the ones with no pipeline. What proves the detector still fires is
    `test_detector_flags_unsafe_pipelines` below.
    """
    offenders = [
        f"{_ident(path, line)}: {offender}"
        for path, line, source in ALL_BLOCKS
        for offender in _unpreserved_pipelines(source)
    ]
    assert not offenders, (
        f"a block decides control flow on a pipeline's exit status without "
        f"`set -o pipefail` or {SAFE_PIPE_WRAPPER}, so it reads the formatter's status "
        f"(always 0) rather than the command's:\n  " + "\n  ".join(offenders)
    )


# The detector matches no block in the skill today, so these fixtures are the only thing
# that would notice it silently breaking. Kept as tables inside two tests rather than
# parametrized: seven pytest cases for one detector was more ceremony than it earns.
_BARE_TEE = 'codeql database analyze "$DB_NAME" suite.qls 2>&1 | tee -a "$LOG_FILE"'

MUST_FLAG = (
    ('codeql database create "$DB_NAME" --language=cpp 2>&1 | tee -a "$LOG_FILE"', None),
    ('if codeql resolve queries "$SUITE_FILE" | grep -q "\\.ql"; then echo ok; fi', None),
    # The regression the per-line exemption exists for: under the old whole-block test
    # `run_logged` appearing anywhere waved through every pipeline in the block.
    (f'run_logged codeql database create "$DB_NAME" --language=cpp\n{_BARE_TEE}\n', [_BARE_TEE]),
)

MUST_PASS = (
    # Output capture: the pipeline's status is never read.
    'COUNT=$(codeql resolve queries "$SUITE_FILE" | wc -l)',
    # Logical or, not a pipeline.
    "if [ -f setup.py ] || [ -f pyproject.toml ]; then echo python; fi",
    # The wrapper sets pipefail itself.
    'run_logged codeql database create "$DB_NAME" --language=cpp',
    # `. build_log.sh` runs `set -o pipefail`, so the rest of the block is genuinely safe.
    f'. "{{baseDir}}/scripts/build_log.sh"\n{_BARE_TEE}\n',
)


def test_detector_flags_unsafe_pipelines() -> None:
    """Guard the guard: with no offending block left in the skill, nothing else would
    notice if this detector stopped matching."""
    for source, expected in MUST_FLAG:
        assert _unpreserved_pipelines(source) == (expected or [source]), (
            f"the detector stopped flagging:\n  {source}"
        )


def test_detector_passes_safe_pipelines() -> None:
    """False positives get silenced, and a silenced check catches nothing."""
    for source in MUST_PASS:
        assert _unpreserved_pipelines(source) == [], (
            f"the detector now fires on safe shell, which is how it gets disabled:\n  {source}"
        )


def test_exit_status_is_not_captured_after_a_pipe() -> None:
    """`EXIT_CODE=$?` after a pipeline captures the wrong process.

    This is how the arm64e exit-137 check was neutered.
    """
    offenders = []
    for path, line, source in ALL_BLOCKS:
        if "set -o pipefail" in source or "set -euo pipefail" in source:
            continue
        lines = source.splitlines()
        for index, raw in enumerate(lines[:-1]):
            if raw.strip().startswith("#") or "|" not in raw:
                continue
            if re.search(r"\|\s*(tee|wc|head|tail)\b", raw) and re.match(
                r"\s*\w+=\$\?", lines[index + 1]
            ):
                offenders.append(
                    f"{_ident(path, line)}: {raw.strip()} / {lines[index + 1].strip()}"
                )

    assert not offenders, (
        "a block captures $? straight after a pipe without pipefail, so it records the "
        "formatter's status rather than the command's:\n  " + "\n  ".join(offenders)
    )


def test_no_unquoted_command_string_expansion() -> None:
    """`CMD="a b c"` then `$CMD` word-splits on any path containing a space."""
    offenders = [
        f"{_ident(path, line)}: {raw.strip()}"
        for path, line, source in ALL_BLOCKS
        for raw in source.splitlines()
        if re.match(r"\s*\$(CMD|BUILD_CMD)\b", raw) and not raw.strip().startswith("#")
    ]
    assert not offenders, (
        "a block runs a command built as a string, unquoted. Pass argv as a list (see "
        "run_logged) so paths with spaces survive:\n  " + "\n  ".join(offenders)
    )


# Variables that hold a filesystem path. An unquoted expansion of any of these splits on
# a space, so `$OUTPUT_DIR` under "~/My Scans" silently targets the wrong path.
PATH_VARS = (
    "DB_NAME",
    "OUTPUT_DIR",
    "SUITE_FILE",
    "RAW_DIR",
    "RESULTS_DIR",
    "LOG_FILE",
    "DIAG_DIR",
)
UNQUOTED_PATH_VAR = re.compile(r"\$\{?(" + "|".join(PATH_VARS) + r")\}?(?![\w\"])")


def _outside_heredoc(source: str):
    """Yield (line, is_shell) — heredoc bodies are literal text, not shell."""
    terminator: str | None = None
    for raw in source.splitlines():
        if terminator is not None:
            if raw.strip() == terminator:
                terminator = None
            yield raw, False
            continue
        opener = re.search(r"<<-?\s*'?([A-Za-z_][A-Za-z0-9_]*)'?", raw)
        yield raw, True
        if opener:
            terminator = opener.group(1)


def test_path_variables_are_quoted() -> None:
    """Every path variable must be quoted at the point of use.

    The narrower CMD/BUILD_CMD check above missed the production command:
    `codeql database analyze $DB_NAME` sits in run-analysis Step 4 and breaks on any
    output directory containing a space.
    """
    offenders = []
    for path, line, source in ALL_BLOCKS:
        for raw, is_shell in _outside_heredoc(source):
            stripped = raw.strip()
            if not is_shell or stripped.startswith("#"):
                continue
            for match in UNQUOTED_PATH_VAR.finditer(raw):
                # Inside double quotes is fine; count quotes before the match to tell.
                if raw[: match.start()].count('"') % 2 == 1:
                    continue
                offenders.append(f"{_ident(path, line)}: {stripped}")
                break

    assert not offenders, (
        "a block expands a path variable unquoted, so it word-splits on any path "
        "containing a space:\n  " + "\n  ".join(offenders)
    )


ARRAY_ASSIGN = re.compile(r"^\s*([A-Z_][A-Z0-9_]*)=\(")

# Array names assigned anywhere in the skill's bash blocks.
ARRAY_NAMES = frozenset(
    m.group(1)
    for _, _, blk in ALL_BLOCKS
    for raw in blk.splitlines()
    if (m := ARRAY_ASSIGN.match(raw))
)


def test_array_names_were_found() -> None:
    """Guard the guard: with no names collected, the scan below inspects nothing and
    passes. A skip here would report that as success."""
    assert ARRAY_NAMES, (
        f"no `NAME=()` assignment found in any of the {len(ALL_BLOCKS)} blocks in "
        f"{SKILL_ROOT} — the collector is broken, not the skill"
    )


def test_arrays_are_expanded_with_subscript() -> None:
    """`$ARR` on an array yields only element 0, silently.

    SKILL.md built FOUND_DBS as an array, counted it with ${#FOUND_DBS[@]}, then looped
    with `for db in $FOUND_DBS` — so multi-database discovery always offered exactly one
    database, contradicting three other sections of the same file.

    Keyed on assignment rather than a name list, so a new array is covered on the day it
    is written. Names are collected across every block and checked against every block:
    SKILL.md assigns FOUND_DBS=() in the discovery block and loops over it in a later
    one, so neither half of the pairing can be found by looking at a block alone.
    """
    offenders = []
    for path, line, source in ALL_BLOCKS:
        for raw in source.splitlines():
            stripped = raw.strip()
            if stripped.startswith("#"):
                continue
            for name in ARRAY_NAMES:
                # Bare $NAME or ${NAME}: no [@], [*], or [n] subscript, and not ${#NAME[@]}.
                if re.search(rf"(?<!#)\$\{{?{name}\}}?(?!\[|\w)", raw):
                    offenders.append(f"{_ident(path, line)}: {stripped}")
                    break

    assert not offenders, (
        "an array is expanded without a subscript, which yields only its first element. "
        'Use "${NAME[@]}":\n  ' + "\n  ".join(offenders)
    )


# Bodies of `python3 -c '…'`, either quote style, on one line or many. Requiring a newline
# after the opening quote missed the two one-liners in create-data-extensions.md, and a
# missed block reports `skip` — indistinguishable from a block with no Python in it.
EMBEDDED_PYTHON = re.compile(r"""python3 -c (['"])(.*?)\1""", re.DOTALL)


def _embedded_python(source: str) -> list[str]:
    return [match.group(2) for match in EMBEDDED_PYTHON.finditer(source)]


def _embedded_python_bodies() -> list[tuple[str, str]]:
    """Every `python3 -c` body in the skill, as (where it came from, the source)."""
    return [
        (f"{_ident(path, line)}#{index}", body)
        for path, line, source in ALL_BLOCKS
        for index, body in enumerate(_embedded_python(source))
    ]


ALL_EMBEDDED_PYTHON = _embedded_python_bodies()


def test_embedded_python_extraction_still_matches() -> None:
    """Guard the guard: a regex that matched nothing would leave the compile check below
    running against an empty parameter set, which passes without inspecting anything.

    Two bodies today, both in create-data-extensions.md. Was three until
    quality-assessment.md stopped parsing baseline-info.json inline — check_db_quality.py
    reports baseline_loc, so the block was computing it twice.
    """
    assert len(ALL_EMBEDDED_PYTHON) >= 2, (
        f"only {len(ALL_EMBEDDED_PYTHON)} embedded python bodies extracted from "
        f"{SKILL_ROOT} — the extractor is broken, not the skill"
    )


@pytest.mark.parametrize(
    "snippet",
    (
        # create-data-extensions.md counts SARIF results this way.
        "BASELINE=$(python3 -c \"import json; print(len(json.load(open('x.sarif'))))\")",
        # The argv form, which the extractor must handle even though no doc uses it today.
        "LOC=$(python3 -c '\nimport json, sys\nprint(json.load(open(sys.argv[1])))\n' \"$DB\")",
    ),
)
def test_both_quote_styles_are_extracted(snippet: str) -> None:
    """Either form is real shell in this skill, and both must reach the compiler below."""
    assert _embedded_python(snippet)


@pytest.mark.parametrize(
    ("origin", "body"),
    ALL_EMBEDDED_PYTHON,
    ids=[origin for origin, _ in ALL_EMBEDDED_PYTHON],
)
def test_embedded_python_compiles(origin: str, body: str) -> None:
    """Python inside a bash block must parse.

    Quoting the shell string correctly and quoting the Python correctly are separate
    problems, and fixing one can break the other: moving a script from a double- to a
    single-quoted shell string leaves `\\"` escapes behind that are then literal
    backslashes to Python.
    """
    try:
        compile(body, "<embedded>", "exec")
    except SyntaxError as error:
        pytest.fail(f"{origin} embeds Python that does not parse: {error}\n{body}")
