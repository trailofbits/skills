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


# Everything build_log.sh defines. Used in a block that never sourced the file, a helper is
# 127 and LOG_FILE is an append to "".
LOG_HELPERS = ("run_logged", "log_step", "log_cmd", "log_result", "LOG_FILE")
USES_LOG_HELPER = re.compile(r"\b(" + "|".join(LOG_HELPERS) + r")\b")


def _unsourced_helper_uses(source: str) -> list[str]:
    """Lines that use a build_log.sh helper in a block that never sources build_log.sh."""
    if any(SOURCES_LOG_HELPERS.match(raw) for raw in source.splitlines()):
        return []
    lines = (raw.strip() for raw in source.splitlines())
    return [line for line in lines if not line.startswith("#") and USES_LOG_HELPER.search(line)]


def test_helper_uses_are_sourced_in_the_same_block() -> None:
    """A helper is a function, and a function does not survive into the next Bash call.

    Same rule as the array check below, higher cost: 127 is a non-zero status, so the ladder
    in build-database.md records the method as failed and walks to the next one. Method 2m-a
    was the case that motivated this: the first rung an affected Mac lands on called
    `log_step` without sourcing the helpers.
    """
    offenders = [
        f"{_ident(path, line)}: {offender}"
        for path, line, source in ALL_BLOCKS
        for offender in _unsourced_helper_uses(source)
    ]
    assert not offenders, (
        "a block uses a build_log.sh helper without sourcing it. Each block is a separate "
        "Bash call, so the helper is undefined there and the line exits 127. Add `. "
        '"{baseDir}/scripts/build_log.sh" || exit 1` to the block:\n  ' + "\n  ".join(offenders)
    )


HELPERS_MUST_FLAG = (
    'log_step "METHOD 2m-a: macOS arm64 Homebrew compiler"',
    'run_logged codeql database create "$DB_NAME" --language=cpp',
    # Not a function, but build_log.sh is what defaults it. Unsourced, this appends to "".
    'echo "=== Build Complete ===" >> "$LOG_FILE"',
)

HELPERS_MUST_PASS = (
    '. "{baseDir}/scripts/build_log.sh" || exit 1\nlog_step "building"',
    "source {baseDir}/scripts/build_log.sh\nrun_logged make",
    # A comment about the helpers, not a call. Blocks carry those.
    "# run_logged returns the build's exit status. Check it before moving on.",
)


def test_detector_flags_unsourced_helpers() -> None:
    """Guard the guard: no block violates the rule now, so nothing else would notice this
    detector going quiet."""
    for source in HELPERS_MUST_FLAG:
        assert _unsourced_helper_uses(source) == [source], (
            f"the detector stopped flagging:\n  {source}"
        )


def test_detector_passes_sourced_helpers() -> None:
    """False positives get silenced, and a silenced check catches nothing."""
    for source in HELPERS_MUST_PASS:
        assert _unsourced_helper_uses(source) == [], (
            f"the detector now fires on a block that sources the helpers, which is how it "
            f"gets disabled:\n  {source}"
        )


def test_the_sourcing_rule_has_something_to_check() -> None:
    """Guard the guard: if the token list or the block extractor broke, every block would
    look helper-free and the check above would inspect nothing."""
    users = [
        _ident(path, line)
        for path, line, source in ALL_BLOCKS
        if any(USES_LOG_HELPER.search(raw) for raw in source.splitlines())
    ]
    assert len(users) >= 10, (
        f"only {len(users)} blocks use a build_log.sh helper across {len(ALL_BLOCKS)} blocks "
        f"in {SKILL_ROOT} — the detector is broken, not the skill"
    )


# `codeql database finalize` after a failed `trace-command` writes a database that resolves
# and holds nothing, so the build method reports success. Something has to gate it: a test on
# the same line, or an enclosing `if` the step already set, which shows as indentation.
FINALIZE = "codeql database finalize"
GATED_ON_THE_LINE = re.compile(r"^(if|elif)\s+!|&&")


def _ungated_finalizes(source: str) -> list[str]:
    """`codeql database finalize` calls that run whatever the step before them returned."""
    found: list[str] = []
    for raw in source.splitlines():
        stripped = raw.strip()
        if FINALIZE not in stripped or stripped.startswith("#"):
            continue
        # Indented means it sits inside an enclosing block; 2m-a's is under `if $TRACE_OK`.
        if raw != stripped or GATED_ON_THE_LINE.search(stripped):
            continue
        found.append(stripped)
    return found


def test_finalize_is_gated_on_the_step_before_it() -> None:
    """A build method that finalizes a database it failed to populate reports success.

    `build_log.sh` deliberately omits `set -e` so the ladder survives a failed method, which
    leaves each block responsible for its own sequencing. Method 3 in build-database.md ran
    four `run_logged` calls in a row, so a `trace-command` that failed on build step 2 still
    reached `finalize`, and `codeql resolve database` then succeeded.
    """
    offenders = [
        f"{_ident(path, line)}: {offender}"
        for path, line, source in ALL_BLOCKS
        for offender in _ungated_finalizes(source)
    ]
    assert not offenders, (
        "a block finalizes a database without checking that the step before it succeeded, so "
        "a failed trace-command still produces a database that resolves and holds nothing:\n  "
        + "\n  ".join(offenders)
    )


FINALIZE_MUST_FLAG = (
    'run_logged codeql database finalize "$DB_NAME"',
    'codeql database finalize "$DB_NAME"',
)

FINALIZE_MUST_PASS = (
    'elif ! run_logged codeql database finalize "$DB_NAME"; then',
    'if ! run_logged codeql database finalize "$DB_NAME"; then',
    # 2m-a's shape: the trace loop sets TRACE_OK, and the finalize sits inside that test.
    'if $TRACE_OK; then\n  run_logged codeql database finalize "$DB_NAME"\nfi',
)


def test_detector_flags_ungated_finalize() -> None:
    """Guard the guard: two call sites, both gated now, so nothing else would notice this
    detector going quiet."""
    for source in FINALIZE_MUST_FLAG:
        assert _ungated_finalizes(source) == [source], f"the detector stopped flagging:\n  {source}"


def test_detector_passes_gated_finalize() -> None:
    """False positives get silenced, and a silenced check catches nothing."""
    for source in FINALIZE_MUST_PASS:
        assert _ungated_finalizes(source) == [], (
            f"the detector now fires on a gated finalize, which is how it gets disabled:\n"
            f"  {source}"
        )


def test_the_finalize_rule_has_something_to_check() -> None:
    """Guard the guard: no `finalize` anywhere means the check above inspects nothing."""
    sites = [_ident(path, line) for path, line, source in ALL_BLOCKS if FINALIZE in source]
    assert len(sites) >= 2, (
        f"only {len(sites)} `{FINALIZE}` call sites found across {len(ALL_BLOCKS)} blocks in "
        f"{SKILL_ROOT} — the detector is broken, not the skill"
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
    is written. Names are collected across every block and checked against every block, so
    a bad expansion is caught wherever it sits relative to the assignment.
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


# A subscripted read: "${NAME[@]}", ${#NAME[@]}, ${NAME[0]}. Bare $NAME is the other bug,
# caught by the test above.
def _subscripted_reads(source: str, name: str) -> bool:
    return bool(re.search(rf"\$\{{#?{name}\[", source))


def _assigns(source: str, name: str) -> bool:
    return any((m := ARRAY_ASSIGN.match(raw)) and m.group(1) == name for raw in source.splitlines())


def test_arrays_are_consumed_in_the_block_that_builds_them() -> None:
    """An array does not survive into the next Bash call, so neither half works alone.

    Each fenced block is its own Bash invocation. SKILL.md built FOUND_DBS in the Database
    Discovery block and looped over it in the next one to print each database's language
    and creation time: the loop iterated zero times and printed nothing, and the selection
    prompt it feeds had no metadata to offer — one paragraph after the text stating the
    rule. Nothing caught it, because both halves are correct read on their own.

    Scoped to arrays because that is the case where the failure is silent: an unset array
    expands to nothing and the loop simply does not run. An unset scalar usually surfaces
    as a command that fails.
    """
    offenders = []
    for path, line, source in ALL_BLOCKS:
        for name in ARRAY_NAMES:
            if _subscripted_reads(source, name) and not _assigns(source, name):
                offenders.append(f"{_ident(path, line)}: reads ${{{name}[@]}}, never builds it")

    assert not offenders, (
        "a block reads an array it does not build. Each block is a separate Bash call, so "
        "the array is empty there and the loop over it silently does nothing — build it in "
        "the same block that reads it:\n  " + "\n  ".join(offenders)
    )


def test_the_same_block_rule_has_something_to_check() -> None:
    """Guard the guard: with no subscripted read anywhere, the check above inspects nothing.

    Also pins the detector itself, since no block in the skill violates the rule today and
    a detector that stopped matching would look identical to a clean skill.
    """
    reads = [
        (path, line, name)
        for path, line, source in ALL_BLOCKS
        for name in ARRAY_NAMES
        if _subscripted_reads(source, name)
    ]
    assert len(reads) >= 2, (
        f"only {len(reads)} subscripted array reads found across {len(ALL_BLOCKS)} blocks — "
        f"the detector is broken, not the skill"
    )
    split = 'FOUND_DBS=()\nFOUND_DBS+=("$db")\n'
    assert _subscripted_reads('for db in "${FOUND_DBS[@]}"; do :; done', "FOUND_DBS")
    assert not _assigns('for db in "${FOUND_DBS[@]}"; do :; done', "FOUND_DBS")
    assert _assigns(split, "FOUND_DBS"), "an append must not be mistaken for the declaration"


# find_databases.sh exits 2 when codeql is missing from the calling shell's PATH, precisely
# so that state cannot be mistaken for "this project has no databases". `done < <(script)`
# throws the status away: the loop's status is the loop's, and the substitution's is
# unobservable. Command substitution keeps it, so the caller can tell the two apart.
DISCOVERY_SCRIPT = "find_databases.sh"
PROCESS_SUBSTITUTION = re.compile(r"<\s*<\(")


def _discovery_without_status(source: str) -> list[str]:
    """Lines that run the discovery script through a process substitution."""
    offenders = []
    for raw in source.splitlines():
        stripped = raw.strip()
        if stripped.startswith("#") or DISCOVERY_SCRIPT not in stripped:
            continue
        if PROCESS_SUBSTITUTION.search(stripped):
            offenders.append(stripped)
    return offenders


def test_discovery_exit_status_is_observed() -> None:
    """All three callers read discovery through a process substitution and dropped its status.

    Failure scenario: codeql is not on this Bash call's PATH — a fresh shell each block, so
    the preflight that checked it ran in a different one. The script prints its ERROR to
    stderr and exits 2, the array comes back empty, and the caller reports "No CodeQL
    database found" while three good databases sit on disk. The user is then walked through
    a full rebuild that fails for the same reason at the same place.
    """
    offenders = [
        f"{_ident(path, line)}: {offender}"
        for path, line, source in ALL_BLOCKS
        for offender in _discovery_without_status(source)
    ]
    assert not offenders, (
        "a block reads find_databases.sh through a process substitution, whose exit status "
        "is unobservable, so exit 2 (no codeql on PATH) reads as an empty result. Use "
        '`if ! DB_LIST=$("{baseDir}/scripts/find_databases.sh" …); then … fi` and loop over '
        '`<<<"$DB_LIST"`:\n  ' + "\n  ".join(offenders)
    )


DISCOVERY_MUST_FLAG = (
    'done < <("{baseDir}/scripts/find_databases.sh" "${OUTPUT_DIR:-.}" .)',
    "done < <(find_databases.sh)",
    # Spacing between the redirect and the substitution is the caller's habit, not a signal.
    'done <  <("{baseDir}/scripts/find_databases.sh" .)',
)

DISCOVERY_MUST_PASS = (
    'if ! DB_LIST=$("{baseDir}/scripts/find_databases.sh" "${OUTPUT_DIR:-.}" .); then',
    'done <<<"$DB_LIST"',
    # Prose about the script, which the blocks carry above every call site.
    "# Command substitution, not `done < <(...)`: find_databases.sh exits 2 when codeql is "
    "missing.",
)


def test_detector_flags_discovery_process_substitution() -> None:
    """Guard the guard: no block violates the rule now, so nothing else would notice this
    detector going quiet."""
    for source in DISCOVERY_MUST_FLAG:
        assert _discovery_without_status(source) == [source], (
            f"the detector stopped flagging:\n  {source}"
        )


def test_detector_passes_status_checked_discovery() -> None:
    """False positives get silenced, and a silenced check catches nothing."""
    for source in DISCOVERY_MUST_PASS:
        assert _discovery_without_status(source) == [], (
            f"the detector now fires on a caller that does check the status, which is how it "
            f"gets disabled:\n  {source}"
        )


def test_the_discovery_rule_has_something_to_check() -> None:
    """Guard the guard: if the block extractor or the script name broke, every block would
    look discovery-free and the check above would inspect nothing."""
    callers = [
        _ident(path, line)
        for path, line, source in ALL_BLOCKS
        if any(
            DISCOVERY_SCRIPT in raw and not raw.strip().startswith("#")
            for raw in source.splitlines()
        )
    ]
    assert len(callers) >= 3, (
        f"only {len(callers)} blocks call {DISCOVERY_SCRIPT} across {len(ALL_BLOCKS)} blocks "
        f"in {SKILL_ROOT} — SKILL.md, run-analysis.md and create-data-extensions.md each do, "
        f"so the detector is broken, not the skill"
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
