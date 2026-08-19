"""Keep the build-mode claims in the docs consistent with each other.

The docs classified Go as interpreted and no-build. Go is compiled and rejects
`--build-mode=none` outright:

    A fatal error occurred: Go does not support the none build mode.
    Please try using one of the following build modes instead: autobuild, manual.

They also listed C# and Java as requiring tracing without mentioning that both accept
`none`. Verified against CodeQL 2.25.6.

These checks are hermetic: they read the markdown, not the CLI, so they run without a
CodeQL install. Re-verify the table by hand when bumping CodeQL, since supported modes
change between releases.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).resolve().parent.parent
BUILD_DB = SKILL_ROOT / "workflows" / "build-database.md"
LANG_DETAILS = SKILL_ROOT / "references" / "language-details.md"

# Verified with `codeql database create --build-mode=none --language=<lang>` on 2.25.6.
# Note the CLI's own --help omits C/C++ from its `none` list, but cpp does support it.
NO_NONE_MODE = ("Go", "Swift")


def test_go_is_not_listed_as_needing_no_build() -> None:
    """The original bug: Go grouped with Python and Ruby."""
    text = BUILD_DB.read_text(encoding="utf-8")
    section = re.search(r"### No build needed \(([^)]*)\)", text)
    assert section, "build-database.md no longer has a 'No build needed' section"
    assert "Go" not in section.group(1), (
        f"Go is listed as needing no build: '{section.group(1)}'. Go rejects "
        f"--build-mode=none and requires autobuild or a manual command."
    )


@pytest.mark.parametrize("language", NO_NONE_MODE)
def test_languages_without_a_none_mode_are_flagged(language: str) -> None:
    """A reader must not be sent to Method 4 for a language that rejects it."""
    text = BUILD_DB.read_text(encoding="utf-8")
    assert re.search(rf"{language}.*[Rr]eject", text), (
        f"{language} rejects --build-mode=none, but build-database.md does not say so. "
        f"Method 4 would be attempted and fail."
    )


def test_method_4_names_the_languages_it_does_not_apply_to() -> None:
    text = BUILD_DB.read_text(encoding="utf-8")
    method4 = text[text.index("#### Method 4") :]
    for language in NO_NONE_MODE:
        assert language in method4[:800], (
            f"Method 4 does not mention that {language} rejects --build-mode=none"
        )


def test_language_table_covers_both_axes() -> None:
    """The table must state build need and none-support, not 'Interpreted/Compiled'.

    That framing is what produced the error: Go is compiled but was called interpreted,
    and 'compiled' was treated as implying no `none` mode.
    """
    text = BUILD_DB.read_text(encoding="utf-8")
    assert "| Language | `--language=` | Build needed | `--build-mode=none` |" in text, (
        "the language table lost its build-mode columns"
    )
    assert "| Type |" not in text, "the Interpreted/Compiled column is back"


def test_go_sits_under_build_required_in_language_details() -> None:
    text = LANG_DETAILS.read_text(encoding="utf-8")
    build_required = text.index("## Build Required")
    go = text.index("### Go")
    assert go > build_required, "language-details.md lists Go under 'No Build Required'"


def test_claims_name_the_verified_codeql_version() -> None:
    """A version-specific claim with no version is unfalsifiable later."""
    assert "2.25.6" in BUILD_DB.read_text(encoding="utf-8"), (
        "build-database.md no longer says which CodeQL version the table was verified "
        "against, so a reader cannot tell whether it has gone stale"
    )
