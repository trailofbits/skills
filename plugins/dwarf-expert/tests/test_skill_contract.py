"""Contract tests for the dwarf-expert skill.

The skill's value is a set of documented llvm-dwarfdump invocations; the failure
mode that matters is documenting flags the real tool does not accept (the defect
class that got seatbelt-sandboxer deleted in #218). These tests extract every
flag the skill documents and check them against a real llvm-dwarfdump.

Per the house rule for checkers, an empty extraction is a failure, not a pass:
if the skill is restructured so that no flags (or no frontmatter) are found,
these tests go red rather than silently checking nothing.

Requires an LLVM dwarfdump on PATH, version 19 or newer: --error-display and
--verify-json landed in LLVM 19 (absent from release/18.x
llvm-dwarfdump.cpp, present in release/19.x). macOS ships a new-enough one as
/usr/bin/dwarfdump with the Xcode Command Line Tools; on Debian/Ubuntu,
`apt install llvm-19` (or any newer llvm). CI installs it in the python-tests
job. The resolver picks the newest LLVM on PATH and fails with the resolved
version when it is below the floor, so toolchain age is distinguishable from
a skill defect.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SKILL_MD = Path(__file__).resolve().parent.parent / "skills" / "dwarf-expert" / "SKILL.md"

# A leading word boundary so hyphenated prose ("exit-code-only") never matches.
# Lowercase-only on both the extraction and --help sides, matching LLVM's flag
# conventions; an uppercase flag would escape checking rather than fail.
FLAG_RE = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*")

EFFORT_LEVELS = {"low", "medium", "high", "xhigh", "max"}


def read_skill() -> str:
    return SKILL_MD.read_text(encoding="utf-8")


def frontmatter(text: str) -> dict[str, str]:
    """Parse the flat key: value frontmatter block without a YAML dependency.

    Single-line values only: a multi-line YAML value (`description: >-`) would
    parse as its marker and fail the contract assertions loudly.
    """
    match = re.match(r"\A---\n(.*?)\n---\n", text, re.DOTALL)
    if match is None:
        pytest.fail(f"{SKILL_MD}: no frontmatter block found")
    fields = {}
    for line in match.group(1).splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return fields


def body_sections(text: str) -> dict[str, str]:
    """Split the post-frontmatter body into {top-level heading: section text}.

    Fenced code blocks are stripped first so a `# comment` line inside an
    example cannot masquerade as a heading and corrupt the section scoping.
    """
    body = re.sub(r"\A---\n.*?\n---\n", "", text, flags=re.DOTALL)
    body = re.sub(r"^```.*?^```\s*?\n", "", body, flags=re.DOTALL | re.MULTILINE)
    sections = {}
    title = ""
    for line in body.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            sections[title] = ""
        else:
            sections[title] = sections.get(title, "") + line + "\n"
    return sections


# --error-display and --verify-json exist since LLVM 19.
MIN_LLVM_MAJOR = 19


def resolve_llvm_dwarfdump() -> tuple[str, str]:
    """Find the newest LLVM dwarfdump on PATH, rejecting libdwarf's tool.

    Newest matters: machines often carry a distro default plus versioned
    packages, and the skill documents flags added in LLVM 19. Returns the
    tool path and its version line for failure messages.
    """
    candidates = ["llvm-dwarfdump", "dwarfdump"]
    candidates += [f"llvm-dwarfdump-{n}" for n in range(14, 31)]
    best = None
    for name in candidates:
        path = shutil.which(name)
        if path is None:
            continue
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, check=False)
        for line in (proc.stdout + proc.stderr).splitlines():
            match = re.search(r"LLVM version (\d+)", line)
            if match:
                major = int(match.group(1))
                if best is None or major > best[0]:
                    best = (major, path, line.strip())
                break
    if best is None:
        pytest.fail(
            "no LLVM dwarfdump found on PATH - install one to run this suite "
            "(macOS: Xcode Command Line Tools; Debian/Ubuntu: apt install llvm-19)"
        )
    major, path, version = best
    if major < MIN_LLVM_MAJOR:
        pytest.fail(
            f"LLVM >= {MIN_LLVM_MAJOR} required (the skill documents "
            f"--error-display/--verify-json, added in LLVM 19); newest found: "
            f"{path} ({version})"
        )
    return path, version


def test_documented_dwarfdump_flags_are_real():
    """Every dwarfdump flag the skill documents must exist in the real tool.

    The readelf section is excluded: its flags belong to binutils readelf,
    which is not a reasonable prerequisite on macOS.
    """
    sections = body_sections(read_skill())
    assert sections, f"{SKILL_MD}: no top-level sections found"
    assert "readelf" in sections, (
        f"{SKILL_MD}: expected a 'readelf' section to scope the extraction; "
        "if it was renamed, update this test so readelf flags are not checked "
        "against llvm-dwarfdump"
    )
    dwarfdump_text = "\n".join(text for title, text in sections.items() if title != "readelf")
    documented = sorted(set(FLAG_RE.findall(dwarfdump_text)))
    assert len(documented) >= 10, (
        f"only {len(documented)} flags extracted from {SKILL_MD} - the skill "
        f"or this extractor is broken: {documented}"
    )

    tool, tool_version = resolve_llvm_dwarfdump()
    proc = subprocess.run([tool, "--help"], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"{tool} --help failed: {proc.stderr}"
    real = set(FLAG_RE.findall(proc.stdout + proc.stderr))

    bogus = [flag for flag in documented if flag not in real]
    assert not bogus, (
        f"flags documented in {SKILL_MD} but not accepted by {tool} "
        f"({tool_version}): {bogus} - if a flag is real but newer than this "
        "LLVM, upgrade the toolchain rather than editing the skill"
    )


def test_frontmatter_contract():
    fields = frontmatter(read_skill())

    assert fields.get("name") == "dwarf-expert"
    assert len(fields.get("description", "")) >= 50, (
        "description is the skill's trigger - it must exist and be substantive"
    )
    assert fields.get("effort") in EFFORT_LEVELS, (
        f"effort must be one of {sorted(EFFORT_LEVELS)}, got: {fields.get('effort')!r}"
    )

    tools = fields.get("allowed-tools", "")
    assert tools, "allowed-tools missing - the skill declares its tool needs"
    assert "," not in tools and "[" not in tools, (
        f"allowed-tools must be space-delimited per the repo spec, got: {tools!r}"
    )
    # Bare tool names only - deliberate for this skill; loosen if it ever
    # needs scoped specifiers like Bash(git:*) or MCP tool names.
    assert all(re.fullmatch(r"[A-Za-z]+", t) for t in tools.split()), (
        f"allowed-tools contains a malformed tool name: {tools!r}"
    )
