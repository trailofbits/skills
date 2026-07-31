"""Contract tests for the dwarf-expert skill.

The skill's value is a set of documented llvm-dwarfdump invocations; the failure
mode that matters is documenting flags the real tool does not accept (the defect
class that got seatbelt-sandboxer deleted in #218). These tests extract every
flag the skill documents and check them against a real llvm-dwarfdump.

Per the house rule for checkers, an empty extraction is a failure, not a pass:
if the skill is restructured so that no flags (or no frontmatter) are found,
these tests go red rather than silently checking nothing.

Requires an LLVM dwarfdump on PATH new enough to accept the documented flags:
--error-display and --verify-json landed in LLVM 19 (absent from release/18.x
llvm-dwarfdump.cpp, present in release/19.x). Apple's LLVM numbering does not
track upstream releases, so the resolver gates on capability (those flags
appearing in --help) rather than a parsed version number. macOS: current
Xcode Command Line Tools qualify; Debian/Ubuntu: `apt install llvm-19` or
newer. CI installs it in the python-tests job. A missing or too-old toolchain
fails with the rejected tools and their versions, so toolchain age is
distinguishable from a skill defect.
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

    Fence-aware: a `# comment` line inside a fenced code block is not a
    heading, but fenced content stays in the section text so flags documented
    only in examples are still extracted and verified.
    """
    body = re.sub(r"\A---\n.*?\n---\n", "", text, flags=re.DOTALL)
    sections = {}
    title = ""
    in_fence = False
    for line in body.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
        if not in_fence and line.startswith("# "):
            title = line[2:].strip()
            sections[title] = ""
        else:
            sections[title] = sections.get(title, "") + line + "\n"
    return sections


# The newest flags the skill documents; both landed in LLVM 19. The resolver
# gates on these appearing in --help because Apple's LLVM version numbering
# does not track upstream, so a parsed major is not comparable across
# toolchains.
GATE_FLAGS = ("--error-display", "--verify-json")


def resolve_llvm_dwarfdump() -> tuple[str, str]:
    """Find an LLVM dwarfdump that supports the newest documented flags.

    Rejects libdwarf's same-named tool via the LLVM version banner, then
    requires the version-gated flags in --help. Returns the tool path and
    its version line for failure messages.
    """
    candidates = ["llvm-dwarfdump", "dwarfdump"]
    candidates += [f"llvm-dwarfdump-{n}" for n in range(30, 13, -1)]
    too_old = []
    for name in candidates:
        path = shutil.which(name)
        if path is None:
            continue
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, check=False)
        version = next(
            (line.strip() for line in (proc.stdout + proc.stderr).splitlines() if "LLVM" in line),
            None,
        )
        if version is None:
            continue
        help_proc = subprocess.run([path, "--help"], capture_output=True, text=True, check=False)
        if all(flag in help_proc.stdout + help_proc.stderr for flag in GATE_FLAGS):
            return path, version
        too_old.append(f"{path} ({version})")
    detail = f"; too old: {', '.join(too_old)}" if too_old else ""
    pytest.fail(
        f"no LLVM dwarfdump supporting {'/'.join(GATE_FLAGS)} (LLVM 19+) found "
        f"on PATH{detail} - macOS: current Xcode Command Line Tools; "
        "Debian/Ubuntu: apt install llvm-19 or newer"
    )


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
    assert len(documented) >= 15, (
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


def test_body_sections_are_fence_aware():
    """Fenced `#` lines are not headings; fenced flags are still extracted."""
    doc = (
        "---\nname: x\n---\n"
        "# real heading\n"
        "prose\n"
        "```bash\n"
        "# a comment, not a heading\n"
        "llvm-dwarfdump --fenced-flag file\n"
        "```\n"
        "# second heading\n"
        "tail\n"
    )
    sections = body_sections(doc)
    assert set(sections) == {"real heading", "second heading"}
    assert "--fenced-flag" in FLAG_RE.findall(sections["real heading"])


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
