"""Cross-file checks: the skill must describe the workflow it actually invokes.

The other suites test the script; nothing else tests SKILL.md, and every way it breaks is
silent. The run still succeeds while the skill fails to trigger, points at a command that
does not exist, or omits an argument nobody can then supply.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = TESTS_DIR.parent
SKILL_DIR = PLUGIN_ROOT / "skills" / PLUGIN_ROOT.name
SKILL = SKILL_DIR / "SKILL.md"
README = PLUGIN_ROOT / "README.md"
WORKFLOW = PLUGIN_ROOT / "workflows" / "port-rule-to-languages.js"

SKILL_TEXT = SKILL.read_text(encoding="utf-8")
README_TEXT = README.read_text(encoding="utf-8")
SCRIPT = WORKFLOW.read_text(encoding="utf-8")

META_NAME_RE = re.compile(r"^\s*name:\s*'([^']+)'", re.MULTILINE)
FRONTMATTER_DESCRIPTION_RE = re.compile(r"^description:\s*(.+)$", re.MULTILINE)
SLASH_COMMAND_RE = re.compile(r"/([a-z0-9-]+):([a-z0-9-]+)")
# Both `args.x` and the optional-chained `args?.x` the script uses for caller-supplied keys.
ARGS_KEY_RE = re.compile(r"\bargs\??\.(\w+)")
BASEDIR_PATH_RE = re.compile(r"\{baseDir\}/([A-Za-z0-9_./-]+)")
# The value SKILL.md's argument block tells the caller to hand `referencesDir`.
HANDOVER_RE = re.compile(r'"referencesDir"\s*:\s*"([^"]*)"')
# A command that prints the directory itself. `ls <dir>` prints the names of the files inside
# it, so a caller told to pass "the value as printed" has no path to copy and assembles one by
# hand — which clears both script guards and still names a directory that is not there.
PATH_PRINTING_RE = re.compile(r"ls\s+-[a-zA-Z]*d[a-zA-Z]*\s[^\n]*CLAUDE_PLUGIN_ROOT")
# Reference files the script's prompts tell an agent to read.
SCRIPT_REFERENCE_RE = re.compile(r"reference\('([A-Za-z0-9_.-]+\.md)'")

# Words a user would actually type when they want this skill. The description is the single
# highest-leverage line in the file: a skill that never triggers may as well not exist.
DESCRIPTION_TRIGGERS = ("semgrep", "language")
DESCRIPTION_TRIGGER_ALTERNATIVES = ("port", "variant")


def meta_name(script: str) -> str:
    """Return the workflow's meta.name, which decides its slash command."""
    found = META_NAME_RE.findall(script)
    return found[0] if found else ""


def skill_description(skill: str) -> str:
    """Return the description from the skill's frontmatter."""
    found = FRONTMATTER_DESCRIPTION_RE.findall(skill)
    return found[0].strip() if found else ""


def check_documented_command_matches_the_script(skill: str, readme: str, script: str) -> list[str]:
    """Check every documented slash command is one the plugin actually defines."""
    name = meta_name(script)
    if not name:
        return ["no meta.name in the script; the slash command cannot be checked"]

    expected = f"/{PLUGIN_ROOT.name}:{name}"
    documented = {
        f"/{plugin}:{command}"
        for text in (skill, readme)
        for plugin, command in SLASH_COMMAND_RE.findall(text)
    }
    if not documented:
        return [f"neither SKILL.md nor README.md documents a slash command; expected {expected}"]
    return [
        f"{found} is documented but the plugin defines {expected}"
        for found in documented
        if found != expected
    ]


def check_every_arg_the_script_reads_is_documented(
    skill: str, readme: str, script: str
) -> list[str]:
    """Check the skill names every argument the workflow requires.

    Invoking the workflow means assembling an `args` object from what the skill documents — the
    runtime hands it to the script as structured data rather than as text the script parses. So
    an argument the skill never names is one nobody knows to put there, and the script's own
    pre-flight guards are all that stands between that and a run made without it.
    """
    keys = sorted(set(ARGS_KEY_RE.findall(script)))
    if not keys:
        return ["the script reads no args; argument discovery is broken"]
    return [
        f"the script reads args.{key} but SKILL.md never names it"
        for key in keys
        if key not in skill
    ]


def check_the_skill_hands_over_its_references(skill: str, readme: str, script: str) -> list[str]:
    """Check the skill hands the workflow a path it can actually read.

    A workflow script cannot expand `{baseDir}` or `${CLAUDE_PLUGIN_ROOT}`, and has no
    filesystem access to notice that it did not, so the skill is the only place an
    unresolvable value can be caught before it is passed. What follows one is silent: every
    phase prompt names a path that does not exist, the agents port without the guidance, and
    the run still reports every language as passed.
    """
    if "referencesDir" not in script:
        return ["the script no longer accepts a references directory"]
    if "referencesDir" not in skill:
        return ["SKILL.md does not tell the caller to pass referencesDir"]

    # The argument block is what a model copies, so the value it shows is the one that matters.
    # Finding none means the block stopped naming the argument, which reads as clean to any
    # check that only searches for the word `referencesDir` in the prose around it.
    handed = HANDOVER_RE.findall(skill)
    if not handed:
        return ["SKILL.md names referencesDir but never shows what value to pass it"]

    errors = [
        f"SKILL.md hands referencesDir {value!r}, a token no workflow script can expand"
        for value in handed
        if "{" in value
    ]
    if "CLAUDE_PLUGIN_ROOT" not in skill:
        errors.append(
            "SKILL.md does not show how to resolve the references directory to a real path"
        )
    elif not PATH_PRINTING_RE.search(skill):
        errors.append(
            "SKILL.md resolves the references directory with a command that never prints it; "
            "`ls <dir>` lists the files inside the directory, so the caller has no path to copy"
        )

    # Only Claude Code exports CLAUDE_PLUGIN_ROOT. A single-step resolution is unreachable
    # everywhere else — Codex included, which this repo runs a loadability check for — and the
    # skill's own fallback advice is to run the phases by hand, which still needs the references.
    # c-review and rust-review both carry the same ladder.
    if "CODEX_PLUGIN_ROOT" not in skill:
        errors.append(
            "SKILL.md resolves the references directory only through ${CLAUDE_PLUGIN_ROOT}, "
            "which no harness outside Claude Code sets; it needs a fallback route"
        )
    return errors


def check_basedir_paths_resolve(skill: str, readme: str, script: str) -> list[str]:
    """Check every {baseDir} path in the skill exists on disk."""
    paths = BASEDIR_PATH_RE.findall(skill)
    if not paths:
        return ["no {baseDir} paths found in SKILL.md; link discovery is broken"]
    return [
        f"SKILL.md points at {{baseDir}}/{path}, which does not exist"
        for path in sorted(set(paths))
        if not (SKILL_DIR / path).exists()
    ]


def check_references_the_script_uses_are_linked(skill: str, readme: str, script: str) -> list[str]:
    """Check every reference the script sends agents to is one the skill documents."""
    named = sorted(set(SCRIPT_REFERENCE_RE.findall(script)))
    if not named:
        return ["the script names no reference files; discovery is broken"]

    errors = []
    for filename in named:
        if not (SKILL_DIR / "references" / filename).exists():
            errors.append(f"the script sends agents to references/{filename}, which does not exist")
        elif filename not in skill:
            errors.append(
                f"the script sends agents to references/{filename}, unmentioned in SKILL.md"
            )
    return errors


def check_description_would_trigger(skill: str, readme: str, script: str) -> list[str]:
    """Check the description still names the situation a user would describe."""
    description = skill_description(skill).lower()
    if not description:
        return ["SKILL.md frontmatter has no description; the skill would never trigger"]

    errors = [
        f"the description never says {word!r}"
        for word in DESCRIPTION_TRIGGERS
        if word not in description
    ]
    if not any(word in description for word in DESCRIPTION_TRIGGER_ALTERNATIVES):
        errors.append(f"the description says none of {DESCRIPTION_TRIGGER_ALTERNATIVES}")
    if description.startswith(("i ", "i'")):
        errors.append("the description is first person; skill descriptions are third person")
    return errors


CHECKERS = (
    check_documented_command_matches_the_script,
    check_every_arg_the_script_reads_is_documented,
    check_the_skill_hands_over_its_references,
    check_basedir_paths_resolve,
    check_references_the_script_uses_are_linked,
    check_description_would_trigger,
)


@pytest.mark.parametrize("checker", CHECKERS, ids=lambda c: c.__name__)
def test_skill_describes_the_workflow_it_invokes(checker) -> None:
    assert checker(SKILL_TEXT, README_TEXT, SCRIPT) == []


# Each mutation is a plausible edit that would break the skill while leaving the script,
# the other two suites, and every repo-wide check green.
BREAKAGES = (
    pytest.param(
        check_documented_command_matches_the_script,
        "skill",
        (":port-rule-to-languages", ":port-rule"),
        id="documenting a command the plugin does not define",
    ),
    pytest.param(
        check_every_arg_the_script_reads_is_documented,
        "skill",
        ('"rulePath": "<path to the rule being ported>",', ""),
        id="dropping an argument name from the skill",
    ),
    pytest.param(
        check_the_skill_hands_over_its_references,
        "skill",
        # The regression this argument exists to prevent, and the one the review found: a token
        # reaches the script, which cannot expand it and cannot see that the path is not there.
        (
            '"referencesDir": "<the absolute path the ls above printed>"',
            '"referencesDir": "{baseDir}/references"',
        ),
        id="handing referencesDir a token no workflow can expand",
    ),
    pytest.param(
        check_the_skill_hands_over_its_references,
        "skill",
        # Deleting the argument leaves the surrounding prose and the
        # `{baseDir}/references/<file>.md` links behind, so a check that searches for the word
        # alone still reports clean.
        ('"referencesDir": "<the absolute path the ls above printed>",\n', ""),
        id="dropping referencesDir from the argument block",
    ),
    pytest.param(
        check_the_skill_hands_over_its_references,
        "skill",
        # Without the resolution step the caller has nowhere to get a real path from, and the
        # placeholder in the block is the only remaining instruction.
        ("${CLAUDE_PLUGIN_ROOT}", "the plugin directory"),
        id="dropping the step that resolves the references path",
    ),
    pytest.param(
        check_the_skill_hands_over_its_references,
        "skill",
        # Dropping the `-d` leaves a command that looks like it resolves the path and prints the
        # names of the files inside it instead. This shipped: the instruction said to pass the
        # value as printed when nothing had printed a path.
        ('ls -d -- "${CLAUDE_PLUGIN_ROOT}', 'ls -- "${CLAUDE_PLUGIN_ROOT}'),
        id="resolving the references path with a command that never prints it",
    ),
    pytest.param(
        check_the_skill_hands_over_its_references,
        "skill",
        # Collapsing the ladder to the one variable only Claude Code exports.
        ("${CODEX_PLUGIN_ROOT}", "the plugin root"),
        id="resolving the references path with no route outside Claude Code",
    ),
    pytest.param(
        check_basedir_paths_resolve,
        "skill",
        ("{baseDir}/references/workflow.md", "{baseDir}/references/troubleshooting.md"),
        id="linking a reference file that does not exist",
    ),
    pytest.param(
        check_references_the_script_uses_are_linked,
        "skill",
        ("applicability-analysis.md", "applicability.md"),
        id="renaming a reference in the skill but not the script",
    ),
    pytest.param(
        check_documented_command_matches_the_script,
        "script",
        ("name: 'port-rule-to-languages'", "name: 'port-rule'"),
        id="renaming the workflow without updating the docs",
    ),
    pytest.param(
        check_every_arg_the_script_reads_is_documented,
        "script",
        ("args.outputDir", "args.destination"),
        id="renaming an argument without updating the docs",
    ),
)


@pytest.mark.parametrize(("checker", "target_file", "mutation"), BREAKAGES)
def test_checkers_detect_breakage(checker, target_file: str, mutation: tuple[str, str]) -> None:
    """Prove each checker fires when the thing it covers is broken.

    Mutations land on either side of the contract, because drift breaks it in both
    directions: the docs can go stale, and so can the script.
    """
    target, replacement = mutation
    texts = {"skill": SKILL_TEXT, "readme": README_TEXT, "script": SCRIPT}
    assert target in texts[target_file], (
        f"mutation target {target!r} is stale; {target_file} moved on"
    )

    texts[target_file] = texts[target_file].replace(target, replacement)
    assert checker(texts["skill"], texts["readme"], texts["script"]), (
        f"{checker.__name__} accepted a broken skill"
    )


def test_description_check_rejects_a_vague_description() -> None:
    """The trigger check gets its own mutation: the whole line has to go.

    Weakening one clause is not enough, because the triggers are spread across the
    description and the surviving clauses still carry them — which is the check working, not
    a gap. What breaks a skill is a description rewritten to say nothing in particular.
    """
    vague = FRONTMATTER_DESCRIPTION_RE.sub(
        "description: Helps with static analysis rules.", SKILL_TEXT, count=1
    )
    assert vague != SKILL_TEXT, "mutation changed nothing; the frontmatter pattern is stale"
    assert check_description_would_trigger(vague, README_TEXT, SCRIPT), (
        "a description naming neither the tool, the task, nor the situation was accepted"
    )
