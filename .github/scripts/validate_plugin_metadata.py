#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Validate plugin metadata, structure, and cross-references.

Two severities. **Errors** fail the build; they are things a machine can decide
without judgement. **Warnings** are reported and do not fail; they are real
problems the repo has not finished paying down, and blocking on them would only
teach people to ignore the output.

Run `--self-test` to prove the checkers still detect what they exist to detect.
A checker that has silently stopped matching reports a clean repo forever.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ERROR = "error"
WARNING = "warning"

# Agent definitions and skills read their tool restrictions from *different* keys.
# Getting this wrong is silent: the frontmatter still parses, the restriction is
# simply ignored and the agent inherits everything.
AGENT_TOOLS_KEY = "tools"
SKILL_TOOLS_KEY = "allowed-tools"

# subagent_type values that are not plugin agents and are correctly unnamespaced.
BUILTIN_SUBAGENT_TYPES = frozenset(
    {
        "general-purpose",
        "Explore",
        "Plan",
        "claude",
        "statusline-setup",
        "output-style-setup",
        "fork",
    }
)

# `subagent_type="x"`, `subagent_type: "x"`, and the prose form `subagent_type` to `x`.
SUBAGENT_TYPE_PATTERNS = (
    re.compile(r"""subagent_type\s*[=:]\s*["'`]([^"'`\n]+)["'`]"""),
    re.compile(r"""`subagent_type`\s+to\s+`([^`\n]+)`"""),
)

# Relative references from a skill or command file to another file in the same plugin.
# The lookbehind anchors the alternation to a path-segment boundary: without it, prose
# citing `.github/workflows/ci.yml` yields the phantom reference `workflows/ci.yml`.
REFERENCE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"(?:\.\./|references/|workflows/|scripts/|examples/|agents/|assets/)"
    r"[A-Za-z0-9_./-]+\.(?:md|sh|py|json|yaml|yml|html|csv|toml)"
)

# Paths this repo deliberately does not carry. Claude marketplace metadata is the
# single canonical source; Codex and other runtimes read it through that compatibility.
FORBIDDEN_SIDECAR_PATHS = (
    ".codex",
    ".opencode",
    ".agents",
)
FORBIDDEN_PLUGIN_SIDECARS = (".codex-plugin", ".opencode-plugin")

SKILL_LINE_LIMIT = 500
KEBAB_CASE_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PLUGIN_NAME_MAX_LENGTH = 64
SEMVER_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)")

# An absolute path into one developer's home directory. The lookbehind anchors to a
# path-segment boundary. Both branches accept either case: macOS account names are
# conventionally lowercase, and a /Users/[A-Z]-only match misses nearly all of them.
HARDCODED_PATH_PATTERN = re.compile(r"(?<![a-zA-Z])(?:/home/[A-Za-z]|/Users/[A-Za-z])")
# Test fixtures and install scripts are where absolute paths hide.
HARDCODED_PATH_SUFFIXES = (".md", ".py", ".json", ".sh", ".bats", ".yml", ".toml")
# The shim suites need literal /home/user paths.
HARDCODED_PATH_EXEMPT_SUFFIX = "-shim.bats"
# Placeholders, illustrative examples (`/Users/me/` in c-review's docs) and shared system
# paths — keep this list to forms that cannot be somebody's actual account.
HARDCODED_PATH_PLACEHOLDERS = ("/path/to", "/home/vscode", "/Users/Shared", "/Users/me/")

# Documented commands the modern-python plugin's PATH shims refuse — a skill carrying one
# cannot run for anyone with that plugin installed. Unanchored, because violations hide
# mid-line (markdown table cells, `run_logged pip install …`); the guards below carve out
# the legitimate uses explicitly rather than under-detecting via an anchor.
# `uv pip` first: its lines also contain `pip <sub>`, and first-hit-wins would otherwise
# report them with pip's advice.
LEGACY_PYTHON_PATTERNS = (
    (
        # Every `uv pip` subcommand is refused without a tool-managed flag, not just
        # install; the allowed-flags guard below carves those out.
        re.compile(r"\buv\s+pip\s+[a-z]"),
        "uses the legacy `uv pip` interface; use `uv add`, `uv sync`, or `uv tool install`",
    ),
    (
        # Leading flags are stepped over — long, short, and value-taking alike
        # (`python3 -W ignore foo.py` is refused too) — except -c/-m, whose
        # argument is not a script path. Values may not start with `-`, and
        # backtracking releases a swallowed script name.
        re.compile(
            r"\bpython3?\s+(?:--?(?![cm]\b)[A-Za-z][\w-]*(?:[= ](?!-)\S+)?\s+)*(?!-)\S*\.py\b"
        ),
        "runs a script through the bare interpreter; use `uv run --no-project <script>`",
    ),
    (
        # A script named by variable or path (`python3 "$MERGE"`, `python3 ./tool`) is
        # refused just the same, with no `.py` token for the pattern above to see.
        re.compile(r"""\bpython3?\s+(?:--?(?![cm]\b)[A-Za-z][\w-]*(?:[= ](?!-)\S+)?\s+)*["'$./]"""),
        "runs a script through the bare interpreter; use `uv run --no-project <script>`",
    ),
    (
        # The shims refuse every pip/pipx subcommand via a catch-all arm. Deliberately a
        # named subset here, to keep prose false positives down; extend as instances appear.
        re.compile(
            r"\bpip3?\s+(install|uninstall|freeze|download|list|show|check|wheel|cache|config)\b"
        ),
        "uses pip; use `uv run --with <pkg>` for a one-off, `uv add` in your own project, "
        "or `uv tool install <pkg>` for a CLI",
    ),
    (
        re.compile(r"\bpipx\s+(install|run|upgrade|uninstall|inject|list|ensurepath|reinstall)\b"),
        "uses pipx; use `uv tool install <pkg>` or `uvx <pkg>`",
    ),
    (
        re.compile(r"\bpython3?\s+-m\s+pip\b"),
        "uses python -m pip; use `uv run --with <pkg>`, `uv add`, or `uv tool install`",
    ),
    (
        # A bare interpreter with only flags (`python3 --version`) is refused as well:
        # the shim finds no -c/-m/- selector and falls through to the refusal arm.
        re.compile(r"\bpython3?\s+--?[A-Za-z][\w-]*\s*$"),
        "invokes the bare interpreter; use `uv run python <flags>`",
    ),
)
# Prose that names a command in order to forbid it ("Do NOT run `pip install`"). Tested
# against the text BEFORE the match, so "Use `pip install x` instead of the tarball" — a
# real instruction — is not exempted by its own trailing "instead of".
LEGACY_PYTHON_PROHIBITIONS = ("do not run", "don't run", "do not use", "never run", "instead of")
# `uv run --no-project python fuzz.py` contains a literal `python fuzz.py`; text already
# introduced by a compliant `uv run` is the fix, not a violation.
LEGACY_PYTHON_COMPLIANT_PREFIX = re.compile(r"uv\s+run\s+(?:--?[A-Za-z-]+(?:[= ]\S+)?\s+)*$")
# A tool managing an environment it owns (prek installs hooks this way); the shim permits
# it. Matched as whole flags after the command so `--target-dir` does not count.
LEGACY_PYTHON_UV_PIP_ALLOWED = re.compile(r"\s(--project|--directory|--target|-t)([= ]|$)")
# Exempts its code block up to the next blank line or fence, for commands that run where
# the shims are absent (a container, a target project's own build). A bare marker with no
# reason does not exempt.
LEGACY_PYTHON_ALLOW_MARKER = "allow-legacy-python:"
LEGACY_PYTHON_ALLOW_RE = re.compile(r"allow-legacy-python:\s*\S")
# Local trees accumulate these; CI never has them, so skipping keeps the two runs equal.
SCAN_SKIP_DIRS = frozenset({".venv", "venv", "node_modules", "__pycache__", ".git", ".ruff_cache"})

# Floor for --self-test, set to the exact number of assertions the fixtures run. There is
# no slack on purpose: dropping one has to be a deliberate edit here, not a silent loss.
SELF_TEST_MINIMUM = 82


@dataclass
class Finding:
    """A single validation finding."""

    plugin: str
    message: str
    severity: str = ERROR

    def __str__(self) -> str:
        return f"{self.plugin}: {self.message}"


@dataclass
class ScanResult:
    """Findings plus the counters the anti-vacuity guards read."""

    findings: list[Finding] = field(default_factory=list)
    refs_checked: int = 0
    paths_scanned: int = 0
    python_docs_scanned: int = 0

    def add(self, plugin: str, message: str, severity: str = ERROR) -> None:
        self.findings.append(Finding(plugin, message, severity))


# --------------------------------------------------------------------------- parsing


def scan_plugins_directory(plugins_dir: Path) -> set[str]:
    """Scan plugins/ directory and return all plugin directory names."""
    if not plugins_dir.is_dir():
        return set()

    return {p.name for p in plugins_dir.iterdir() if p.is_dir() and not p.name.startswith(".")}


def parse_marketplace(marketplace_path: Path) -> dict[str, dict]:
    """Parse marketplace.json and return plugin_name -> plugin_data mapping."""
    if not marketplace_path.exists():
        return {}

    data = json.loads(marketplace_path.read_text())
    return {p["name"]: p for p in data.get("plugins", []) if p.get("name")}


def parse_codeowners(codeowners_path: Path) -> set[str]:
    """Parse CODEOWNERS and return set of plugin names with entries."""
    if not codeowners_path.exists():
        return set()

    plugins = set()
    pattern = re.compile(r"^/plugins/([^/]+)/")

    for line in codeowners_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and (match := pattern.match(line)):
            plugins.add(match.group(1))

    return plugins


def parse_readme(readme_path: Path) -> set[str]:
    """Parse README.md and return set of plugin names mentioned in tables."""
    if not readme_path.exists():
        return set()

    plugins = set()
    pattern = re.compile(r"\[[^\]]+\]\(\.?/?plugins/([^/)]+)")

    for line in readme_path.read_text().splitlines():
        for match in pattern.finditer(line):
            plugins.add(match.group(1))

    return plugins


def parse_plugin_json(plugin_path: Path) -> dict | None:
    """Parse plugin.json and return data, or None if missing/invalid."""
    json_path = plugin_path / ".claude-plugin" / "plugin.json"
    if not json_path.exists():
        return None

    try:
        return json.loads(json_path.read_text())
    except json.JSONDecodeError:
        return None


def extract_frontmatter(text: str) -> str | None:
    """Return the raw YAML frontmatter block, or None when absent."""
    if not text.startswith("---"):
        return None

    match = re.match(r"^---\r?\n(.*?)\r?\n---\s*(?:\r?\n|$)", text, re.DOTALL)
    return match.group(1) if match else None


def frontmatter_has_key(block: str, key: str) -> bool:
    """True when the frontmatter declares `key` at the top level."""
    return re.search(rf"^{re.escape(key)}\s*:", block, re.MULTILINE) is not None


def agent_files(plugin_path: Path) -> list[Path]:
    """Markdown agent definitions at the plugin's own agents/ directory.

    Scoped to `plugins/<name>/agents/`. A `skills/<skill>/agents/` directory holds
    per-runtime presentation metadata (icons, brand colors), not agent definitions —
    matching any path containing `/agents/` would flag those as broken agents.
    """
    agents_dir = plugin_path / "agents"
    if not agents_dir.is_dir():
        return []
    return sorted(p for p in agents_dir.rglob("*.md") if p.is_file())


def skill_files(plugin_path: Path) -> list[Path]:
    """Every SKILL.md under the plugin."""
    skills_dir = plugin_path / "skills"
    if not skills_dir.is_dir():
        return []
    return sorted(skills_dir.rglob("SKILL.md"))


def command_files(plugin_path: Path) -> list[Path]:
    """Markdown slash-command definitions at the plugin's own commands/ directory."""
    commands_dir = plugin_path / "commands"
    if not commands_dir.is_dir():
        return []
    return sorted(p for p in commands_dir.rglob("*.md") if p.is_file())


# ---------------------------------------------------------------------------- errors


def validate_plugin_json(
    plugin_data: dict | None,
    plugin_path: Path,
    plugin_name: str,
) -> list[str]:
    """Validate plugin.json, the directory name, and the plugin README."""
    errors = []

    # These run before the early returns below, so a plugin with an unparseable
    # plugin.json still gets told about its name and its missing README.
    if not KEBAB_CASE_PATTERN.match(plugin_name):
        errors.append(f"directory name '{plugin_name}' is not kebab-case")
    if len(plugin_name) > PLUGIN_NAME_MAX_LENGTH:
        errors.append(
            f"directory name is {len(plugin_name)} characters, "
            f"over the {PLUGIN_NAME_MAX_LENGTH} limit"
        )

    # Listed rather than stat'd: `Readme.md` satisfies is_file() on case-insensitive
    # macOS and then fails on Linux CI.
    if "README.md" not in {p.name for p in plugin_path.iterdir()}:
        errors.append("missing README.md")

    json_path = plugin_path / ".claude-plugin" / "plugin.json"
    if not json_path.exists():
        errors.append("missing .claude-plugin/plugin.json")
        return errors

    if plugin_data is None:
        errors.append(".claude-plugin/plugin.json is invalid JSON")
        return errors

    if "name" not in plugin_data:
        errors.append(".claude-plugin/plugin.json missing 'name' field")
    elif plugin_data["name"] != plugin_name:
        errors.append(
            f".claude-plugin/plugin.json name '{plugin_data['name']}' "
            f"doesn't match directory name '{plugin_name}'"
        )

    if "description" not in plugin_data:
        errors.append(".claude-plugin/plugin.json missing 'description' field")

    if "version" not in plugin_data:
        errors.append(".claude-plugin/plugin.json missing 'version' field")
    elif not SEMVER_PATTERN.match(str(plugin_data["version"])):
        errors.append(f"version '{plugin_data['version']}' is not MAJOR.MINOR.PATCH")

    return errors


def validate_marketplace_entry(
    marketplace_plugins: dict[str, dict],
    plugin_data: dict | None,
    plugin_name: str,
) -> list[str]:
    """Validate plugin has matching entry in marketplace.json."""
    if plugin_name not in marketplace_plugins:
        return ["not found in .claude-plugin/marketplace.json"]

    if plugin_data is None:
        return []

    errors = []
    marketplace_entry = marketplace_plugins[plugin_name]

    if plugin_data.get("name") != marketplace_entry.get("name"):
        errors.append(
            f"name mismatch: plugin.json has '{plugin_data.get('name')}', "
            f"marketplace.json has '{marketplace_entry.get('name')}'"
        )

    # A bump to one file only ships nothing: clients read marketplace.json.
    if plugin_data.get("version") != marketplace_entry.get("version"):
        errors.append(
            f"version mismatch: plugin.json has '{plugin_data.get('version')}', "
            f"marketplace.json has '{marketplace_entry.get('version')}'"
        )

    if plugin_data.get("description") != marketplace_entry.get("description"):
        errors.append("description mismatch between plugin.json and marketplace.json")

    expected_source = f"./plugins/{plugin_name}"
    actual_source = marketplace_entry.get("source", "")
    if actual_source != expected_source:
        errors.append(f"marketplace.json source '{actual_source}' should be '{expected_source}'")

    return errors


def validate_tools_frontmatter(plugin_path: Path) -> list[str]:
    """Agent files declare tools with `tools:`; skills and commands use `allowed-tools:`.

    The keys are inverted between the file types and the loader silently ignores
    the wrong one, so a restriction written the wrong way is not a restriction at all.
    """
    errors = []

    for agent in agent_files(plugin_path):
        block = extract_frontmatter(agent.read_text(encoding="utf-8", errors="replace"))
        if block is None:
            errors.append(f"{agent.name}: agent file has no YAML frontmatter")
            continue
        if frontmatter_has_key(block, SKILL_TOOLS_KEY):
            errors.append(
                f"agents/{agent.name} uses '{SKILL_TOOLS_KEY}:'; agent files must use "
                f"'{AGENT_TOOLS_KEY}:' (the loader ignores the other key silently)"
            )

    for skill in skill_files(plugin_path):
        block = extract_frontmatter(skill.read_text(encoding="utf-8", errors="replace"))
        if block is None:
            continue
        if frontmatter_has_key(block, AGENT_TOOLS_KEY):
            rel = skill.relative_to(plugin_path)
            errors.append(f"{rel} uses '{AGENT_TOOLS_KEY}:'; skills must use '{SKILL_TOOLS_KEY}:'")

    for command in command_files(plugin_path):
        block = extract_frontmatter(command.read_text(encoding="utf-8", errors="replace"))
        if block is None:
            continue
        if frontmatter_has_key(block, AGENT_TOOLS_KEY):
            rel = command.relative_to(plugin_path)
            errors.append(
                f"{rel} uses '{AGENT_TOOLS_KEY}:'; commands must use '{SKILL_TOOLS_KEY}:'"
            )

    return errors


def validate_command_frontmatter(plugin_path: Path) -> list[str]:
    """Command files need parseable frontmatter with a description, and `allowed-tools:`.

    Nothing else checks commands. A plugin whose only entry point is a command had its
    frontmatter validated by no tool at all, and the loadability checks count skills, so
    a malformed command shipped green.
    """
    errors = []

    for command in command_files(plugin_path):
        rel = command.relative_to(plugin_path)
        block = extract_frontmatter(command.read_text(encoding="utf-8", errors="replace"))
        if block is None:
            errors.append(f"{rel}: command file has no YAML frontmatter")
            continue
        if not frontmatter_has_key(block, "description"):
            errors.append(f"{rel}: command frontmatter has no 'description:'")
        if frontmatter_has_key(block, AGENT_TOOLS_KEY):
            errors.append(
                f"{rel} uses '{AGENT_TOOLS_KEY}:'; commands must use '{SKILL_TOOLS_KEY}:' "
                "(the loader ignores the other key silently)"
            )

    return errors


def validate_skill_frontmatter(plugin_path: Path) -> list[str]:
    """Top-level frontmatter values must survive a YAML parse.

    A plain (unquoted) YAML scalar cannot contain ": " — that parses as a nested
    mapping — nor " #", which starts a comment. Either one makes the whole block
    unparseable, and the loader then drops *every* field and loads the skill with
    empty metadata. Nothing about the file looks wrong: a presence check still sees
    `description:` on line 3 and reports it clean, so the skill ships with no
    description and simply never triggers.
    """
    errors = []

    for skill in skill_files(plugin_path):
        block = extract_frontmatter(skill.read_text(encoding="utf-8", errors="replace"))
        if block is None:
            errors.append(f"{skill.relative_to(plugin_path)}: has no YAML frontmatter")
            continue

        for line in block.splitlines():
            match = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(\S.*?)\s*$", line)
            if not match:
                continue
            key, value = match.group(1), match.group(2)
            # Quotes, block scalars, flow collections and YAML indicators are all
            # parsed by rules other than the plain-scalar ones below.
            if value[0] in "\"'|>[{&*!%@`":
                continue
            for token, human in ((": ", "': '"), (" #", "' #'")):
                if token in value:
                    errors.append(
                        f"{skill.relative_to(plugin_path)}: '{key}' is an unquoted YAML "
                        f"scalar containing {human}, so the frontmatter does not parse and "
                        f"the skill loads with no metadata at all — wrap the value in quotes"
                    )
                    break

    return errors


def validate_entry_points(plugin_path: Path) -> list[str]:
    """A plugin must expose something a user or model can actually invoke.

    The loadability checks count `skills/**/SKILL.md` and MCP servers, so a plugin with
    neither passes them at 0 == 0 while shipping nothing runnable. Requiring at least one
    entry point here means that vacuous pass cannot be the whole story.
    """
    if skill_files(plugin_path) or command_files(plugin_path):
        return []
    if (plugin_path / "agents").is_dir() and agent_files(plugin_path):
        return []
    if (plugin_path / ".mcp.json").is_file() or (plugin_path / "hooks" / "hooks.json").is_file():
        return []
    return ["exposes no entry point: no skills/, commands/, agents/, hooks, or .mcp.json"]


def validate_subagent_dispatch(
    plugin_path: Path,
    plugin_name: str,
    agent_owners: dict[str, list[str]],
) -> list[str]:
    """Every bare subagent_type is a dispatch that fails at runtime.

    `agent_owners` maps an agent filename stem to the plugins defining it, across the
    whole repo. Scoping this to the plugin's own agents would miss the two cases most
    likely to ship: a bare name borrowed from another plugin, and a bare name for an
    agent that no longer exists anywhere.
    """
    own_agents = {p.stem for p in agent_files(plugin_path)}

    errors = []
    for path in sorted(plugin_path.rglob("*.md")) + sorted(plugin_path.rglob("*.sh")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in SUBAGENT_TYPE_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(1).strip()
                if ":" in value or value in BUILTIN_SUBAGENT_TYPES:
                    continue
                if value.startswith(("{", "$")):
                    continue
                rel = path.relative_to(plugin_path)
                if value in own_agents:
                    errors.append(
                        f"{rel}: subagent_type '{value}' is not namespaced; "
                        f"use '{plugin_name}:{value}'"
                    )
                elif value in agent_owners:
                    suggestion = " or ".join(
                        f"'{owner}:{value}'" for owner in sorted(agent_owners[value])
                    )
                    errors.append(
                        f"{rel}: subagent_type '{value}' is not namespaced; use {suggestion}"
                    )
                else:
                    errors.append(
                        f"{rel}: subagent_type '{value}' names no agent in this repo and is "
                        f"not a builtin, so the dispatch fails at runtime"
                    )
    return errors


def find_legacy_python_invocations(repo_root: Path) -> tuple[list[str], int]:
    """Documented commands the modern-python shims refuse, so the skill cannot run.

    Returns the findings and the number of files scanned; zero scanned is the caller's
    anti-vacuity guard. `plugins/modern-python/` is exempt wholesale so it can keep
    documenting the commands it intercepts.
    """
    errors: list[str] = []
    scanned = 0

    plugins_dir = repo_root / "plugins"
    if not plugins_dir.is_dir():
        return errors, scanned

    # .sh and .py as well as .md: shell suites carried ten live invocations a docs-only
    # sweep missed, and .py usage strings tell users to run refused commands.
    candidates = (
        sorted(plugins_dir.rglob("*.md"))
        + sorted(plugins_dir.rglob("*.sh"))
        + sorted(plugins_dir.rglob("*.py"))
    )
    for path in candidates:
        if not path.is_file():
            continue
        if path.is_relative_to(plugins_dir / "modern-python"):
            continue
        if SCAN_SKIP_DIRS.intersection(path.parts):
            continue
        # .md and .py under evals*/tests quote commands as expectations under test;
        # .sh there are commands, so shell keeps no exemption.
        if path.suffix in (".md", ".py") and any(
            part.startswith("evals") or part == "tests"
            for part in path.relative_to(plugins_dir).parts
        ):
            continue
        scanned += 1

        # A `dockerfile` fence runs in a container, where the PATH shims are absent.
        in_dockerfile = False
        block_exempt = False
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for lineno, line in enumerate(lines, 1):
            fence = line.strip()
            if fence.startswith("```"):
                language = fence[3:].strip().lower()
                in_dockerfile = language == "dockerfile" if language else False
                block_exempt = False
                continue
            if not line.strip():
                block_exempt = False
                continue
            if LEGACY_PYTHON_ALLOW_MARKER in line:
                block_exempt = bool(LEGACY_PYTHON_ALLOW_RE.search(line))
                continue
            if in_dockerfile or block_exempt:
                continue

            # Every match is examined, not just the first: a compliant `uv run …` earlier
            # on a line must not mask a refused command later on the same line.
            hit = None
            for pattern, advice in LEGACY_PYTHON_PATTERNS:
                for match in pattern.finditer(line):
                    prefix = line[: match.start()]
                    if LEGACY_PYTHON_COMPLIANT_PREFIX.search(prefix):
                        continue
                    # A `pip …` directly after `uv ` is part of a `uv pip` command,
                    # whose verdict the uv-pip pattern above already delivered.
                    if not match.group(0).startswith("uv") and re.search(r"\buv\s+$", prefix):
                        continue
                    if any(p in prefix.lower() for p in LEGACY_PYTHON_PROHIBITIONS):
                        continue
                    if "uv pip" in match.group(0) and LEGACY_PYTHON_UV_PIP_ALLOWED.search(
                        line[match.start() :]
                    ):
                        continue
                    hit = advice
                    break
                if hit:
                    break
            if hit:
                rel = path.relative_to(repo_root)
                errors.append(f"{rel}:{lineno} {hit} — found: {line.strip()[:70]}")

    return errors, scanned


def find_hardcoded_paths(repo_root: Path) -> tuple[list[str], int]:
    """Absolute paths into one developer's home directory, which nobody else has.

    Returns the findings and the number of files scanned. The count is the caller's
    anti-vacuity guard: a scan that inspected nothing must not report clean.
    """
    errors = []
    scanned = 0

    plugins_dir = repo_root / "plugins"
    if not plugins_dir.is_dir():
        return errors, scanned

    for path in sorted(plugins_dir.rglob("*")):
        if not path.is_file() or path.suffix not in HARDCODED_PATH_SUFFIXES:
            continue
        if path.name.endswith(HARDCODED_PATH_EXEMPT_SUFFIX):
            continue
        if SCAN_SKIP_DIRS.intersection(path.parts):
            continue
        scanned += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            if not HARDCODED_PATH_PATTERN.search(line):
                continue
            if any(placeholder in line for placeholder in HARDCODED_PATH_PLACEHOLDERS):
                continue
            rel = path.relative_to(repo_root)
            errors.append(f"{rel}:{lineno} hardcodes an absolute user path: {line.strip()[:80]}")

    return errors, scanned


def find_forbidden_sidecars(repo_root: Path) -> list[str]:
    """Runtime sidecar directories this repo does not carry."""
    errors = []

    for rel in FORBIDDEN_SIDECAR_PATHS:
        if (repo_root / rel).exists():
            errors.append(
                f"{rel} exists; Claude marketplace metadata is the single canonical "
                f"source and other runtimes read it through that compatibility"
            )

    plugins_dir = repo_root / "plugins"
    if plugins_dir.is_dir():
        for plugin in sorted(plugins_dir.iterdir()):
            for sidecar in FORBIDDEN_PLUGIN_SIDECARS:
                if (plugin / sidecar).exists():
                    errors.append(f"plugins/{plugin.name}/{sidecar} exists; not supported")

    return errors


def check_dependabot_lockfiles(repo_root: Path) -> list[str]:
    """Every uv directory in dependabot.yml must carry a committed uv.lock.

    Without one there is nothing to pin, so Dependabot's only available action is
    raising the lower bound of an already-open range — which changes nothing about
    what installs and only drops support for older versions. That produced five
    no-op PRs the first time this config ran. Documenting the rule in a comment
    left it unenforced; this makes it real.
    """
    config = repo_root / ".github" / "dependabot.yml"
    if not config.exists():
        return []

    text = config.read_text()
    # Read the `directories:` list belonging to the uv ecosystem block only. A bare
    # search for `- /plugins/...` would also pick up any future ecosystem's paths.
    uv_block = re.search(
        r"^\s*-\s*package-ecosystem:\s*uv\s*$(.*?)(?=^\s*-\s*package-ecosystem:|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not uv_block:
        return []

    listed = re.findall(r"^\s+-\s+(/plugins/\S+)\s*$", uv_block.group(1), re.MULTILINE)
    if not listed:
        # The block exists but no directories parsed out — the regex broke, or the
        # block was emptied. Either way this checker just inspected zero items.
        return [
            "dependabot.yml has a uv ecosystem block but no directories parsed from it "
            "— the lockfile check inspected nothing"
        ]

    errors = []
    for rel in listed:
        directory = repo_root / rel.lstrip("/")
        if not directory.is_dir():
            errors.append(f"dependabot.yml lists {rel}, which does not exist")
        elif not (directory / "uv.lock").is_file():
            errors.append(
                f"dependabot.yml lists {rel} but it has no committed uv.lock; "
                f"without one Dependabot can only raise version floors (run "
                f"`cd {rel.lstrip('/')} && uv lock`)"
            )
    return errors


def _git_show(repo_root: Path, ref: str, rel_path: str) -> str | None:
    """Contents of `rel_path` at `ref`, or None when it did not exist there."""
    result = subprocess.run(
        ["git", "show", f"{ref}:{rel_path}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def _merge_base(repo_root: Path, base_ref: str) -> str:
    """The commit this branch forked from, falling back to base_ref itself."""
    result = subprocess.run(
        ["git", "merge-base", base_ref, "HEAD"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else base_ref


def _semver_tuple(value: str) -> tuple[int, int, int] | None:
    match = SEMVER_PATTERN.match(str(value))
    return tuple(int(g) for g in match.groups()) if match else None  # type: ignore[return-value]


def changed_plugins(repo_root: Path, base_ref: str) -> set[str]:
    """Plugins with file changes between the merge base and HEAD.

    Compares commits, so uncommitted local changes are invisible to a local run.

    The version-increment check applies only to these. Running it over every plugin
    would demand a bump from all 40+ on every PR, including PRs that touch no plugin
    at all — which is exactly what it did the first time it ran in CI.
    """
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        # Returning an empty set here would disarm the version check for every plugin
        # with no message — a force-pushed base, a gc'd commit or a shallow clone would
        # read as "everything is fine".
        raise RuntimeError(
            f"git diff against {base_ref} failed, so changed plugins cannot be "
            f"determined: {result.stderr.strip()}"
        )

    changed = set()
    for line in result.stdout.splitlines():
        parts = line.strip().split("/")
        if len(parts) >= 2 and parts[0] == "plugins":
            changed.add(parts[1])
    return changed


def validate_version_increment(
    repo_root: Path,
    plugin_name: str,
    plugin_data: dict | None,
    base_ref: str,
) -> list[str]:
    """A substantive change to a plugin must raise its version above the base ref.

    Clients only see an update when the number increases, so a fix shipped without a
    bump reaches nobody.
    """
    if plugin_data is None or "version" not in plugin_data:
        return []

    rel = f"plugins/{plugin_name}/.claude-plugin/plugin.json"
    # Merge base, not the base branch head. `changed_plugins` diffs `base...HEAD`, so
    # reading the old version at `base_ref` directly would compare against whatever
    # landed on main after this branch forked — failing a PR for not out-bumping a
    # sibling it never saw.
    base_raw = _git_show(repo_root, _merge_base(repo_root, base_ref), rel)
    if base_raw is None:
        return []  # new plugin on this branch

    try:
        base_version = json.loads(base_raw).get("version")
    except json.JSONDecodeError:
        return []

    new = _semver_tuple(plugin_data["version"])
    old = _semver_tuple(base_version) if base_version else None
    if new is None or old is None or new > old:
        return []

    return [
        f"version {plugin_data['version']} is not greater than {base_version} at "
        f"the merge base; clients only pull an update when the number increases. "
        f"Bump it, or apply the 'no-version-bump' label for a typo-only change. "
        f"If another PR bumped this plugin after you branched, rebase first"
    ]


# -------------------------------------------------------------------------- warnings


def check_skill_length(plugin_path: Path) -> list[str]:
    """Long skills should be split into references/."""
    warnings = []
    for skill in skill_files(plugin_path):
        lines = len(skill.read_text(encoding="utf-8", errors="replace").splitlines())
        if lines > SKILL_LINE_LIMIT:
            rel = skill.relative_to(plugin_path)
            warnings.append(f"{rel} is {lines} lines, over the {SKILL_LINE_LIMIT} limit")
    return warnings


def strip_code_blocks(text: str) -> str:
    """Blank out fenced and inline code so illustrative paths are not read as links.

    Skill-authoring docs are full of example paths (`references/patterns.md`) that
    describe a shape rather than point at a file. Counting those produces a warning
    list nobody reads. Lines are preserved so reported positions stay meaningful.
    """
    out, in_fence = [], False
    for line in text.splitlines():
        if re.match(r"^\s*(```|~~~)", line):
            in_fence = not in_fence
            out.append("")
            continue
        out.append("" if in_fence else re.sub(r"`[^`\n]*`", "``", line))
    return "\n".join(out)


def validate_reference_links(plugin_path: Path) -> tuple[list[str], int]:
    """Relative references should resolve to a file somewhere in the plugin.

    Deliberately not pinned to one base directory: authors write pointers relative to
    the containing file, the skill root, and the plugin root interchangeably, and
    pinning produces a flood of false positives. Returns the count of references
    examined so callers can detect an extractor that matched nothing.
    """
    warnings: list[str] = []
    checked = 0

    # Any evals* directory is skipped: its .md files are labelled eval queries, not
    # documentation, and they carry frontmatter rather than references. The prefix match
    # covers "evals-extra" (harnesses invoked by hand rather than by `make check`) as
    # well as "evals" — a bare equality check silently starts scanning them.
    files = [
        p
        for p in plugin_path.rglob("*.md")
        if p.is_file() and not any(part.startswith("evals") for part in p.parts)
    ]
    if not files:
        return warnings, checked

    suffixes = {str(p.relative_to(plugin_path)) for p in plugin_path.rglob("*") if p.is_file()}

    def resolves(md: Path, ref: str) -> bool:
        # A `../` reference may legitimately point outside the plugin (repo-root
        # AGENTS.md, a sibling plugin), so resolve those literally first.
        if ref.startswith("../") and (md.parent / ref).resolve().is_file():
            return True
        normalized = ref.lstrip("./")
        while normalized.startswith("../"):
            normalized = normalized[3:]
        return any(s == normalized or s.endswith("/" + normalized) for s in suffixes)

    for md in files:
        text = strip_code_blocks(md.read_text(encoding="utf-8", errors="replace"))
        for match in REFERENCE_PATTERN.finditer(text):
            ref = match.group(0)
            checked += 1
            if not resolves(md, ref):
                warnings.append(
                    f"{md.relative_to(plugin_path)}: reference '{ref}' does not resolve"
                )

    return warnings, checked


# ------------------------------------------------------------------------ the driver


def validate_plugins(
    plugins_to_check: set[str],
    repo_root: Path,
    base_ref: str | None = None,
) -> ScanResult:
    """Validate all specified plugins."""
    result = ScanResult()

    plugins_dir = repo_root / "plugins"
    marketplace_plugins = parse_marketplace(repo_root / ".claude-plugin" / "marketplace.json")
    codeowners_plugins = parse_codeowners(repo_root / "CODEOWNERS")
    readme_plugins = parse_readme(repo_root / "README.md")

    # Agents are addressed as `<plugin>:<agent>` from anywhere, so the registry has to be
    # repo-wide and built before any single plugin is checked against it.
    agent_owners: dict[str, list[str]] = {}
    if plugins_dir.is_dir():
        for plugin in sorted(plugins_dir.iterdir()):
            if not plugin.is_dir():
                continue
            for agent in agent_files(plugin):
                agent_owners.setdefault(agent.stem, []).append(plugin.name)

    for msg in find_forbidden_sidecars(repo_root):
        result.add("<repo>", msg)
    for msg in check_dependabot_lockfiles(repo_root):
        result.add("<repo>", msg)

    legacy_errors, result.python_docs_scanned = find_legacy_python_invocations(repo_root)
    for msg in legacy_errors:
        result.add("<repo>", msg)

    path_errors, result.paths_scanned = find_hardcoded_paths(repo_root)
    for msg in path_errors:
        result.add("<repo>", msg)

    # Scoped to plugins this branch actually touched. Empty when there is no base ref
    # (a push to main, or a local run), which switches the version check off entirely.
    version_check_scope = changed_plugins(repo_root, base_ref) if base_ref else set()

    for plugin_name in sorted(plugins_to_check):
        plugin_path = plugins_dir / plugin_name

        if not plugin_path.is_dir():
            if plugin_name in marketplace_plugins:
                result.add(plugin_name, "deleted but still in .claude-plugin/marketplace.json")
            if plugin_name in codeowners_plugins:
                result.add(plugin_name, "deleted but still in CODEOWNERS")
            if plugin_name in readme_plugins:
                result.add(plugin_name, "deleted but still in README.md")
            continue

        plugin_data = parse_plugin_json(plugin_path)

        for msg in validate_plugin_json(plugin_data, plugin_path, plugin_name):
            result.add(plugin_name, msg)
        for msg in validate_marketplace_entry(marketplace_plugins, plugin_data, plugin_name):
            result.add(plugin_name, msg)
        for msg in validate_tools_frontmatter(plugin_path):
            result.add(plugin_name, msg)
        for msg in validate_command_frontmatter(plugin_path):
            result.add(plugin_name, msg)
        for msg in validate_skill_frontmatter(plugin_path):
            result.add(plugin_name, msg)
        for msg in validate_entry_points(plugin_path):
            result.add(plugin_name, msg)
        for msg in validate_subagent_dispatch(plugin_path, plugin_name, agent_owners):
            result.add(plugin_name, msg)

        if base_ref and plugin_name in version_check_scope:
            for msg in validate_version_increment(repo_root, plugin_name, plugin_data, base_ref):
                result.add(plugin_name, msg)

        if plugin_name not in codeowners_plugins:
            result.add(plugin_name, "not found in CODEOWNERS")
        if plugin_name not in readme_plugins:
            result.add(plugin_name, "not found in README.md")

        for msg in check_skill_length(plugin_path):
            result.add(plugin_name, msg, WARNING)

        ref_warnings, checked = validate_reference_links(plugin_path)
        result.refs_checked += checked
        for msg in ref_warnings:
            result.add(plugin_name, msg, WARNING)

    return result


def report(result: ScanResult) -> None:
    """Print findings grouped by severity."""
    errors = [f for f in result.findings if f.severity == ERROR]
    warnings = [f for f in result.findings if f.severity == WARNING]

    if warnings:
        print(f"\n{len(warnings)} warning(s) — these do not fail the build:\n")
        for finding in warnings:
            print(f"  ! {finding}")

    if errors:
        print(f"\n{len(errors)} error(s):\n")
        for finding in errors:
            print(f"  ✗ {finding}")


def main(argv: list[str] | None = None) -> int:
    """Validate plugin metadata consistency."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_root", nargs="?", default=None)
    parser.add_argument(
        "--base-ref",
        default=None,
        help="git ref to compare versions against (enables the version-increment check)",
    )
    parser.add_argument(
        "--allow-no-bump",
        action="store_true",
        help="skip the version-increment check (set by CI from the no-version-bump label)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove each checker still detects what it exists to detect, then exit",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    repo_root = Path(args.repo_root) if args.repo_root else Path(__file__).parent.parent.parent

    plugins_to_check = scan_plugins_directory(repo_root / "plugins")
    if not plugins_to_check:
        print(f"No plugins found in {repo_root / 'plugins'}")
        return 1

    print(f"Checking {len(plugins_to_check)} plugin(s)")

    base_ref = None if args.allow_no_bump else args.base_ref
    if args.allow_no_bump and args.base_ref:
        print("version-increment check skipped: no-version-bump label is applied")
    result = validate_plugins(plugins_to_check, repo_root, base_ref)
    report(result)

    # A full scan that resolved zero references means the extractor broke, not that
    # every plugin is clean. Reporting success there is the exact failure this guards.
    if result.refs_checked == 0:
        print("\n✗ reference extractor matched nothing across the whole repo — it is broken")
        return 1

    # Same failure, different scan: a clean result here means nothing if the walk found
    # no files to read, so prove discovery worked before trusting it.
    if result.paths_scanned == 0:
        print("\n✗ hardcoded-path scan matched no files at all — discovery is broken")
        return 1

    if result.python_docs_scanned == 0:
        print("\n✗ legacy-python scan read no files at all — discovery is broken")
        return 1

    errors = [f for f in result.findings if f.severity == ERROR]
    if errors:
        return 1

    print(
        f"\n✓ no errors ({result.refs_checked} references resolved, "
        f"{result.paths_scanned} files scanned for hardcoded paths, "
        f"{result.python_docs_scanned} for legacy python invocations)"
    )
    return 0


# ----------------------------------------------------------------------- self-test


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _build_demo(root: Path, name: str = "demo") -> Path:
    """A minimal well-formed plugin that every checker should accept."""
    plugin = root / "plugins" / name
    _write(
        plugin / ".claude-plugin" / "plugin.json",
        json.dumps(
            {
                "name": name,
                "version": "1.0.0",
                "description": "A demo plugin.",
            }
        ),
    )
    _write(plugin / "README.md", f"# {name}\n")
    _write(
        plugin / "skills" / name / "SKILL.md",
        "---\nname: demo\ndescription: Demo.\nallowed-tools: Read Grep\n---\n\n"
        "## When to Use\n\nAlways.\n\n## When NOT to Use\n\nNever.\n\n"
        "See [detail](references/detail.md).\n",
    )
    _write(plugin / "skills" / name / "references" / "detail.md", "# detail\n")
    _write(
        root / ".claude-plugin" / "marketplace.json",
        json.dumps(
            {
                "plugins": [
                    {
                        "name": name,
                        "version": "1.0.0",
                        "description": "A demo plugin.",
                        "source": f"./plugins/{name}",
                    }
                ]
            }
        ),
    )
    _write(root / "README.md", f"| [{name}](plugins/{name}/) | demo |\n")
    _write(root / "CODEOWNERS", f"/plugins/{name}/ @someone @dguido\n")
    return plugin


def _errors_for(root: Path, name: str = "demo") -> list[str]:
    result = validate_plugins({name}, root)
    return [str(f) for f in result.findings if f.severity == ERROR]


def _warnings_for(root: Path, name: str = "demo") -> list[str]:
    result = validate_plugins({name}, root)
    return [str(f) for f in result.findings if f.severity == WARNING]


def _check(ran: list[str], label: str, condition: bool) -> None:
    ran.append(label)
    if not condition:
        raise AssertionError(f"self-test failed: {label}")


def _self_test_errors(ran: list[str]) -> None:
    """Each error-level checker rejects a known-bad fixture."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _check(ran, "clean fixture produces no errors", not _errors_for(root))
        _check(ran, "clean fixture produces no warnings", not _warnings_for(root))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        (plugin / "README.md").unlink()
        _check(ran, "missing plugin README", any("README.md" in e for e in _errors_for(root)))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(plugin / "commands" / "go.md", "# no frontmatter\n")
        _check(
            ran,
            "command without frontmatter",
            any("no YAML frontmatter" in e for e in _errors_for(root)),
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(plugin / "commands" / "go.md", "---\nargument-hint: x\n---\n")
        _check(
            ran,
            "command without description",
            any("no 'description:'" in e for e in _errors_for(root)),
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(plugin / "commands" / "go.md", "---\ndescription: Go.\ntools:\n  - Read\n---\n")
        _check(
            ran,
            "command using tools:",
            any("commands must use 'allowed-tools:'" in e for e in _errors_for(root)),
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(plugin / "commands" / "go.md", "---\ndescription: Go.\nallowed-tools: Read\n---\n")
        _check(ran, "a valid command is accepted", not _errors_for(root))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        shutil.rmtree(plugin / "skills")
        _check(
            ran,
            "plugin with no entry point",
            any("exposes no entry point" in e for e in _errors_for(root)),
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        shutil.rmtree(plugin / "skills")
        _write(plugin / "commands" / "go.md", "---\ndescription: Go.\nallowed-tools: Read\n---\n")
        _check(
            ran,
            "commands alone satisfy the entry-point rule",
            not any("exposes no entry point" in e for e in _errors_for(root)),
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(plugin / "agents" / "worker.md", "---\nname: worker\nallowed-tools: Read\n---\n")
        _check(
            ran,
            "agent using allowed-tools",
            any("must use 'tools:'" in e for e in _errors_for(root)),
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(plugin / "agents" / "worker.md", "---\nname: worker\ntools:\n  - Read\n---\n")
        _check(ran, "agent using tools: accepted", not _errors_for(root))
        # A presentation sidecar under skills/*/agents/ must not be mistaken for one.
        _write(plugin / "skills" / "demo" / "agents" / "openai.yaml", "color: blue\n")
        _check(ran, "skills/*/agents sidecar ignored", not _errors_for(root))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(plugin / "agents" / "worker.md", "---\nname: worker\ntools:\n  - Read\n---\n")
        skill = plugin / "skills" / "demo" / "SKILL.md"
        skill.write_text(skill.read_text() + '\nUse subagent_type="worker" here.\n')
        _check(
            ran,
            "bare subagent_type",
            any("not namespaced" in e for e in _errors_for(root)),
        )
        skill.write_text(skill.read_text().replace('"worker"', '"demo:worker"'))
        _check(ran, "namespaced subagent_type accepted", not _errors_for(root))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(plugin / "agents" / "w.md", "---\nname: w\ntools:\n  - Read\n---\n")
        skill = plugin / "skills" / "demo" / "SKILL.md"
        skill.write_text(skill.read_text() + '\nsubagent_type="Explore" is builtin.\n')
        _check(ran, "builtin subagent_type accepted", not _errors_for(root))

    with tempfile.TemporaryDirectory() as tmp:
        # `other` is built first so the second _build_demo leaves the marketplace, README
        # and CODEOWNERS describing `demo`, which is the only plugin validated here.
        root = Path(tmp)
        other = _build_demo(root, "other")
        _write(other / "agents" / "helper.md", "---\nname: helper\ntools:\n  - Read\n---\n")
        plugin = _build_demo(root)
        skill = plugin / "skills" / "demo" / "SKILL.md"
        skill.write_text(skill.read_text() + '\nUse subagent_type="helper" here.\n')
        _check(
            ran,
            "bare subagent_type borrowed from another plugin",
            any("other:helper" in e for e in _errors_for(root)),
        )
        skill.write_text(skill.read_text().replace('"helper"', '"other:helper"'))
        _check(ran, "cross-plugin namespaced subagent_type accepted", not _errors_for(root))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        skill = plugin / "skills" / "demo" / "SKILL.md"
        skill.write_text(skill.read_text() + '\nUse subagent_type="ghost" here.\n')
        _check(
            ran,
            "subagent_type naming no agent at all",
            any("names no agent in this repo" in e for e in _errors_for(root)),
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(
            plugin / "commands" / "audit.md",
            "---\nname: audit\ndescription: Audit it\ntools: Read\n---\n\nRun it.\n",
        )
        _check(
            ran,
            "command using tools:",
            any("commands must use 'allowed-tools:'" in e for e in _errors_for(root)),
        )
        _write(plugin / "commands" / "audit.md", "Run it.\n")
        _check(
            ran,
            "command with no frontmatter",
            any("command file has no YAML frontmatter" in e for e in _errors_for(root)),
        )
        _write(
            plugin / "commands" / "audit.md",
            "---\nname: audit\nallowed-tools: Read\n---\n\nRun it.\n",
        )
        _check(
            ran,
            "command with no description",
            any("command frontmatter has no 'description:'" in e for e in _errors_for(root)),
        )
        _write(
            plugin / "commands" / "audit.md",
            "---\nname: audit\ndescription: Audit it\nallowed-tools: Read\n---\n\nRun it.\n",
        )
        _check(ran, "command using allowed-tools: accepted", not _errors_for(root))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(plugin / "scripts" / "run.sh", "#!/usr/bin/env bash\ncd /Users/Someone/cc/skills\n")
        _check(
            ran,
            "hardcoded /Users path",
            any("hardcodes an absolute user path" in e for e in _errors_for(root)),
        )

    with tempfile.TemporaryDirectory() as tmp:
        # The case the inherited pattern missed. macOS account names are lowercase by
        # convention, so this is the form a real leaked path almost always takes.
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(plugin / "scripts" / "run.sh", "#!/usr/bin/env bash\ncd /Users/alice/cc/skills\n")
        _check(
            ran,
            "hardcoded lowercase /Users path",
            any("hardcodes an absolute user path" in e for e in _errors_for(root)),
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(plugin / "skills" / "demo" / "shared.md", "Drop it in /Users/Shared/build.\n")
        _check(ran, "macOS shared directory is not a personal path", not _errors_for(root))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(plugin / "skills" / "demo" / "setup.md", "Run from /home/alice/work.\n")
        _check(
            ran,
            "hardcoded /home path",
            any("hardcodes an absolute user path" in e for e in _errors_for(root)),
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        shim_suite = plugin / "hooks" / "shims" / "gh-shim.bats"
        _write(shim_suite, "@test 'x' {\n  cd /home/user/repo\n}\n")
        _check(ran, "shim suite exempt from path scan", not _errors_for(root))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _write(plugin / "skills" / "demo" / "devcontainer.md", "Workspace is /home/vscode/app.\n")
        _check(ran, "container image path is not a personal path", not _errors_for(root))

    # The refused forms must fire; the compliant and exempt forms must not.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        doc = plugin / "skills" / "demo" / "howto.md"

        for label, body in (
            ("bare interpreter on a script", "Run `python3 tools/x.py` first.\n"),
            ("bare interpreter behind a flag", "```bash\npython3 -u tools/x.py\n```\n"),
            ("bare interpreter, flags only", "```bash\npython3 --version\n```\n"),
            ("pip install", "```bash\npip install requests\n```\n"),
            ("uv pip install", "```bash\nuv pip install requests\n```\n"),
            ("uv pip non-install subcommand", "```bash\nuv pip list\n```\n"),
            ("python -m pip", "```bash\npython -m pip download requests\n```\n"),
            ("pip non-install subcommand", "```bash\npip freeze\n```\n"),
            ("pipx", "```bash\npipx install detect-secrets\n```\n"),
            ("value-taking flag before the script", "```bash\npython3 -W ignore harness.py\n```\n"),
            ("long flag before the script", "```bash\npython3 --verbose tool.py\n```\n"),
            (
                "allow-marker with no reason",
                "```bash\n# allow-legacy-python:\npip install requests\n```\n",
            ),
            ("script named by a variable", '```bash\npython3 "$MERGE" out.sarif\n```\n'),
            (
                "compliant match masking a later violation",
                "| a | `uv run python a.py` | `python3 b.py` |\n",
            ),
            (
                "prohibition after the command, not before",
                "Use `pip install semgrep` instead of the tarball.\n",
            ),
            (
                "uv pip with a flag that is not tool-managed",
                "```bash\nuv pip install --target-dir /x foo\n```\n",
            ),
            ("usage string in a .py file", None),
            (
                "marker scope ends at a blank line",
                "```bash\n# allow-legacy-python: x\n\npip install requests\n```\n",
            ),
        ):
            if body is None:
                _write(doc, "clean\n")
                script = plugin / "skills" / "demo" / "scripts" / "t.py"
                _write(script, '"""Usage: python3 t.py"""\n')
                _check(
                    ran,
                    f"legacy python invocation: {label}",
                    any("uv run" in e for e in _errors_for(root)),
                )
                script.unlink()
                continue
            _write(doc, body)
            _check(
                ran,
                f"legacy python invocation: {label}",
                any("uv add" in e or "uv run" in e or "uv tool" in e for e in _errors_for(root)),
            )

        for label, body in (
            ("uv run --no-project", "```bash\nuv run --no-project tools/x.py\n```\n"),
            (
                "uv run --no-project python",
                "```bash\nuv run --no-project python infra/helper.py b\n```\n",
            ),
            ("python3 -c", "```bash\npython3 -c 'print(1)'\n```\n"),
            ("python3 -m with a module", "```bash\npython3 -m json.tool data.json\n```\n"),
            ("uv pip with --directory", "```bash\nuv pip install --directory /tmp requests\n```\n"),
            ("uv pip with short -t", "```bash\nuv pip install -t /tmp requests\n```\n"),
            (
                "uv pip with the flag after the package",
                "```bash\nuv pip install foo -t /tmp\n```\n",
            ),
            ("prohibition before the command", "Do NOT use `pip freeze` here.\n"),
            ("prose forbidding the command", "Do NOT run `pip install` here.\n"),
            ("dockerfile fence", "```dockerfile\nRUN pip install requests\n```\n"),
            (
                "allow-marker",
                "```bash\n# allow-legacy-python: in a container\npip install requests\n```\n",
            ),
        ):
            _write(doc, body)
            _check(ran, f"legal python invocation accepted: {label}", not _errors_for(root))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        skill = plugin / "skills" / "demo" / "SKILL.md"
        _write(skill, "---\nname: demo\ndescription: Use when: parsing files\n---\n\nBody\n")
        _check(
            ran,
            "unquoted description with a colon",
            any("does not parse" in e for e in _errors_for(root)),
        )
        _write(skill, "---\nname: demo\ndescription: Handles a # sign\n---\n\nBody\n")
        _check(
            ran,
            "unquoted description with a comment marker",
            any("does not parse" in e for e in _errors_for(root)),
        )
        _write(skill, '---\nname: demo\ndescription: "Use when: parsing files"\n---\n\nBody\n')
        _check(ran, "quoted description with a colon accepted", not _errors_for(root))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _build_demo(root, "Not_Kebab")
        _check(
            ran,
            "non-kebab plugin name",
            any("kebab-case" in e for e in _errors_for(root, "Not_Kebab")),
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        data = json.loads((plugin / ".claude-plugin" / "plugin.json").read_text())
        data["version"] = "2.0.0"
        _write(plugin / ".claude-plugin" / "plugin.json", json.dumps(data))
        _check(
            ran,
            "version parity mismatch",
            any("version mismatch" in e for e in _errors_for(root)),
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        data = json.loads((plugin / ".claude-plugin" / "plugin.json").read_text())
        data["version"] = "not-a-version"
        _write(plugin / ".claude-plugin" / "plugin.json", json.dumps(data))
        _check(ran, "non-semver version", any("MAJOR.MINOR.PATCH" in e for e in _errors_for(root)))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _build_demo(root)
        _write(root / ".codex" / "skills" / "demo", "symlink stand-in\n")
        _check(ran, "forbidden .codex sidecar", any(".codex" in e for e in _errors_for(root)))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _build_demo(root)
        _write(root / ".opencode" / "plugin.json", "{}\n")
        _check(ran, "forbidden .opencode sidecar", any(".opencode" in e for e in _errors_for(root)))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _build_demo(root)
        _write(root / "CODEOWNERS", "# nobody\n")
        _check(ran, "missing CODEOWNERS entry", any("CODEOWNERS" in e for e in _errors_for(root)))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _build_demo(root)
        _write(root / "README.md", "# nothing here\n")
        _check(ran, "missing README row", any("README.md" in e for e in _errors_for(root)))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _build_demo(root)
        _write(root / ".claude-plugin" / "marketplace.json", json.dumps({"plugins": []}))
        _check(
            ran,
            "missing marketplace entry",
            any("marketplace.json" in e for e in _errors_for(root)),
        )


def _self_test_warnings(ran: list[str]) -> None:
    """Each warning-level checker fires on a known-bad fixture, and does not block."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        skill = plugin / "skills" / "demo" / "SKILL.md"
        skill.write_text(skill.read_text() + "\n" + ("filler\n" * (SKILL_LINE_LIMIT + 5)))
        _check(ran, "oversize SKILL.md", any("over the 500" in w for w in _warnings_for(root)))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        (plugin / "skills" / "demo" / "references" / "detail.md").unlink()
        _check(
            ran,
            "dangling reference",
            any("does not resolve" in w for w in _warnings_for(root)),
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        skill = plugin / "skills" / "demo" / "SKILL.md"
        skill.write_text(
            skill.read_text()
            + "\nExample layout:\n\n```\nreferences/imaginary.md\n```\n"
            + "\nInline `references/also-imaginary.md` too.\n"
        )
        _check(
            ran,
            "illustrative paths in code blocks ignored",
            not any("imaginary" in w for w in _warnings_for(root)),
        )


def _self_test_guards(ran: list[str]) -> None:
    """The anti-vacuity guards themselves."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        _, checked = validate_reference_links(plugin)
        _check(ran, "reference extractor counts a real reference", checked > 0)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _build_demo(root)
        # Remove the plugin directory itself, not just its files: leaving the
        # directory means scan_plugins_directory still returns {"demo"} and main()
        # exits non-zero for a missing README, so the guard this names would go
        # untested while the assertion passed.
        shutil.rmtree(root / "plugins" / "demo")
        assert not scan_plugins_directory(root / "plugins"), "fixture did not empty plugins/"
        with contextlib.redirect_stdout(io.StringIO()):
            exit_code = main([str(root)])
        _check(ran, "scan finding no plugins returns non-zero", exit_code != 0)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plugin = _build_demo(root)
        (plugin / ".codex-plugin").mkdir()
        _check(
            ran,
            "per-plugin .codex-plugin sidecar",
            any(".codex-plugin" in e for e in _errors_for(root)),
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _build_demo(root)
        _write(root / ".agents" / "skills" / "demo.md", "sidecar\n")
        _check(ran, "forbidden .agents tree", any(".agents" in e for e in _errors_for(root)))

    _check(ran, "makefile and CI pin the same ruff", _check_ruff_parity() is None)

    # The dependabot lockfile rule, including the case where the checker itself
    # parses nothing — the failure mode the rule exists to prevent, one level up.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        cfg = root / ".github" / "dependabot.yml"
        body = (
            "version: 2\nupdates:\n  - package-ecosystem: uv\n    directories:\n"
            "      - /plugins/locked\n      - /plugins/unlocked\n"
            "    schedule:\n      interval: weekly\n"
            "  - package-ecosystem: github-actions\n    directory: /\n"
            "    schedule:\n      interval: weekly\n"
        )
        _write(cfg, body)
        _write(root / "plugins" / "locked" / "uv.lock", "version = 1\n")
        (root / "plugins" / "unlocked").mkdir(parents=True)
        errs = check_dependabot_lockfiles(root)
        _check(ran, "missing uv.lock is reported", any("unlocked" in e for e in errs))
        _check(ran, "present uv.lock is accepted", not any("/plugins/locked" in e for e in errs))

        _write(cfg, body.replace("      - /plugins/locked\n      - /plugins/unlocked\n", ""))
        _check(
            ran,
            "uv block parsing nothing is an error",
            any("inspected nothing" in e for e in check_dependabot_lockfiles(root)),
        )

    # The version check must apply only to plugins the branch touched. Without this
    # scoping it demanded a bump from every plugin in the repo on every PR — which is
    # how it behaved the first time it ran in CI, before this assertion existed.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _build_demo(root, "touched")
        _build_demo(root, "untouched")
        _write(
            root / ".claude-plugin" / "marketplace.json",
            json.dumps(
                {
                    "plugins": [
                        {
                            "name": n,
                            "version": "1.0.0",
                            "description": "A demo plugin.",
                            "source": f"./plugins/{n}",
                        }
                        for n in ("touched", "untouched")
                    ]
                }
            ),
        )
        _write(
            root / "README.md",
            "| [touched](plugins/touched/) | x |\n| [untouched](plugins/untouched/) | x |\n",
        )
        _write(
            root / "CODEOWNERS",
            "/plugins/touched/ @a @dguido\n/plugins/untouched/ @a @dguido\n",
        )
        for cmd in (
            ["git", "init", "-q"],
            ["git", "config", "user.email", "t@example.com"],
            ["git", "config", "user.name", "t"],
            ["git", "add", "-A"],
            ["git", "commit", "-q", "-m", "base"],
        ):
            subprocess.run(cmd, cwd=root, check=True, capture_output=True)
        base = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True
        ).stdout.strip()

        skill = root / "plugins" / "touched" / "skills" / "touched" / "SKILL.md"
        skill.write_text(skill.read_text() + "\nA substantive change.\n")
        subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "change"], cwd=root, check=True, capture_output=True
        )

        scope = changed_plugins(root, base)
        _check(ran, "changed-plugin scope finds the touched plugin", scope == {"touched"})

        res = validate_plugins({"touched", "untouched"}, root, base)
        msgs = [str(f) for f in res.findings if f.severity == ERROR]
        _check(ran, "unbumped touched plugin errors", any("not greater than" in m for m in msgs))
        _check(
            ran,
            "untouched plugin is not asked to bump",
            not any(m.startswith("untouched") and "not greater" in m for m in msgs),
        )


def _check_ruff_parity() -> str | None:
    """The Makefile claims to run what CI runs; nothing else enforces that.

    CI reaches ruff through pre-commit, so the authority is the `ruff-pre-commit`
    rev, not a `ruff-action` input. The rev is matched off its own repo line: a bare
    `rev:` search picks up whichever hook repo happens to be listed first, which is
    how this check passed against the wrong version the first time it ran.
    """
    repo_root = Path(__file__).parent.parent.parent
    makefile = repo_root / "Makefile"
    precommit = repo_root / ".pre-commit-config.yaml"
    if not makefile.exists():
        return "Makefile is missing, so ruff parity cannot be checked"
    if not precommit.exists():
        return ".pre-commit-config.yaml is missing, so ruff parity cannot be checked"

    mk = re.search(r"^RUFF_VERSION\s*:?=\s*(\S+)", makefile.read_text(), re.MULTILINE)
    if not mk:
        return "Makefile has no RUFF_VERSION"

    pinned = re.search(
        r"repo:\s*https://github\.com/astral-sh/ruff-pre-commit\s*\n\s*rev:\s*v?([\d.]+)",
        precommit.read_text(),
    )
    if not pinned:
        return ".pre-commit-config.yaml has no pinned astral-sh/ruff-pre-commit rev"
    if pinned.group(1) != mk.group(1):
        return (
            f"Makefile pins ruff {mk.group(1)}, .pre-commit-config.yaml pins "
            f"{pinned.group(1)} — `make lint` would grade against a different version "
            f"than CI"
        )
    return None


def self_test() -> int:
    """Prove each checker still detects what it exists to detect."""
    ran: list[str] = []
    try:
        _self_test_errors(ran)
        _self_test_warnings(ran)
        _self_test_guards(ran)
    except AssertionError as exc:
        print(f"✗ {exc}")
        print(f"  ({len(ran)} assertions ran before the failure)")
        return 1

    # The self-test is itself a checker. An early return or a bad merge that drops the
    # fixture block must fail here rather than print success having run nothing.
    if len(ran) < SELF_TEST_MINIMUM:
        print(
            f"✗ self-test ran only {len(ran)} assertions, below the floor of "
            f"{SELF_TEST_MINIMUM} — the fixture block was probably truncated"
        )
        return 1

    print(f"✓ validator self-test passed ({len(ran)} assertions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
