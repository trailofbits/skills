# Contributing Skills

## Resources

**Official Anthropic documentation (always check these first):**

- [Claude Code Plugins](https://code.claude.com/docs/en/plugins)
- [Agent Skills](https://code.claude.com/docs/en/skills)
- [Best Practices](https://code.claude.com/docs/en/skills#best-practices)
- [Skill Authoring Best Practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices) — progressive disclosure, degrees of freedom, workflow checklists
- [The Complete Guide to Building Skills](https://resources.anthropic.com/hubfs/The-Complete-Guide-to-Building-Skill-for-Claude.pdf) ([text](https://gist.github.com/liskl/269ae33835ab4bfdd6140f0beb909873)) — evaluation-driven development, iterative testing

**Reference skills** - learn by example at different complexity levels:

| Complexity | Skill | What It Demonstrates |
|------------|-------|---------------------|
| **Basic** | [git-cleanup](plugins/git-cleanup/) | Single self-contained SKILL.md, `allowed-tools` scoping |
| **Intermediate** | [constant-time-analysis](plugins/constant-time-analysis/) | Python package, references/, language-specific docs |
| **Advanced** | [culture-index](plugins/culture-index/) | Scripts, workflows/, templates/, PDF extraction, multiple entry points |

**When in doubt, copy one of these and adapt it.**

**Deep dives on skill authoring:**
- [Claude Skills Deep Dive](https://leehanchung.github.io/blogs/2025/10/26/claude-skills-deep-dive/) - Comprehensive analysis of skill architecture

**Example plugins worth studying:**
- [superpowers](https://github.com/obra/superpowers) - Advanced workflow patterns, TDD enforcement, multi-skill orchestration
- [compound-engineering-plugin](https://github.com/EveryInc/compound-engineering-plugin) - Production plugin structure
- [getsentry/skills](https://github.com/getsentry/skills) — Production Sentry skills; `security-review` is a standout routing + progressive disclosure example

**For Claude:** Use the `claude-code-guide` subagent for questions about official Claude
Code behaviour that you cannot answer from this repository — it has access to the
official documentation. For anything answerable by reading the files here, read them;
delegating a lookup you could do directly costs a round trip and buys nothing.

## Technical Reference

### Codex Compatibility

This repository uses Claude plugin marketplace metadata as the canonical source for both Claude Code and Codex. Codex supports `.claude-plugin/marketplace.json` and `plugins/<name>/.claude-plugin/plugin.json` directly, so do not add duplicate Codex-only sidecar metadata.

Rules:

- Do not add `.agents/plugins/marketplace.json`, `.codex/`, `.opencode/`, or
  `plugins/<name>/.codex-plugin/`. The validator enforces this — sidecars drift out of
  sync with the canonical metadata, which is why the last set was removed in #173.
- Keep plugin components at the plugin root using Codex-compatible default paths: `skills/`, `hooks/hooks.json`, `.mcp.json`, and `.app.json`.
- If a plugin needs MCP configuration, put it in `.mcp.json` at the plugin root rather than embedding an object in `.claude-plugin/plugin.json`.
- Both loadability checks run in CI, not in `make check` — they need the Claude Code
  and Codex CLIs installed, which is not a reasonable local prerequisite. Run them by
  hand if you are changing plugin metadata:

  ```sh
  python3 .github/scripts/check_claude_loadability.py
  python3 .github/scripts/check_codex_loadability.py
  ```

  If one fails, update the canonical Claude marketplace or the plugin root components
  so Codex can load them through Claude marketplace compatibility — do not add a
  sidecar to work around it.

### Plugin Structure

```
plugins/
  <plugin-name>/
    .claude-plugin/
      plugin.json         # Plugin metadata (name, version, description, author)
    commands/             # Optional: slash commands
    agents/               # Optional: autonomous agents
    workflows/            # Optional: dynamic workflows (*.js), ships as /<plugin>:<workflow>
    evals/                # Optional: `claude plugin eval` cases + graders
    skills/               # Optional: knowledge/guidance
      <skill-name>/
        SKILL.md          # Entry point with frontmatter
        references/       # Optional: detailed docs
        workflows/        # Optional: step-by-step guides (prose, not scripts)
        scripts/          # Optional: utility scripts
    hooks/                # Optional: event hooks
    tests/                # Optional: run_*.sh suites (CI runs these — keep them free)
    README.md             # Plugin documentation
```

**Important**: Component directories (`skills/`, `commands/`, `agents/`, `hooks/`) must be at the plugin root, NOT inside `.claude-plugin/`. Only `plugin.json` belongs in `.claude-plugin/`.

**Two different `workflows/`.** A **dynamic workflow** is a JavaScript file at the *plugin
root* under `workflows/`; it exports a `meta` object, orchestrates subagents in code, and
ships through the marketplace as `/<plugin-name>:<workflow-name>` (from `meta.name`, not the
filename). The older `skills/<skill>/workflows/` holds prose step-by-step guides. If a
SKILL.md has "Phase 1", "for each finding", or "repeat until" sections, the plan belongs in
a script at the plugin root, not in prose. See `plugins/variant-analysis/workflows/` for a
worked example, and note that `${CLAUDE_PLUGIN_ROOT}` is **not** available inside a workflow
script — it is not a hook, MCP, or LSP subprocess.

### Frontmatter

Skills and commands declare tools with `allowed-tools`, space-delimited:

```yaml
---
name: skill-name              # kebab-case, max 64 chars
description: "Third-person description of what it does and when to use it"
allowed-tools: Read Grep      # Optional: restrict to needed tools only
---
```

Agent files under `agents/` use a different key — `tools`, as a YAML list:

```yaml
---
name: agent-name
description: "What this agent does and when the coordinator should dispatch it"
tools:
  - Read
  - Grep
---
```

The keys are inverted between the two file types, and the loader silently ignores
the wrong one — the frontmatter still parses, the restriction simply does not apply
and the agent inherits everything. The validator checks this.

### Naming Conventions

- **kebab-case**: `constant-time-analysis`, not `constantTimeAnalysis`
- **Gerund form preferred**: `analyzing-contracts`, `processing-pdfs` (not `contract-analyzer`, `pdf-processor`)
- **Avoid vague names**: `helper`, `utils`, `tools`, `misc`
- **Avoid reserved words**: `anthropic`, `claude`

### Path Handling

- Use `{baseDir}` for paths, **never hardcode** absolute paths
- Use forward slashes (`/`) even on Windows

### Python Scripts

When skills include Python scripts with dependencies:

1. **Use PEP 723 inline metadata** - Declare dependencies in the script header:
   ```python
   # /// script
   # requires-python = ">=3.11"
   # dependencies = ["requests>=2.28", "pydantic>=2.0"]
   # ///
   ```

2. **Use `uv run`** - Enables automatic dependency resolution:
   ```bash
   uv run {baseDir}/scripts/process.py input.pdf
   ```

3. **Include `pyproject.toml`** - Keep in `scripts/` for development tooling (ruff, etc.)

4. **Document system dependencies** - List non-Python deps (poppler, tesseract) in workflows with platform-specific install commands

### Hooks

PreToolUse hooks run on every Bash command—performance is critical:

- **Prefer shell + jq** over Python—interpreter startup (Python + tree-sitter) adds noticeable latency
- **Fast-fail early** - exit 0 immediately for non-matching commands so most invocations are instant
- **Favor regex over AST parsing** - accept rare false positives if performance gain is significant and Claude can rephrase
- **Anticipate false positive patterns** - diagnostic commands (`which python`), search tools (`grep python`), and filenames (`cat python.txt`) shouldn't trigger interception
- **Document tradeoffs** in PR descriptions so reviewers understand deliberate design choices

## Quality Standards

These are Trail of Bits house standards on top of Anthropic's requirements.

### Description Quality

Your skill competes with 100+ others. The description must trigger correctly.

- **Third-person voice**: "Analyzes X" not "I help with X"
- **Include triggers**: "Use when auditing Solidity" not just "Smart contract tool"
- **Be specific**: "Detects reentrancy vulnerabilities" not "Helps with security"

### Value-Add

Skills should provide guidance Claude doesn't already have, not duplicate reference material.

- **Behavioral guidance over reference dumps** - Don't paste entire specs; teach when and how to look things up
- **Explain WHY, not just WHAT** - Include trade-offs, decision criteria, judgment calls
- **Document anti-patterns WITH explanations** - Say why something is wrong, not just that it's wrong

**Example**: The DWARF skill doesn't include the full DWARF spec. It teaches Claude how to use `dwarfdump`, `readelf`, and `pyelftools` to look up what it needs, plus judgment about when each tool is appropriate.

### Scope Boundaries

Prescriptiveness should match task risk:
- **Strict for fragile tasks** - Security audits, crypto implementations, compliance checks need rigid step-by-step enforcement
- **Flexible for variable tasks** - Code exploration, documentation, refactoring can offer options and judgment calls

### Security Skills

For audit/security skills, also include:

```markdown
## Rationalizations to Reject
[Common shortcuts or rationalizations that lead to missed findings]
```

### Content Organization

- Keep SKILL.md **under 500 lines** - split into `references/`, `workflows/`
- Use **progressive disclosure** - quick start first, details in linked files
- **One level deep** - SKILL.md links to files, files don't chain to more files

Note: Directory depth is fine (`references/guides/topic.md`). Reference *chains* are not (`SKILL.md → file1.md → file2.md` where file1 references file2). The problem is chained references, not nested folders.

### Progressive Disclosure Pattern

```markdown
## Quick Start
[Core instructions here]

## Advanced Usage
See [ADVANCED.md](references/ADVANCED.md) for detailed patterns.

## API Reference
See [API.md](references/API.md) for complete method documentation.
```

## Before committing

```sh
make check
```

That runs the validator self-test, ruff, shellcheck, shfmt, bats, the plugin
Python suites, and the plugin validator.

It is most of CI, not all of it. Three things run only in CI, so a green `make check`
is strong evidence and not a guarantee:

- **the two loadability checks**, which need the Claude Code and Codex CLIs installed
- **the rest of pre-commit** — actionlint, zizmor, check-yaml/json/toml,
  detect-private-key, end-of-file-fixer, trailing-whitespace. Run `prek run -a` (or
  `pre-commit run -a`) to cover those locally.
- **the version-increment check**, which needs a base ref to diff against and so has
  no meaning outside a PR.
- **`make shell-suites`**, which is a target but not part of `check`: it still fails on a
  machine with the `modern-python` plugin installed, though no longer for the reason
  #207 describes. The `python3 -` interception that broke zeroize-audit is gone as of
  modern-python 1.6.0. What remains is `plugins/variant-analysis/tests/` invoking
  `python3 <script>.py`, which the shim intercepts *by design* — a bare script run is
  exactly what `uv run python` replaces. That one is variant-analysis's to fix. With no
  shim on PATH the whole target passes.

Both scan every plugin; the validator is not scoped down in CI. Only the
version-increment check is limited to the plugins a branch touched, and it is the one
check CI runs that local cannot. Do not add a scoping flag to the local run — the
zero-reference guard only arms on a full scan.

`make fix` applies the formatting CI would otherwise reject. `make help` lists the rest.

### What the validator enforces, so you do not have to

Each of these fails the build. There is no value in checking any of it by hand:

- `plugin.json` exists, parses, and has `name`, `description`, and a semver `version`
- `plugin.json`'s `name` equals the plugin's directory name
- Plugin directory name is kebab-case and ≤64 characters
- Plugin has a `README.md` (exact case — `Readme.md` passes on macOS and fails on CI)
- Registered in `.claude-plugin/marketplace.json`, the root `README.md`, and `CODEOWNERS`
- The marketplace entry's `source` is exactly `./plugins/<name>` and its `description`
  matches `plugin.json`
- `version` matches between `plugin.json` and `marketplace.json`, **and** increases when
  you change a plugin — clients only pull an update when the number goes up, so a fix
  shipped without a bump reaches nobody. Apply the `no-version-bump` label for
  typo-only changes and CI skips the check.
- `SKILL.md` has frontmatter, and no top-level value is an unquoted YAML scalar
  containing `: ` or ` #`. Either one makes the whole block unparseable, and the
  loader then drops *every* field and loads the skill with empty metadata — so a
  skill whose `description:` line reads perfectly well ships with no description
  and never triggers. Quote any description containing a colon.
- Agent files use `tools:`; skills and commands use `allowed-tools:`
- `subagent_type` values are namespaced `<plugin>:<agent>` — a bare name is
  unregistered and the dispatch fails at runtime, whether it names this plugin's own
  agent, another plugin's, or nothing at all
- No hardcoded `/Users/…` or `/home/…` paths, in any `.md`, `.py`, `.json`, `.sh`,
  `.bats`, `.yml` or `.toml` file under `plugins/`. `*-shim.bats` is exempt because
  those fixtures need literal paths, and `/path/to` and `/home/vscode` are treated as
  placeholders rather than somebody's home directory.
- No `.codex/`, `.opencode/`, `.agents/`, or `plugins/*/.codex-plugin/` sidecars
- A committed `uv.lock` for every uv directory listed in `.github/dependabot.yml`
- Both loadability checks pass under the real Claude Code and Codex CLIs

Two more are reported as **warnings**, so they will not stop a merge and do still
need your eye: `SKILL.md` over 500 lines, and references that do not resolve. A dangling
`references/setup.md` link 404s for every user of the skill, and CI will not stop you
shipping it.

### What no tool can check — this is the part that needs you

- **The description actually triggers.** Third person, names the situation, uses the
  words a user would actually type. This is the single highest-leverage line in a skill:
  a skill that never triggers may as well not exist.
- **Examples are concrete** — real input, real output, not a shape.
- **It explains why**, including the trade-off and when not to do the thing.
- **The version bump is the right size.** The validator confirms the number went up;
  only you know whether the change was substantive. `MAJOR.MINOR.PATCH`, MINOR for
  features, PATCH for fixes.
- **CODEOWNERS lists the right people**: `/plugins/<name>/ @you @dguido`. Find your
  username with `gh api user --jq .login`.
- **The entry is in the right section** of the root `README.md`. The validator only
  checks that the plugin appears *somewhere* in that file, so a row appended to
  whichever table you scrolled to first passes CI and stays filed under the wrong
  category indefinitely.

## Scripts a plugin ships

**A checker that inspects zero items must fail, not pass.** This is the single most
expensive class of bug in a repo like this one, because it is invisible on every read
and in every review. Real examples, all of which were green for months:

- a validator using `grep -oP` (rejected by BSD grep) with stderr sent to `/dev/null`,
  so it printed "all valid" on every run without ever matching anything
- an eval grader that judged the response text rather than the artifact, so a run that
  skipped the actual work still scored a pass
- a citation gate that validated only the citations that were present, so a document
  with zero citations passed

If your script counts, filters, or matches, make it exit non-zero when the count is
zero, and give it a fixture proving it still detects its target. The validator's
`--self-test` is the worked example: it builds a known-bad plugin in a tempdir and
asserts each checker rejects it, and it fails if it runs fewer assertions than it
should — because the self-test is itself a checker.

Otherwise: `set -euo pipefail`, POSIX ERE rather than PCRE (`grep -oP` is not portable
to macOS), and never send a tool's stderr to `/dev/null` unless you have handled the
failure it would have reported.

## Working effectively in this repo

- **Effort.** Start at `xhigh` for coding and agentic work and `high` elsewhere, then
  sweep downward on your own evals — `low` and `medium` are unusually strong on current
  models and often match what an older model needed `xhigh` to do. Defaults carried over
  from a previous model are rarely the right setting.
- **Subagents.** Delegate work that is large and genuinely independent — a wide
  multi-file investigation, several unrelated tracks. Do not spawn subagents to verify
  or double-check your own work, and do not split one modest job across several: each
  one re-establishes context, re-explores, and reports back, and then you re-read the
  report. One well-briefed agent beats three vague ones.
- **Do not add verification scaffolding to prompts.** "Double-check your answer", "add a
  final verification step", and similar make output worse on current models rather than
  better — they cause over-verification, and removing them costs no capability. This
  inverts older advice, so it is worth stating explicitly. Put the check in `make check`
  or the validator, where it runs deterministically and cannot be talked out of firing.
  This applies to skills you write or edit; existing skills carrying the pattern are not
  a cleanup backlog, so strip it when you are already in the file rather than as its own
  sweep.
- **Do not tell a reviewer to pre-filter.** "Only report high-severity issues" is
  followed literally: the model investigates just as thoroughly, finds the bugs, and
  then declines to report what it judges below the bar. Precision rises, recall appears
  to collapse, and the regression looks like a capability problem when it is a prompt
  problem. Ask for everything with a severity attached and filter in a separate pass —
  `c-review` and `rust-review` do this correctly if you want a model to copy.
