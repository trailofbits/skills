# Contributing Skills

## Resources

**Official Anthropic documentation (always check these first):**

- [Claude Code Plugins](https://docs.anthropic.com/en/docs/claude-code/plugins)
- [Agent Skills](https://docs.anthropic.com/en/docs/claude-code/skills)
- [Best Practices](https://docs.anthropic.com/en/docs/claude-code/skills#best-practices)

**Reference skills** - learn by example at different complexity levels:

| Complexity | Skill | What It Demonstrates |
|------------|-------|---------------------|
| **Basic** | [ask-questions-if-underspecified](plugins/ask-questions-if-underspecified/) | Minimal frontmatter, simple guidance |
| **Intermediate** | [constant-time-analysis](plugins/constant-time-analysis/) | Python package, references/, language-specific docs |
| **Advanced** | [culture-index](plugins/culture-index/) | Scripts, workflows/, templates/, PDF extraction, multiple entry points |

**When in doubt, copy one of these and adapt it.**

**Deep dives on skill authoring:**
- [Claude Skills Deep Dive](https://leehanchung.github.io/blogs/2025/10/26/claude-skills-deep-dive/) - Comprehensive analysis of skill architecture
- [Claude Code Skills Training](https://huggingface.co/blog/sionic-ai/claude-code-skills-training) - Practical authoring guide

**Example plugins worth studying:**
- [superpowers](https://github.com/obra/superpowers) - Advanced workflow patterns, TDD enforcement, multi-skill orchestration
- [compound-engineering-plugin](https://github.com/EveryInc/compound-engineering-plugin) - Production plugin structure

**For Claude:** Use the `claude-code-guide` subagent for plugin/skill questions - it has access to official documentation.

## Technical Reference

### Plugin Structure

```
plugins/
  <plugin-name>/
    .claude-plugin/
      plugin.json         # Plugin metadata (name, version, description, author)
    commands/             # Optional: slash commands
    agents/               # Optional: autonomous agents
    skills/               # Optional: knowledge/guidance
      <skill-name>/
        SKILL.md          # Entry point with frontmatter
        references/       # Optional: detailed docs
        workflows/        # Optional: step-by-step guides
        scripts/          # Optional: utility scripts
    hooks/                # Optional: event hooks
    README.md             # Plugin documentation
```

**Important**: Component directories (`skills/`, `commands/`, `agents/`, `hooks/`) must be at the plugin root, NOT inside `.claude-plugin/`. Only `plugin.json` belongs in `.claude-plugin/`.

### Frontmatter

```yaml
---
name: skill-name              # kebab-case, max 64 chars
description: "Third-person description of what it does and when to use it"
allowed-tools:                # Optional: restrict to needed tools only
  - Read
  - Grep
---
```

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

### Required Sections

Every SKILL.md must include:

```markdown
## When to Use
[Specific scenarios where this skill applies]

## When NOT to Use
[Scenarios where another approach is better]
```

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

## PR Checklist

Before submitting:

**Technical (CI validates these):**
- [ ] Valid YAML frontmatter with `name` and `description`
- [ ] Name is kebab-case, ≤64 characters
- [ ] All referenced files exist
- [ ] No hardcoded paths (`/Users/...`, `/home/...`)

**Quality (reviewers check these):**
- [ ] Description triggers correctly (third-person, specific)
- [ ] "When to use" and "When NOT to use" sections present
- [ ] Examples are concrete (input → output)
- [ ] Explains WHY, not just WHAT

**Documentation:**
- [ ] Plugin has README.md
- [ ] Added to root README.md table
- [ ] Registered in marketplace.json

**Version updates (for existing plugins):**
- [ ] Increment version in `.claude-plugin/marketplace.json` when making substantive changes to a plugin or skill (clients only update plugins when the version number increases)
