# Contributing Skills for Cursor

This document provides guidance for adapting and using Trail of Bits skills with Cursor IDE.

## Overview

This repository contains skills originally designed for Claude Code that have been adapted to work with Cursor. The skills are converted to Cursor-compatible rule files in `.cursor/rules/`.

## Quick Start for Cursor Users

### Using the Skills

1. Copy the `.cursor/` folder to your target project:
   ```bash
   cd /path/to/your/project
   cp -r /path/to/trailofbits_ai_tool/.cursor ./
   ```

2. **Restart Cursor** or reload the window (Ctrl+Shift+P → "Developer: Reload Window")

3. The rules are now active. How they work:
   - **Auto-attached rules**: Rules with `globs` patterns (like `*.cairo`) automatically activate when you reference matching files
   - **Manual rules**: Reference specific rules using `@ruleName` in your prompt
   - **Agent-requested**: The AI may pull in relevant rules based on their descriptions

### How to Use (Important!)

**You don't "run" rules like commands.** Instead, ask naturally:

- "Review the Cairo contracts in `contract/` for security vulnerabilities"
- "Check this code for timing side-channel issues"
- "Find entry points in these Solidity contracts"

The rules provide the AI with **methodology and patterns** to follow when answering.

To explicitly include a rule, use `@` mention:
- "@cairo-vulnerability-scanner review the contracts in src/"
- "@sharp-edges check this authentication code"

### Regenerating Rules

If you've updated skills or want to regenerate the Cursor rules:

```bash
# Convert all plugins
python scripts/convert_to_cursor.py

# Convert a specific plugin
python scripts/convert_to_cursor.py --plugin constant-time-analysis

# List available plugins
python scripts/convert_to_cursor.py --list

# Custom output directory
python scripts/convert_to_cursor.py --output-dir ./my-rules
```

## Differences from Claude Code

| Feature | Claude Code | Cursor |
|---------|-------------|--------|
| Configuration | `.claude-plugin/plugin.json` | `.cursor/rules/*.mdc` |
| Skills | `skills/*/SKILL.md` with YAML frontmatter | `.cursor/rules/*.mdc` markdown files |
| Marketplace | `/plugin marketplace add` | Manual file copying |
| Commands | `commands/*.md` | Not directly supported |
| Agents | `agents/` directory | Not directly supported |
| Hooks | `hooks/` directory | Not directly supported |

## Structure

### Claude Code Plugin Structure (Original)

```
plugins/
  <plugin-name>/
    .claude-plugin/
      plugin.json         # Plugin metadata
    skills/
      <skill-name>/
        SKILL.md          # Entry point with YAML frontmatter
        references/       # Detailed docs
        workflows/        # Step-by-step guides
        scripts/          # Utility scripts
```

### Cursor Rules Structure (Converted)

```
.cursor/
  rules/
    <skill-name>.mdc      # Converted skill with references merged
    index.md              # Index of available rules
```

## Contributing New Skills

When contributing skills that work for both Claude Code and Cursor:

### 1. Create the Claude Code Structure (Primary)

Follow the guidelines in [CLAUDE.md](CLAUDE.md) to create the skill in the standard Claude Code format:

```
plugins/<plugin-name>/
  .claude-plugin/
    plugin.json
  skills/
    <skill-name>/
      SKILL.md
      references/  # Optional
```

### 2. SKILL.md Format

Use YAML frontmatter compatible with both systems:

```yaml
---
name: skill-name              # kebab-case, max 64 chars
description: "Third-person description of what it does and when to use it"
---

# Skill Name

## When to Use
[Specific scenarios]

## When NOT to Use
[When to skip this skill]

## Content
[Main skill content]
```

### 3. Path Handling

Use `{baseDir}` for paths in SKILL.md files. The conversion script will translate these to appropriate relative paths for Cursor:

```markdown
<!-- In SKILL.md -->
Run the analyzer:
```bash
uv run {baseDir}/scripts/analyze.py input.c
```
```

This becomes:

```markdown
<!-- In .cursor/rules/skill-name.mdc -->
Run the analyzer:
```bash
uv run plugins/<plugin-name>/scripts/analyze.py input.c
```
```

### 4. Generate Cursor Rules

After creating or updating a skill:

```bash
python scripts/convert_to_cursor.py --plugin <plugin-name>
```

### 5. Test Both Systems

- **Claude Code**: Install via `/plugin marketplace add` or local path
- **Cursor**: Open the repository and verify rules are loaded

## Quality Standards

### Cursor-Specific Considerations

1. **Self-Contained Rules**: Since Cursor loads rules as individual files, the conversion script merges reference files into the main rule. Keep reference files concise.

2. **No External Dependencies**: Unlike Claude Code's agent system, Cursor rules should be self-contained instructions that don't rely on external commands or agents.

3. **Clear Triggers**: Describe when the skill should be activated. Cursor doesn't have explicit skill activation, so clear "When to Use" sections help users know when to apply the guidance.

4. **Tool Agnostic**: Write skills that work regardless of whether the AI is Claude (in Claude Code) or another model (in Cursor).

## Conversion Details

The `convert_to_cursor.py` script:

1. Reads `plugin.json` for metadata
2. Parses YAML frontmatter from `SKILL.md`
3. Finds and merges reference files
4. Converts `{baseDir}` paths to relative paths
5. Generates `.mdc` files in `.cursor/rules/`
6. Creates an `index.md` with links to all rules

### Limitations

- **Commands**: Claude Code `/commands` are not converted (Cursor doesn't have an equivalent)
- **Agents**: Autonomous agents are not supported in Cursor
- **Hooks**: Event hooks are not converted
- **Interactive Scripts**: Scripts requiring user input may need adaptation

## File Extension

Cursor rules use the `.mdc` (Markdown Configuration) extension. This distinguishes them from regular markdown documentation while maintaining readability.

## Example Workflow

```bash
# 1. Create a new skill for Claude Code
mkdir -p plugins/my-skill/.claude-plugin plugins/my-skill/skills/my-skill

# 2. Create plugin.json
cat > plugins/my-skill/.claude-plugin/plugin.json << 'EOF'
{
  "name": "my-skill",
  "version": "1.0.0",
  "description": "Description of my skill",
  "author": {
    "name": "Your Name"
  }
}
EOF

# 3. Create SKILL.md (see format above)
# Edit: plugins/my-skill/skills/my-skill/SKILL.md

# 4. Convert to Cursor
python scripts/convert_to_cursor.py --plugin my-skill

# 5. Verify
ls -la .cursor/rules/my-skill.mdc
```

## Resources

- [CLAUDE.md](CLAUDE.md) - Claude Code skill authoring guidelines
- [Cursor Documentation](https://cursor.sh/docs) - Official Cursor docs
- [Trail of Bits](https://www.trailofbits.com/) - About Trail of Bits
