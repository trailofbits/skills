# Hook & Command Skill Template

Use for skills that combine knowledge guidance with event hooks, slash commands, or automation scripts. This template scaffolds a full plugin, not just a knowledge skill.

## When to Use This Template

- The subject involves automated enforcement (pre-commit checks, code style, etc.)
- Users need both knowledge (skill) AND automation (hooks/commands)
- The skill's value comes from active enforcement, not passive guidance
- Examples: code formatting on save, security checks before commit, test runners

## Plugin Structure

This template produces a full plugin structure, not just a SKILL.md:

```
plugins/{plugin-name}/
├── .claude-plugin/
│   └── plugin.json
├── skills/
│   └── {skill-name}/
│       └── SKILL.md          # Knowledge + workflow guidance
├── hooks/
│   └── {hook-name}.json      # Event hook definitions
├── commands/
│   └── {command-name}.md     # Slash command definitions
└── README.md
```

## Hook Definition Reference

Hooks respond to Claude Code events. Define them as JSON files in `hooks/`:

### Hook Events

| Event | When It Fires | Common Use |
|-------|--------------|-----------|
| `PreToolUse` | Before any tool call | Block dangerous commands, validate inputs |
| `PostToolUse` | After any tool call | Format code, run linters, log actions |
| `SessionStart` | When Claude session begins | Set up environment, load state |
| `SubagentStop` | When a subagent completes | Validate output, trigger next step |
| `Notification` | On notification events | Alert user, log metrics |

### Hook Definition Format

```json
{
  "hooks": {
    "{event}": [
      {
        "matcher": "{tool_name_pattern}",
        "command": "{shell_command}",
        "timeout": 10000
      }
    ]
  }
}
```

### Performance Rules for Hooks

Hooks run on every matching event — performance is critical:

| Rule | Rationale |
|------|-----------|
| Prefer shell + jq over Python | Interpreter startup adds ~200ms latency |
| Fast-fail early (exit 0 for non-matching) | Most invocations should be instant |
| Favor regex over AST parsing | Accept rare false positives for speed |
| Avoid network calls in hooks | Latency kills user experience |
| Set tight timeouts (5-10s max) | Prevent hanging on unexpected input |

### Common False Positive Patterns

Hooks that intercept commands must handle these non-threatening cases:

| Pattern | Example | Why It's Not Dangerous |
|---------|---------|----------------------|
| Diagnostic commands | `which python` | Just checking if tool exists |
| Search tools | `grep python` | Searching for text, not executing |
| Filename references | `cat python.txt` | Reading a file, not running Python |
| String arguments | `echo "python is great"` | Just a string literal |

## Command Definition Reference

Slash commands are user-invocable actions. Define them as markdown files in `commands/`:

### Command Format

```markdown
---
name: {command-name}
description: "{What this command does}"
---

# {Command Name}

{Instructions for Claude when this command is invoked}

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| {param1} | Yes/No | {What it does} |

## Workflow

{Step-by-step instructions for Claude}
```

## Template

```markdown
---
name: {skill-name-lowercase}
description: >
  {What behavior this enforces or automates}.
  Use when {trigger conditions}.
allowed-tools:
  - Read
  - Grep
  - Bash
---

# {Skill Name}

{1-2 paragraph introduction: what this automates and why
manual enforcement doesn't work.}

## When to Use

- {Scenario where automation is needed}
- {Scenario where manual checks are error-prone}
- {Scenario where consistency matters across team}

## When NOT to Use

- {Scenario where the overhead isn't justified}
- {Scenario where the hook would interfere with workflows}
- {Scenario where manual control is preferred}

## Quick Reference

| Component | Purpose | File |
|-----------|---------|------|
| Skill | {What knowledge it provides} | `skills/{name}/SKILL.md` |
| Hook: {name} | {What it enforces automatically} | `hooks/{name}.json` |
| Command: /{name} | {What the user can invoke} | `commands/{name}.md` |

## How It Works

### The Skill (passive guidance)

{What Claude learns from the skill — decision criteria, best practices, etc.}

### The Hook (active enforcement)

{What the hook does automatically — when it fires, what it checks, what it blocks}

\```json
{
  "hooks": {
    "{event}": [
      {
        "matcher": "{pattern}",
        "command": "{command}",
        "timeout": {ms}
      }
    ]
  }
}
\```

### The Command (user-invocable)

{What the slash command does when the user explicitly invokes it}

## Setup

### Installation

\```bash
{Installation commands}
\```

### Verify

\```bash
{Verification commands}
\```

## Configuration

{Any user-configurable settings}

| Setting | Default | Description |
|---------|---------|-------------|
| {setting} | {default} | {what it controls} |

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| Hook blocks legitimate command | False positive pattern | {How to adjust matcher} |
| Hook too slow | Heavy processing | {How to optimize} |
| Command not found | Not installed correctly | {How to fix} |

## Related Skills

| Skill | Relationship |
|-------|--------------|
| **{skill-1}** | {How they relate} |
```

## Key Differences From Other Templates

| Aspect | Hook/Command Skill | Knowledge-Only Skill |
|--------|-------------------|---------------------|
| Output | SKILL.md + hooks/ + commands/ | SKILL.md only |
| Enforcement | Active (hooks block/modify) | Passive (guidance only) |
| Must have | Hook definitions, performance rules | Workflow, examples |
| Key section | "How It Works" (skill + hook + command) | Core Workflow |
| Testing | Hook false positive testing critical | Activation testing |

## Notes

- Hooks run on EVERY matching event — a slow hook degrades the entire Claude experience
- Always test hooks against false positive patterns before shipping
- Commands should be discoverable via their name — use verb-noun format (`run-tests`, `check-style`)
- Keep hook logic minimal — complex analysis belongs in the skill, not the hook
- If the hook needs to read config, cache it rather than reading on every invocation
