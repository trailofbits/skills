# Tool Skill Template

Use for CLI tools, analysis tools, or any software with installation, configuration, and commands.

## When to Use This Template

- The subject is a specific software tool (e.g., Semgrep, AFL++, Frida)
- It has CLI commands, installation steps, or configuration files
- Users interact with it through a terminal or programmatic API

## Template

```markdown
---
name: {tool-name-lowercase}
description: >
  {One-sentence summary of what this tool does and its key differentiator}.
  Use when {specific trigger conditions}.
allowed-tools:
  - Read
  - Grep
  - Bash
---

# {Tool Name}

{1-2 paragraph introduction: what it is, why it exists, key differentiator
from alternatives.}

## When to Use

**Use {Tool Name} when:**
- {Specific scenario 1}
- {Specific scenario 2}
- {Specific scenario 3}

**Consider alternatives when:**
- {Limitation 1} → Consider {Alternative}
- {Limitation 2} → Consider {Alternative}

## When NOT to Use

- {Scenario where this tool is wrong}
- {Scenario where another approach is better}
- {Scenario where it wastes time}

## Quick Reference

| Task | Command |
|------|---------|
| {Common task 1} | `{command}` |
| {Common task 2} | `{command}` |
| {Common task 3} | `{command}` |

## Installation

### Prerequisites

- {Prerequisite 1}
- {Prerequisite 2}

### Install

\```bash
{installation commands}
\```

### Verify

\```bash
{verification command}
\```

## Core Workflow

{The typical workflow for using this tool — numbered steps}

### Step 1: {First Step}

{Instructions with code examples}

\```bash
{example commands}
\```

### Step 2: {Second Step}

{Instructions}

### Step 3: {Third Step}

{Instructions}

## Configuration

{Settings, config files, key options}

### Configuration File

\```{format}
{example config}
\```

### Key Options

| Option | Purpose | Default |
|--------|---------|---------|
| {option 1} | {what it does} | {default} |
| {option 2} | {what it does} | {default} |

## Advanced Usage

### Tips and Tricks

| Tip | Why It Helps |
|-----|--------------|
| {Tip 1} | {Explanation} |
| {Tip 2} | {Explanation} |

### {Advanced Topic}

{Details}

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| {Problem 1} | {Cause} | {Fix} |
| {Problem 2} | {Cause} | {Fix} |

## Related Skills

| Skill | Relationship |
|-------|--------------|
| **{skill-1}** | {How they relate} |
| **{skill-2}** | {How they relate} |

## Resources

**[{Title}]({URL})**
{Brief summary of what this resource provides}
```

## Field Guide

| Field | Source |
|-------|--------|
| `{tool-name-lowercase}` | Kebab-case from tool name |
| Quick Reference | Extract most common commands from docs |
| Installation | From official install guide |
| Core Workflow | The "getting started" or tutorial section |
| Configuration | From config reference docs |
| Troubleshooting | From FAQ, issues, or community knowledge |

## Notes

- Keep under 500 lines — extract Installation and Advanced Usage to references/ if needed
- Always include comparison with alternatives in "When to Use"
- Include concrete command examples, not abstract descriptions
- If the tool has a config file, show a minimal working example
