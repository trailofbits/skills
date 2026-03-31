---
description: "Iteratively reviews and fixes a Claude Code skill until it meets quality standards. Triggers on 'fix my skill', 'improve skill quality', 'skill improvement loop'."
argument-hint: "<SKILL_NAME_OR_PATH> [--max-iterations N]"
allowed-tools: ["Bash(${CLAUDE_PLUGIN_ROOT}/scripts/setup-skill-improver.sh:*)", "Task", "Read", "Edit", "Write", "Glob", "Grep"]
---

# Skill Improver

## Step 1: Resolve Skill Path

The user provided: `$ARGUMENTS`

**Resolution rules:**
1. If input ends with `/SKILL.md` and file exists, use directly
2. If input is a directory containing `SKILL.md`, use that path
3. Otherwise, search for matching skills:

```
Glob(pattern="**/SKILL.md")
```

Filter results to find skills matching the user's input (by skill name or path substring).

- **Multiple matches:** Ask the user to choose
- **No matches:** Report available skills
- **Single match:** Proceed with that path

Store the resolved absolute path to the skill directory in `RESOLVED_SKILL_PATH`.

## Step 2: Initialize the Loop

Run the setup script with the resolved path:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/setup-skill-improver.sh" "<RESOLVED_SKILL_PATH>" [--max-iterations N]
```

Substitute `<RESOLVED_SKILL_PATH>` with the actual path. Add `--max-iterations N` only if specified.

## Step 3: Follow the Skill Methodology

Apply the `skill-improver:skill-improver` skill to iteratively improve the target skill. The loop continues automatically via the stop hook until completion.
