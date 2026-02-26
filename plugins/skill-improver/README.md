# Skill Improver Plugin

Iteratively reviews and fixes Claude Code skill quality issues until they meet standards. Runs automated fix-review cycles using the `skill-reviewer` agent from the `plugin-dev` plugin.

## Requirements

- **`plugin-dev` plugin** must be installed (provides `skill-reviewer` agent)

## Commands

### /skill-improver \<SKILL_PATH\> [--max-iterations N]

Start an improvement loop for a skill.

```bash
/skill-improver ./plugins/my-plugin/skills/my-skill
/skill-improver ./skills/my-skill/SKILL.md --max-iterations 15
```

### /cancel-skill-improver [SESSION_ID]

Stop the active improvement loop. Changes made during the loop are preserved.

## How It Works

1. `/skill-improver` resolves the skill path and creates a session state file
2. The skill-improver methodology reviews, fixes, and re-reviews iteratively
3. A stop hook continues the loop until the quality bar is met or max iterations (default: 20) are reached
4. The loop ends when Claude outputs `<skill-improvement-complete>` or the limit is hit

Multiple sessions can run simultaneously on different skills. Each gets a unique session ID and separate state file in `.claude/`.

See [SKILL.md](skills/skill-improver/SKILL.md) for detailed methodology and issue categorization.

## Troubleshooting

- **"subagent not found"**: Install the `plugin-dev` plugin
- **Loop never completes**: Check state with `cat .claude/skill-improver.*.local.md`, cancel with `/cancel-skill-improver`
- **Orphaned state files**: Remove with `trash .claude/skill-improver.*.local.md`
