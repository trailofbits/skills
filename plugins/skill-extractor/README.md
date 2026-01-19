# skill-extractor

Extract reusable skills from work sessions. Manual invocation only - no hooks, no noise.

## Usage

```
/skill-extractor [--project] [context hint]
```

Invoke after solving a non-obvious problem to capture the knowledge as a reusable skill.

**Examples:**
```
/skill-extractor                           # Extract from current session
/skill-extractor --project                 # Save to project instead of user level
/skill-extractor the cyclic data DoS fix  # Hint to focus extraction
```

## What It Does

1. Analyzes your conversation for extractable knowledge
2. Presents a quality checklist for confirmation
3. Optionally researches best practices (web search, Context7)
4. Generates a skill following Trail of Bits standards
5. Validates structure before saving
6. Saves to `~/.claude/skills/` or `.claude/skills/`

## Quality Gates

Before extraction, you confirm:
- Reusable (helps future tasks)
- Non-trivial (required discovery)
- Verified (solution worked)
- Specific triggers (exact errors/scenarios)
- Explains WHY (not just steps)

## Generated Skill Structure

```markdown
---
name: kebab-case-name
description: "Third-person with triggers. Fixes X. Use when..."
---

# Title

## When to Use
## When NOT to Use
## Problem
## Solution
## Verification
## References
```

## Why This Exists

Knowledge gained during work sessions is often lost. You solve a tricky problem,
move on, and next month face the same issue with no memory of the solution.

skill-extractor captures non-obvious solutions at the moment of discovery:
- **Manual trigger** - You decide when something is worth preserving
- **Quality gates** - LLM validates before saving to prevent skill bloat
- **Trail of Bits standard** - Generated skills follow project conventions
- **Discoverable** - Saved skills auto-load when similar problems arise

## License

MIT
