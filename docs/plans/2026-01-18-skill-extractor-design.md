# skill-extractor Design

Extract reusable skills from work sessions. Manual invocation only - no hooks, no noise.

## Command

```
/skill-extractor [--project] [context hint]
```

- Default: saves to `~/.claude/skills/[name]/SKILL.md`
- `--project`: saves to `.claude/skills/[name]/SKILL.md`
- Context hint helps focus extraction

## Flow

1. User invokes `/skill-extractor`
2. Analyze conversation for extractable knowledge
3. Present quality checklist - user confirms or skips
4. Optional: web search / Context7 for library-specific topics
5. Generate skill following ToB template
6. Validate structure before saving
7. Save to appropriate location

## Quality Checklist

Before extraction, user confirms:

- [ ] Reusable - helps with future tasks, not just this instance
- [ ] Non-trivial - required discovery, not just docs lookup
- [ ] Verified - solution actually worked
- [ ] Specific triggers - exact error messages or scenarios
- [ ] Explains WHY - includes trade-offs and judgment

## Generated Skill Template

```markdown
---
name: [kebab-case-name]
description: |
  [Third-person with triggers. "Fixes X. Use when: (1)..., (2)..., (3)..."]
author: [user or "Claude Code"]
version: 1.0.0
date: [YYYY-MM-DD]
---

# [Title]

## When to Use

- [Scenario 1]
- [Scenario 2]

## When NOT to Use

- [When another approach is better]

## Problem

[What this solves, why non-obvious]

## Solution

### Step 1: [Action]
[Instructions with code]

## Verification

1. [How to confirm]
2. [Expected outcome]

## References

- [Official docs if researched]
- [Web sources if consulted]
```

## Validation Rules

- Name: kebab-case, max 64 chars
- Description: third-person ("Fixes X" not "I help with X")
- Required sections: When to Use, When NOT to Use, Problem, Solution, Verification
- No hardcoded paths
- Under 500 lines

## Plugin Structure

```
plugins/skill-extractor/
├── .claude-plugin/
│   └── plugin.json
├── skills/
│   └── skill-extractor/
│       └── SKILL.md
└── README.md
```

## Key Differences from continuous-learning

| Aspect | continuous-learning | skill-extractor |
|--------|---------------------|-----------------|
| Trigger | Hook on every prompt | Manual only |
| Noise | 15-line banner | None |
| Quality | Self-assessed | Checklist with user confirmation |
| Template | 6 sections | ToB standard with "When NOT to Use" |
| Integration | Standalone | Web search + Context7 when relevant |
