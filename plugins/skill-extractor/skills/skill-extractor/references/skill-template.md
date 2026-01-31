# Skill Template

Copy this template when generating a new skill.

```markdown
---
name: [kebab-case-name]
description: |
  [Third-person description with specific triggers. Example: "Detects infinite
  recursion vulnerabilities in AST visitors from cyclic data structures. Use
  when: (1) RecursionError during tree traversal, (2) analyzing untrusted
  serialized data, (3) visitor pattern without cycle detection."]
author: Claude Code
version: 1.0.0
date: [YYYY-MM-DD]
---

# [Human Readable Title]

## When to Use

- [Specific scenario 1]
- [Specific scenario 2]
- [Exact error message if applicable]

## When NOT to Use

- [Scenario where this doesn't apply]
- [Better alternative for related but different problem]

## Problem

[Clear description of what this solves and why it's non-obvious]

## Solution

### Step 1: [Action]

[Instructions with code examples]

```language
// Example code
```

### Step 2: [Action]

[Continue with clear steps]

## Verification

1. [How to confirm it worked]
2. [Expected outcome]

## References

- [Link to official docs if researched]
- [Web source if consulted]
```

## Validation Checklist

Before saving, verify:

- [ ] Name is kebab-case, max 64 characters
- [ ] Description is third-person ("Fixes X" not "I help with X")
- [ ] Description includes specific trigger conditions
- [ ] "When to Use" section is present and specific
- [ ] "When NOT to Use" section is present
- [ ] Solution has concrete steps
- [ ] No hardcoded paths (`/Users/...`, `/home/...`)
- [ ] Under 500 lines total
