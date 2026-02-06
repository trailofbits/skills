# Technique Skill Template

Use for cross-cutting methodologies that apply across multiple tools — harness writing, coverage analysis, code review patterns, etc.

## When to Use This Template

- The subject is a methodology, not a specific tool
- It applies to multiple tools or languages
- Users need to understand patterns and anti-patterns, not just commands

## Template

```markdown
---
name: {technique-name-lowercase}
description: >
  {Summary of what this technique does and why it matters}.
  Use when {trigger conditions}.
allowed-tools:
  - Read
  - Grep
---

# {Technique Name}

{1-2 paragraph introduction: what this technique is, why it matters,
and what goes wrong without it.}

## When to Use

**Apply this technique when:**
- {Trigger 1}
- {Trigger 2}
- {Trigger 3}

**Skip this technique when:**
- {Skip condition 1}
- {Skip condition 2}

## When NOT to Use

- {Scenario where this technique is inappropriate}
- {Scenario where a different approach is better}

## Quick Reference

| Task | Pattern |
|------|---------|
| {Task 1} | `{pattern or command}` |
| {Task 2} | `{pattern or command}` |
| {Task 3} | `{pattern or command}` |

## Key Concepts

| Concept | Description |
|---------|-------------|
| {Concept 1} | {Brief explanation} |
| {Concept 2} | {Brief explanation} |

## Step-by-Step

### Step 1: {First Step}

{Instructions with code examples}

\```{language}
{example code}
\```

### Step 2: {Second Step}

{Instructions}

### Step 3: {Third Step}

{Instructions}

## Common Patterns

### Pattern: {Pattern Name}

**Use Case:** {When to apply this pattern}

**Before:**
\```{language}
{code before applying technique}
\```

**After:**
\```{language}
{code after applying technique}
\```

**Why it works:** {Explanation}

### Pattern: {Pattern Name 2}

{Same structure}

## Anti-Patterns

| Anti-Pattern | Problem | Correct Approach |
|--------------|---------|------------------|
| {Bad practice 1} | {Why it fails} | {What to do instead} |
| {Bad practice 2} | {Why it fails} | {What to do instead} |

## Tool-Specific Guidance

{How this technique applies to specific tools — KEY for discoverability}

### {Tool 1}

\```bash
{tool-specific command}
\```

**Integration tips:**
- {Tip specific to this tool}
- {Tip specific to this tool}

### {Tool 2}

\```bash
{tool-specific command}
\```

**Integration tips:**
- {Tip specific to this tool}

## Advanced Usage

### Tips and Tricks

| Tip | Why It Helps |
|-----|--------------|
| {Tip 1} | {Explanation} |
| {Tip 2} | {Explanation} |

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| {Issue 1} | {Cause} | {Fix} |
| {Issue 2} | {Cause} | {Fix} |

## Related Skills

### Tools That Use This Technique

| Skill | How It Applies |
|-------|----------------|
| **{tool-skill-1}** | {How this technique is used with this tool} |
| **{tool-skill-2}** | {How this technique is used with this tool} |

### Related Techniques

| Skill | Relationship |
|-------|--------------|
| **{technique-1}** | {How they complement each other} |
| **{technique-2}** | {How they complement each other} |

## Resources

**[{Title}]({URL})**
{Brief summary of key insights}
```

## Key Differences From Tool Skills

| Aspect | Tool Skill | Technique Skill |
|--------|-----------|-----------------|
| Focus | One specific tool | Methodology across tools |
| Must have | Installation, CLI commands | Before/after patterns, tool-specific sections |
| Key section | Core Workflow | Common Patterns + Anti-Patterns |
| Related Skills | Links to techniques it uses | Links to tools it applies to |

## Notes

- The Tool-Specific Guidance section is critical — it's what makes the technique discoverable when someone is using a particular tool
- Always include Before/After code examples in Common Patterns
- Anti-Patterns section prevents Claude from applying the technique incorrectly
- Keep under 500 lines — extract tool-specific sections to references/ if needed
