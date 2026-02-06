# Guidance Skill Template

Use for behavioral guidance, best practices, decision frameworks, and process skills that shape how Claude approaches work rather than teaching a specific tool or technique.

## When to Use This Template

- The subject is about HOW to think, not WHAT tool to use
- It provides decision rules, behavioral constraints, or process guidance
- Examples: "ask clarifying questions," "modern Python practices," "code review process"

## Template

```markdown
---
name: {guidance-name-lowercase}
description: >
  {What behavior this skill enforces or guides}.
  Use when {trigger conditions — describe the situation, not the tool}.
---

# {Guidance Name}

{1-2 paragraph introduction: what problem this guidance solves and
what goes wrong without it.}

## When to Use

Use this skill when:
- {Situation 1 — describe the context, not the action}
- {Situation 2}
- {Situation 3}

## When NOT to Use

Do not use this skill when:
- {Situation where it's counterproductive}
- {Situation where another skill is better}
- {Situation where the guidance doesn't apply}

## Goal

{One sentence: what is the desired outcome of following this guidance?}

## Core Principles

{3-7 principles that form the foundation of this guidance}

### 1. {Principle Name}

{Explanation with concrete example}

**Example:**
{Specific scenario showing this principle in action}

### 2. {Principle Name}

{Explanation with concrete example}

### 3. {Principle Name}

{Explanation with concrete example}

## Workflow

{Step-by-step process for applying this guidance}

### Step 1: {Decision or Assessment Step}

{How to evaluate the situation}

**Ask yourself:**
- {Question 1}
- {Question 2}
- {Question 3}

### Step 2: {Action Step}

{What to do based on the assessment}

### Step 3: {Verification Step}

{How to confirm the guidance was applied correctly}

## Decision Framework

{For guidance that involves choosing between approaches}

| Situation | Approach | Rationale |
|-----------|----------|-----------|
| {Situation 1} | {What to do} | {Why} |
| {Situation 2} | {What to do} | {Why} |
| {Situation 3} | {What to do} | {Why} |

## Templates

{Reusable templates for common outputs of this guidance}

### {Template Name}

\```text
{Template content with placeholders}
\```

### {Template Name 2}

\```text
{Template content}
\```

## Anti-Patterns

{Behaviors to avoid — with explanations of why they're wrong}

| Anti-Pattern | Why It's Wrong | Instead |
|--------------|---------------|---------|
| {Bad behavior 1} | {What goes wrong} | {Correct behavior} |
| {Bad behavior 2} | {What goes wrong} | {Correct behavior} |

## Examples

### Example: {Scenario Name}

**Situation:** {Describe the context}

**Wrong approach:**
{What Claude might do without this guidance}

**Correct approach:**
{What Claude should do with this guidance}

**Why:** {Explanation of the difference}

### Example: {Scenario Name 2}

{Same structure}

## Related Skills

| Skill | When to Use Together |
|-------|---------------------|
| **{skill-1}** | {Integration scenario} |
| **{skill-2}** | {Integration scenario} |
```

## Key Differences From Other Templates

| Aspect | Guidance Skill | Tool/Technique Skill |
|--------|---------------|---------------------|
| Focus | How Claude should behave | What Claude should do |
| Content | Principles, decision rules, examples | Commands, code, workflows |
| Key section | Core Principles + Decision Framework | Quick Reference + Core Workflow |
| Success metric | Claude makes better decisions | Claude uses the tool correctly |

## Notes

- Guidance skills are about shaping behavior, not teaching commands
- The Examples section is critical — show Wrong vs. Correct approaches
- Keep principles to 3-7 (more becomes unactionable)
- Anti-Patterns section is essential — guidance skills exist to prevent specific mistakes
- Templates help Claude produce consistent outputs
- These skills often have the highest activation rates — keep descriptions precise to avoid false triggers
