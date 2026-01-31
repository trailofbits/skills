---
name: skill-extractor
description: |
  Extracts reusable skills from work sessions. Use when: (1) a non-obvious problem
  was solved worth preserving, (2) a pattern was discovered that would help future
  sessions, (3) a workaround or debugging technique needs documentation. Manual
  invocation only via /skill-extractor command - no automatic triggers or hooks.
allowed-tools:
  - Read
  - Write
  - Glob
  - Grep
  - WebSearch
  - AskUserQuestion
---

# Skill Extractor

Extracts reusable knowledge from work sessions and saves it as a Claude Code skill.

## When to Use

- Just solved a non-obvious problem through investigation
- Discovered a workaround that required trial-and-error
- Found a debugging technique that would help in similar situations
- Learned a project-specific pattern worth preserving
- Fixed an error where the root cause wasn't immediately apparent

## When NOT to Use

- Simple documentation lookups (just bookmark the docs)
- Trivial fixes (typos, obvious errors)
- One-off project-specific configurations
- Knowledge that's already well-documented elsewhere
- Unverified solutions (wait until it actually works)

## Finding Extraction Candidates

Use these prompts to identify knowledge worth extracting:

- "What did I just learn that wasn't obvious before starting?"
- "If I faced this exact problem again, what would I wish I knew?"
- "What error message or symptom led me here, and what was the actual cause?"
- "Is this pattern specific to this project, or would it help in similar projects?"
- "What would I tell a colleague who hits this same issue?"

If you can't answer at least two of these with something non-trivial, it's probably not worth extracting.

## Command

```
/skill-extractor [--project] [context hint]
```

- Default: saves to `~/.claude/skills/[name]/SKILL.md`
- `--project`: saves to `.claude/skills/[name]/SKILL.md`
- Context hint helps focus extraction (e.g., `/skill-extractor the cyclic data DoS fix`)

## Extraction Process

### Step 0: Check for Existing Skills

Before creating a new skill, search for existing ones that might cover the same ground:

```bash
# Check user skills
ls ~/.claude/skills/

# Check project skills
ls .claude/skills/

# Search by keyword
grep -r "keyword" ~/.claude/skills/ .claude/skills/ 2>/dev/null
```

If a related skill exists, consider **updating it** instead of creating a new one. See [skill-lifecycle.md](references/skill-lifecycle.md) for guidance on when to update vs create.

### Step 1: Identify the Learning

If `$ARGUMENTS` contains a context hint (e.g., "the cyclic data DoS fix"), use it to focus the extraction on that specific topic.

Analyze the conversation to identify:
- What problem was solved?
- What made the solution non-obvious?
- What would someone need to know to solve this faster next time?
- What are the exact trigger conditions (error messages, symptoms)?

Present a brief summary to the user:
```
I identified this potential skill:

**Problem:** [Brief description]
**Key insight:** [What made it non-obvious]
**Triggers:** [Error messages or symptoms]
```

### Step 2: Quality Assessment

Evaluate the candidate skill against these criteria:

| Criterion | Pass? | Evidence |
|-----------|-------|----------|
| **Reusable** - Helps future tasks, not just this instance | ✓/✗ | [Why] |
| **Non-trivial** - Required discovery, not docs lookup | ✓/✗ | [Why] |
| **Verified** - Solution actually worked | ✓/✗ | [Evidence] |
| **Specific triggers** - Exact error messages or scenarios | ✓/✗ | [What they are] |
| **Explains WHY** - Trade-offs and judgment, not just steps | ✓/✗ | [How] |
| **Value-add** - Teaches judgment, not just facts Claude could look up | ✓/✗ | [How] |

Present assessment to user and ask: "Proceed with extraction? [yes/no]"

The user decides whether to proceed regardless of how many criteria pass. Respect their judgment - if they say yes, extract; if no, skip.

### Step 3: Gather Details

Ask the user:
1. **Skill name** - Suggest a kebab-case name based on context, let them override
2. **Scope** - User-level (default) or project-level (`--project`)

### Step 4: Optional Research

If the topic involves a specific library or framework:
- Use web search to find current best practices
- Use Context7 MCP (if available) for official documentation
- Include relevant sources in the References section

Skip research for:
- Project-specific internal patterns
- Generic programming concepts
- Time-sensitive extractions

### Step 5: Generate the Skill

Use the template from [skill-template.md](references/skill-template.md).

**Quality standards:** Follow [quality-guide.md](references/quality-guide.md) to ensure the skill provides lasting value. Key points:
- Behavioral guidance over reference dumps
- Explain WHY, not just WHAT
- Specific triggers that compete well against other skills

### Step 6: Validate Before Saving

Run through the validation checklist in [skill-template.md](references/skill-template.md). If validation fails, fix the issues before saving.

### Step 7: Save the Skill

Create the directory and save:
- User-level: `~/.claude/skills/[name]/SKILL.md`
- Project-level: `.claude/skills/[name]/SKILL.md`

Report success:
```
Skill saved to: [path]

The skill will be available in future sessions when the context matches:
"[first line of description]"
```

## Memory Consolidation

When extracting, consider how the new knowledge relates to existing skills:

**Combine or separate?**
- **Combine** if the new knowledge is a variation or edge case of an existing skill
- **Separate** if it has distinct trigger conditions or solves a fundamentally different problem
- When in doubt, start separate — you can always merge later

**Update vs create:**
- **Update** an existing skill when you've discovered additional edge cases, better solutions, or corrections
- **Create** a new skill when the knowledge has different trigger conditions, even if the domain is related

**Cross-referencing:**
- If skills are related but separate, add a "See also" section linking them
- Example: A skill for "debugging connection pool exhaustion" might link to "serverless cold start optimization"

## Skill Lifecycle

Skills aren't permanent. See [skill-lifecycle.md](references/skill-lifecycle.md) for guidance on:
- Updating skills with new discoveries
- Deprecating skills when tools or patterns change
- Archiving skills that are no longer relevant

## Rationalizations to Reject

If you catch yourself thinking any of these, do NOT extract:

- "This might be useful someday" → Only extract verified, reusable knowledge
- "Let me just save everything" → Quality over quantity
- "The user didn't confirm but it seems valuable" → Always get explicit confirmation
- "I'll skip the 'When NOT to Use' section" → It's mandatory for good skills
- "The description can be vague" → Specific triggers are essential for discovery

## Example Extraction

**Scenario:** User discovered that an AST visitor crashes with RecursionError when analyzing serialized files containing cyclic references (e.g., a list that contains itself).

**Identified learning:**
- Cyclic data structures create cyclic ASTs
- Visitor pattern without cycle tracking causes infinite recursion
- Need to track visited nodes or enforce depth limits

**Generated skill name:** `cyclic-ast-visitor-hardening`

**Key sections:**
- When to Use: "RecursionError in AST visitor", "analyzing untrusted serialized input"
- When NOT to Use: "Recursion from deeply nested (but acyclic) structures"
- Problem: Visitor doesn't track visited nodes, enters infinite loop on cycles
- Solution: Add `visited: set` parameter, check before recursing
- Verification: Cyclic test case completes without RecursionError
