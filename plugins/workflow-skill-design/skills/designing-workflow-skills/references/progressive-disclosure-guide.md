# Progressive Disclosure Guide

How to split skill content across files so the LLM prioritizes correctly.

---

## The 500-Line Rule

SKILL.md must stay under 500 lines. This is not arbitrary — it's the threshold where LLM attention degrades. Beyond 500 lines, instructions at the bottom of SKILL.md get less weight than instructions at the top.

If your SKILL.md exceeds 500 lines, split content into `references/` and `workflows/`.

---

## What Goes Where

### SKILL.md (always read first)

Content the LLM needs for **every** invocation:

- Frontmatter (name, description, allowed-tools) — description controls activation
- Essential principles (5-7 non-negotiable rules)
- When to Use / When NOT to Use (behavioral scope, not activation triggers)
- Routing logic or pattern selection (if applicable)
- Quick reference tables (compact summaries)
- Reference index (links to all supporting files)
- Success criteria checklist

**Test:** If removing this content would cause the LLM to produce wrong output on any invocation, it belongs in SKILL.md.

### references/ (read on demand)

Detailed knowledge the LLM needs for **specific** tasks:

- Full pattern descriptions with examples
- Complete anti-pattern catalogs
- API references
- Domain-specific knowledge
- Tool documentation

**Test:** If this content is only needed for some invocations (e.g., one workflow path but not others), it belongs in references/.

### workflows/ (read for specific processes)

Step-by-step procedures:

- Multi-phase processes
- Checklists
- Decision procedures
- Specific task guides

**Test:** If this content is a series of ordered steps to follow for a specific task, it belongs in workflows/.

---

## File Naming

Use kebab-case descriptive names:

| Good | Bad |
|------|-----|
| `workflow-patterns.md` | `patterns.md` (too vague) |
| `anti-patterns.md` | `bad-stuff.md` (unprofessional) |
| `tool-assignment-guide.md` | `tools.md` (too vague) |
| `design-a-workflow-skill.md` | `workflow.md` (ambiguous) |
| `review-checklist.md` | `checklist.md` (which checklist?) |

The filename should tell you what's inside without opening it.

---

## The One-Level-Deep Rule

SKILL.md links to reference and workflow files. Those files do NOT link to other reference files.

```
ALLOWED:
SKILL.md -> references/patterns.md
SKILL.md -> references/anti-patterns.md
SKILL.md -> workflows/build-process.md

NOT ALLOWED:
references/patterns.md -> references/pattern-details.md
workflows/build-process.md -> references/build-config.md
```

**Why:** Each hop degrades context. By the second hop, the LLM has lost track of where it started and why. If a reference file needs content from another reference file, either merge them or restructure so SKILL.md links to both directly.

**Exception:** Directory nesting for organization is fine (`references/guides/topic.md`). The restriction is on *reference chains* (file A telling the LLM to go read file B), not on directory depth.

---

## Sizing Guidelines

| File type | Target size | Maximum |
|-----------|-------------|---------|
| SKILL.md | 200-400 lines | 500 lines |
| Reference file | 100-300 lines | 400 lines |
| Workflow file | 80-200 lines | 300 lines |
| Agent definition | 80-200 lines | 300 lines |

If a reference file exceeds 400 lines, split it into two files that SKILL.md links to separately.

---

## Progressive Disclosure in Practice

Structure SKILL.md as a funnel: broad overview first, details via links.

```markdown
## Essential Principles     <- Always read (5-7 bullet points)
## When to Use / NOT        <- Scopes behavior (not activation — that's the description)
## Decision Tree            <- Routes to the right pattern
## Quick Reference Table    <- Compact summary (10-15 rows)
## Reference Index          <- Links to detailed files
## Success Criteria         <- Final checklist
```

The LLM reads top-to-bottom. Front-load what matters for every invocation. Push details into files that are only read when needed.
