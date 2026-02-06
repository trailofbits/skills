---
name: skill-generator-v2
description: >
  Generates Claude Code skills from any documentation source with multi-agent
  review, quality scoring, and ecosystem-aware duplicate detection. Use when
  creating new skills, converting documentation into skills, or bulk-generating
  skills from a knowledge base.
allowed-tools:
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - Bash
  - Task
  - WebFetch
  - TodoWrite
---

# Skill Generator v2

Generate production-quality Claude Code skills from any documentation source. Extends the v1 generator with ecosystem-aware duplicate detection, thinking lenses for content depth, multi-agent review, scored quality rubrics, timelessness scoring, and hook/command scaffolding.

## When to Use

- Converting existing documentation (repos, websites, PDFs) into Claude Code skills
- Creating a new skill from scratch with proper structure and quality
- Bulk-generating skills from a documentation source with multiple topics
- Improving an existing skill to meet marketplace quality standards
- Scaffolding a full plugin with skills, hooks, and commands together

## When NOT to Use

- Writing a simple CLAUDE.md project configuration (no plugin structure needed)
- The documentation source is a single paragraph or trivial content
- You need only a hook or command without any skill content

## Decision Tree

```
What do you need?

├─ Generate skills from a documentation source?
│  └─ Follow Phase 0-7 workflow below
│     Start with discovery, includes duplicate detection + review
│
├─ Create a single new skill from scratch?
│  └─ Read: templates/ for the right template
│     Pick: tool, technique, guidance, audit, or hook-command
│     Apply thinking lenses (references/quality-standards.md)
│     Then follow Phase 3 (generation) directly
│
├─ Scaffold a full plugin (skills + hooks + commands)?
│  └─ Read: templates/hook-command-skill.md
│     Combine with other templates as needed
│
├─ Improve an existing skill?
│  └─ Read: references/quality-standards.md
│     Run scored rubric from references/validation.md
│     Apply thinking lenses to identify gaps
│
├─ Understand what makes a good skill?
│  └─ Read: references/quality-standards.md
│     Key additions: thinking lenses, timelessness scoring
│
└─ Validate a generated skill?
   └─ Read: references/validation.md
      Run scored rubric (not just pass/fail)
```

## Quick Reference

### Skill Type Selection

| Your Content Is About | Skill Type | Template |
|----------------------|------------|----------|
| A CLI tool or analysis tool | Tool | `templates/tool-skill.md` |
| A cross-cutting methodology | Technique | `templates/technique-skill.md` |
| Best practices or behavioral guidance | Guidance | `templates/guidance-skill.md` |
| Security review or vulnerability detection | Audit | `templates/audit-skill.md` |
| Event hooks, slash commands, or automation | Hook/Command | `templates/hook-command-skill.md` |

### What's New in v2

| Enhancement | Phase | What It Does |
|-------------|-------|-------------|
| Duplicate detection | 1 | Scans existing skills before creating new ones |
| Thinking lenses | 3 | Forces deep analysis through 6 analytical perspectives |
| Two-stage review | 4 | Spec compliance first, then content quality |
| Scored rubric | 4 | 9-criteria weighted score (not just pass/fail) |
| Timelessness scoring | 4 | Ensures skills remain useful over time |
| Hook/command template | 3 | Scaffolds full plugins, not just knowledge skills |

## Workflow Overview

```
Phase 0: Setup              Phase 1: Discovery + Dedup
┌─────────────────┐        ┌──────────────────────┐
│ Locate source   │   →    │ Analyze content      │
│ - Find docs     │        │ - Scan sections      │
│ - Confirm path  │        │ - Classify types     │
│ - Choose output │        │ - DUPLICATE CHECK    │
└─────────────────┘        │ - Map relations      │
                           └──────────────────────┘
         ↓                          ↓
Phase 3: Generation        Phase 2: Planning
┌─────────────────┐        ┌─────────────────┐
│ THREE-PASS GEN  │   ←    │ Present plan    │
│ Pass 1: Lenses  │        │ - Skill list    │
│ Pass 2: Content │        │ - Dedup results │
│ Pass 3: X-refs  │        │ - User approval │
└─────────────────┘        └─────────────────┘
         ↓
Phase 4: Review            Phase 5: Scoring
┌─────────────────┐        ┌─────────────────┐
│ TWO-STAGE       │   →    │ Scored rubric   │
│ Stage 1: Spec   │        │ - 9 criteria    │
│ Stage 2: Quality│        │ - Timelessness  │
│ - Per skill     │        │ - Score ≥ 70    │
└─────────────────┘        └─────────────────┘
         ↓
Phase 6: Fix + Iterate     Phase 7: Finalize
┌─────────────────┐        ┌─────────────────┐
│ Fix review hits │   →    │ Post-generation │
│ - Rescore       │        │ - Update README │
│ - Loop til ≥70  │        │ - Register      │
└─────────────────┘        │ - Report scores │
                           └─────────────────┘
```

## Phase 0: Setup

### Locate Documentation Source

Ask the user or infer from context:

1. **Repository path** — check if user mentioned a path or URL
2. **Website URL** — if user provides a docs site
3. **Local files** — glob for documentation files in working directory

```
"What documentation should I generate skills from?
 - Local path: /path/to/docs or ./docs
 - Git repo: https://github.com/org/repo
 - Website: https://docs.example.com
 - Or describe the topic and I'll create from scratch"
```

### Choose Output Location

Generated skills go to a plugin directory:

```
plugins/{plugin-name}/
├── .claude-plugin/
│   └── plugin.json
├── skills/
│   └── {skill-name}/
│       └── SKILL.md
├── hooks/                    # NEW: optional hook scaffolding
├── commands/                 # NEW: optional command scaffolding
└── README.md
```

## Phase 1: Discovery + Duplicate Detection

See [references/discovery.md](references/discovery.md) for the full methodology.

**Quick version:**

1. **Scan** the source for distinct topics, tools, or techniques
2. **Classify** each topic into a skill type (tool, technique, guidance, audit)
3. **Check for duplicates** against the existing skill ecosystem
4. **Map relationships** between topics (which reference each other?)
5. **Estimate scope** — flag topics with too little content to warrant a skill

### Duplicate Detection

Before generating, scan for existing skills that already cover the same topic.

**Where to look:**

```
1. Local plugin directories:
   Glob: plugins/*/skills/*/SKILL.md
   Extract: name, description from frontmatter

2. Installed marketplace skills:
   Read: .claude-plugin/marketplace.json
   Extract: name, description from each plugin

3. Known community marketplaces (optional):
   WebFetch: skillsmp.com search for topic keywords
```

**Match evaluation:**

| Confidence | Action |
|------------|--------|
| >= 80% match (same topic, same type) | **WARN**: "Skill '{name}' already covers this. Improve it instead?" |
| 50-79% match (related topic, some overlap) | **NOTE**: "Related skill '{name}' exists. Consider referencing it." |
| < 50% match | Proceed with generation |

**Include results in the plan:**

```markdown
## Duplicate Check Results

| Candidate Skill | Existing Match | Confidence | Recommendation |
|----------------|----------------|------------|----------------|
| frida-hooking | — | No match | Proceed |
| coverage-analysis | testing-handbook:coverage-analysis | 90% | Improve existing |
| harness-writing | testing-handbook:harness-writing | 85% | Improve existing |
```

### Classification Rules

| Signal | Skill Type |
|--------|-----------|
| Has CLI commands, installation steps, config files | Tool |
| Describes a methodology applicable across multiple tools | Technique |
| Provides behavioral rules, best practices, or decision frameworks | Guidance |
| Focuses on finding vulnerabilities or security issues | Audit |
| Defines event hooks, slash commands, or automation | Hook/Command |
| Content is < 50 lines after extraction | Skip — insufficient content |

## Phase 2: Planning

Present a plan to the user before generating anything.

```markdown
# Skill Generation Plan

## Summary
- **Source:** {source_path_or_url}
- **Skills to generate:** {count}
- **Duplicates found:** {count}
- **Plugin name:** {plugin-name}

## Duplicate Check Results

| Candidate | Existing Match | Confidence | Action |
|-----------|---------------|------------|--------|
| {name} | {match or —} | {%} | {Proceed/Improve/Skip} |

## Skills to Generate

| # | Skill Name | Type | Source Section | Timelessness Est. |
|---|------------|------|---------------|--------------------|
| 1 | {name} | {type} | {section} | {High/Medium/Low} |

## Skipped Sections

| Section | Reason |
|---------|--------|
| {section} | {reason} |

## Actions
- [ ] Confirm and proceed
- [ ] Remove skill #X
- [ ] Change type for skill #Y
- [ ] Cancel
```

**Wait for explicit user approval before generating.**

## Phase 3: Generation

### Three-Pass Approach

**Pass 1 — Thinking Lenses (per skill):** Before writing any content, analyze the topic through at least 4 of these lenses. See [references/quality-standards.md](references/quality-standards.md) for details.

| Lens | Question It Answers |
|------|-------------------|
| First Principles | What is the irreducible core of this topic? |
| Inversion | What would a BAD skill for this topic look like? |
| Pre-Mortem | Assume the skill failed — why did it fail? |
| Devil's Advocate | What would a skeptic say about this skill's value? |
| Second-Order Thinking | If Claude follows this skill perfectly, what side effects occur? |
| Constraints Analysis | What can't this skill cover? What are its hard limits? |

Record lens outputs as internal notes. They inform content decisions but aren't included in the skill directly. Continue probing each lens until 2 consecutive rounds yield no new insights.

**Pass 2 — Content (parallel):** Generate all skills without cross-references.

For each skill:
1. Read the appropriate template from `templates/`
2. Read source content for this topic
3. Apply quality standards from `references/quality-standards.md`
4. Incorporate insights from thinking lenses into:
   - "When NOT to Use" (from Inversion + Constraints)
   - Anti-patterns (from Pre-Mortem + Devil's Advocate)
   - Decision trees (from First Principles decomposition)
5. Write SKILL.md with a placeholder for Related Skills:
   ```markdown
   ## Related Skills

   <!-- PASS3: populate after all skills exist -->
   ```

**Pass 3 — Cross-references (sequential):** After all Pass 2 skills exist:

1. List all generated skill names
2. For each skill, determine related skills based on:
   - Source content relationships (what references what)
   - Skill type relationships (tools → techniques they use)
   - Explicit mentions in content
3. Replace placeholder with actual Related Skills section
4. Validate all references point to existing skills

### Template Selection

Read the template matching the skill type:

- **Tool:** [templates/tool-skill.md](templates/tool-skill.md)
- **Technique:** [templates/technique-skill.md](templates/technique-skill.md)
- **Guidance:** [templates/guidance-skill.md](templates/guidance-skill.md)
- **Audit:** [templates/audit-skill.md](templates/audit-skill.md)
- **Hook/Command:** [templates/hook-command-skill.md](templates/hook-command-skill.md)

### Content Rules

| Rule | Rationale |
|------|-----------|
| SKILL.md under 500 lines | Longer files dilute signal; split into references/ |
| Every skill needs "When to Use" AND "When NOT to Use" | Sharp activation boundaries reduce false triggers |
| Third-person descriptions ("Analyzes X") | Consistent trigger format for skill selection |
| Description must include "Use when" or "Use for" | Required trigger phrase for activation |
| `{baseDir}` for all paths, never hardcode | Portability across environments |
| Code blocks preserve exact content from source | Accuracy over reformatting |
| Behavioral guidance over reference dumps | Teach Claude when and how, not just what |

## Phase 4: Two-Stage Review

After generation, review each skill in two stages. **The order matters** — reviewing quality on a skill that doesn't match the spec wastes effort.

### Stage 1: Spec Compliance

"Does this skill match what was planned?"

| Check | Question |
|-------|----------|
| Topic coverage | Does it cover the source material from the plan? |
| Type match | Does the content match the assigned type (tool/technique/etc.)? |
| Scope | Does it stay within its boundaries, not overlapping with other skills? |
| Source fidelity | Are code examples and commands preserved accurately from the source? |
| User requirements | Does it address any specific requests from the user? |

**If Stage 1 fails:** Fix the content to match the plan before proceeding to Stage 2. Do not review quality on misspecified content.

### Stage 2: Content Quality

"Is this skill good?"

Run the scored rubric from [references/validation.md](references/validation.md). Each skill gets a score out of 100 across 9 weighted criteria:

| Criterion | Weight | What It Measures |
|-----------|--------|-----------------|
| Structure & Anatomy | 10% | Frontmatter, required sections, line count |
| Content Quality | 20% | Explains WHY, concrete examples, tables over prose |
| Activation Precision | 15% | Description triggers correctly, no false activations |
| Domain Accuracy | 15% | Technical correctness, no outdated information |
| Timelessness | 10% | Will this still be useful in 2 years? |
| Reusability | 10% | Works across projects, not overfitted to one codebase |
| Zero-Shot Usability | 10% | A user with no context can follow this skill |
| Maintainability | 5% | Easy to update, clear content boundaries |
| Completeness | 5% | No missing sections for its type |

**Score thresholds:**

| Score | Rating | Action |
|-------|--------|--------|
| 90-100 | Excellent | Ship as-is |
| 80-89 | Good | Ship with minor notes |
| 70-79 | Acceptable | Ship, log improvements for next version |
| 60-69 | Needs Work | Fix before shipping (Phase 6) |
| < 60 | Insufficient | Major rework required (Phase 6) |

**Minimum score to ship: 70/100.**

## Phase 5: Timelessness Check

For each skill, evaluate durability:

| Question | Score |
|----------|-------|
| Does it reference specific version numbers that will become outdated? | -1 per pinned version without "or later" |
| Does it teach concepts vs. memorize current syntax? | +2 for conceptual, 0 for syntax-heavy |
| Would a tool upgrade break this skill's guidance? | -2 if yes, +1 if resilient |
| Does it link to official docs for version-specific details? | +1 for delegating specifics |
| Will the "When to Use" scenarios still exist in 2 years? | +2 if yes, -1 if tied to a trend |

**Target: >= 7/10.** If below, revise to:
- Replace pinned versions with "current version" + link to official docs
- Focus on durable concepts over transient syntax
- Add a "Version Notes" section for version-specific details that may change

## Phase 6: Fix and Iterate

For skills scoring below 70 or failing timelessness:

1. Apply fixes based on scored rubric feedback
2. Re-run Stage 2 scoring
3. Loop until score >= 70 and timelessness >= 7/10
4. Maximum 3 iterations — if still failing, flag to user with specific issues

## Phase 7: Finalize

After all skills pass review:

1. **Write plugin.json** if not already created
2. **Write README.md** for the plugin with a table of generated skills and scores
3. **Scaffold hooks/commands** if the hook-command template was used
4. **Report results** to user:

```markdown
# Generation Report

## Skills Generated

| Skill | Type | Score | Timelessness | Status |
|-------|------|-------|-------------|--------|
| {name} | {type} | {score}/100 | {score}/10 | SHIPPED |

## Duplicate Detections
- {count} duplicates detected, {count} skipped, {count} improved instead

## Review Summary
- Pass 1 (spec compliance): {pass}/{total}
- Pass 2 (quality): avg score {score}/100
- Iterations needed: {count}
```

## Example Usage

### From a Git Repository

```
User: "Generate skills from https://github.com/example/security-docs"

1. Clone or locate repository
2. Scan docs/ directory — find 5 topics
3. Duplicate check — 1 match found at 85%, recommend improve instead
4. Present plan: 3 tool skills, 1 technique, 1 improve-existing
5. On approval, run thinking lenses → generate in parallel
6. Two-stage review: spec then quality
7. Score: avg 82/100, all timelessness >= 7/10
8. Report and deliver
```

### Single Skill from Scratch

```
User: "Create a skill for Frida dynamic instrumentation"

1. Duplicate check — no existing Frida skill found
2. Select type: Tool (has CLI, installation, scripts)
3. Thinking lenses: First Principles (what IS dynamic instrumentation?),
   Inversion (what would a bad Frida skill look like?),
   Pre-Mortem (skill fails because it only covers iOS, not Android)
4. Use tool-skill template, generate SKILL.md
5. Two-stage review → Score: 78/100, timelessness 8/10
6. Ship
```

## Tips

**Do:**
- Always run duplicate detection before generating
- Apply at least 4 thinking lenses per skill
- Review spec compliance BEFORE content quality
- Target score >= 70 before shipping
- Include timelessness check for every skill
- Use hook-command template for automation-heavy plugins

**Don't:**
- Generate without duplicate check (creates ecosystem bloat)
- Skip thinking lenses (produces shallow skills)
- Review quality on misspecified content (fix spec first)
- Ship skills scoring below 70 without user acknowledgment
- Pin version numbers without linking to official docs
