---
name: skill-generator
description: >
  Generates Claude Code skills from any documentation source — repositories,
  websites, PDFs, or local files. Use when creating new skills, converting
  documentation into skills, or bulk-generating skills from a knowledge base.
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

# Skill Generator

Generate production-quality Claude Code skills from any documentation source. This skill encodes the design patterns, quality standards, and generation workflow proven across 50+ skills in the Trail of Bits marketplace.

## When to Use

- Converting existing documentation (repos, websites, PDFs) into Claude Code skills
- Creating a new skill from scratch with proper structure and quality
- Bulk-generating skills from a documentation source with multiple topics
- Improving an existing skill to meet marketplace quality standards

## When NOT to Use

- Writing a simple CLAUDE.md project configuration (no plugin structure needed)
- The documentation source is a single paragraph or trivial content
- You need a slash command or hook, not a knowledge skill

## Decision Tree

```
What do you need?

├─ Generate skills from a documentation source?
│  └─ Read: Phase 0-5 workflow below
│     Start with discovery, then plan, then generate
│
├─ Create a single new skill from scratch?
│  └─ Read: templates/ for the right template
│     Pick: tool, technique, guidance, or audit
│     Then follow Phase 3 (generation) directly
│
├─ Improve an existing skill?
│  └─ Read: references/quality-standards.md
│     Apply the quality checklist to the existing skill
│
├─ Understand what makes a good skill?
│  └─ Read: references/quality-standards.md
│     Key patterns: rationalizations, decision trees, scope boundaries
│
└─ Validate a generated skill?
   └─ Read: references/validation.md
      Run the validation checklist
```

## Quick Reference

### Skill Type Selection

| Your Content Is About | Skill Type | Template |
|----------------------|------------|----------|
| A CLI tool or analysis tool | Tool | `templates/tool-skill.md` |
| A cross-cutting methodology | Technique | `templates/technique-skill.md` |
| Best practices or behavioral guidance | Guidance | `templates/guidance-skill.md` |
| Security review or vulnerability detection | Audit | `templates/audit-skill.md` |

### Source Type Handling

| Source | Discovery Approach |
|--------|-------------------|
| Git repository | Scan directory structure, read markdown files, parse frontmatter |
| Website / docs site | WebFetch key pages, extract structure from navigation |
| PDF documents | Read with PDF support, extract sections by heading |
| Local files | Glob for markdown/text files, read and classify |
| Mixed sources | Combine approaches, deduplicate overlapping content |

## Workflow Overview

```
Phase 0: Setup              Phase 1: Discovery
┌─────────────────┐        ┌─────────────────┐
│ Locate source   │   →    │ Analyze content │
│ - Find docs     │        │ - Scan sections │
│ - Confirm path  │        │ - Classify types│
│ - Choose output │        │ - Map relations │
└─────────────────┘        └─────────────────┘
         ↓                          ↓
Phase 3: Generation        Phase 2: Planning
┌─────────────────┐        ┌─────────────────┐
│ TWO-PASS GEN    │   ←    │ Present plan    │
│ Pass 1: Content │        │ - Skill list    │
│ Pass 2: X-refs  │        │ - Types assigned│
│ - Apply template│        │ - User approval │
└─────────────────┘        └─────────────────┘
         ↓
Phase 4: Validation        Phase 5: Finalize
┌─────────────────┐        ┌─────────────────┐
│ Quality checks  │   →    │ Post-generation │
│ - Structure     │        │ - Update README │
│ - Content       │        │ - Register      │
│ - Activation    │        │ - Report results│
└─────────────────┘        └─────────────────┘
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
└── README.md
```

Ask the user for the plugin name, or derive it from the source.

## Phase 1: Discovery

See [references/discovery.md](references/discovery.md) for the full methodology.

**Quick version:**

1. **Scan** the source for distinct topics, tools, or techniques
2. **Classify** each topic into a skill type (tool, technique, guidance, audit)
3. **Map relationships** between topics (which reference each other?)
4. **Estimate scope** — flag topics with too little content to warrant a skill

### Classification Rules

| Signal | Skill Type |
|--------|-----------|
| Has CLI commands, installation steps, config files | Tool |
| Describes a methodology applicable across multiple tools | Technique |
| Provides behavioral rules, best practices, or decision frameworks | Guidance |
| Focuses on finding vulnerabilities or security issues | Audit |
| Content is < 50 lines after extraction | Skip — insufficient content |

## Phase 2: Planning

Present a plan to the user before generating anything.

```markdown
# Skill Generation Plan

## Summary
- **Source:** {source_path_or_url}
- **Skills to generate:** {count}
- **Plugin name:** {plugin-name}

## Skills to Generate

| # | Skill Name | Type | Source Section |
|---|------------|------|---------------|
| 1 | {name} | {type} | {section} |
| 2 | {name} | {type} | {section} |

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

### Two-Pass Approach

**Pass 1 — Content (parallel):** Generate all skills without cross-references.

For each skill:
1. Read the appropriate template from `templates/`
2. Read source content for this topic
3. Apply quality standards from `references/quality-standards.md`
4. Write SKILL.md with a placeholder for Related Skills:
   ```markdown
   ## Related Skills

   <!-- PASS2: populate after all skills exist -->
   ```

**Pass 2 — Cross-references (sequential):** After all Pass 1 skills exist:

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

### Line Count Splitting

If a skill exceeds 450 lines:

1. Extract standalone sections (installation, advanced usage, CI/CD) into `references/`
2. Add a decision tree to SKILL.md pointing to extracted files
3. Target SKILL.md under 400 lines after split

## Phase 4: Validation

See [references/validation.md](references/validation.md) for the full checklist.

**Quick validation:**

```
For each generated skill, verify:
├─ YAML frontmatter parses (name, description present)
├─ Name is kebab-case, ≤64 characters
├─ Description includes "Use when" or "Use for"
├─ "When to Use" section present
├─ "When NOT to Use" section present
├─ Line count < 500
├─ All internal links resolve
├─ No hardcoded paths (/Users/..., /home/...)
├─ Code blocks have language specifiers
└─ Related Skills reference existing skills only
```

## Phase 5: Finalize

After all skills pass validation:

1. **Write plugin.json** if not already created
2. **Write README.md** for the plugin with a table of generated skills
3. **Report results** to user with summary

## Example Usage

### From a Git Repository

```
User: "Generate skills from https://github.com/example/security-docs"

1. Clone or locate repository
2. Scan docs/ directory — find 5 topics
3. Present plan: 3 tool skills, 2 technique skills
4. On approval, generate in parallel
5. Populate cross-references
6. Validate and report
```

### Single Skill from Scratch

```
User: "Create a skill for Frida dynamic instrumentation"

1. Select type: Tool (has CLI, installation, scripts)
2. Use tool-skill template
3. WebFetch Frida docs for content
4. Generate SKILL.md with proper structure
5. Validate and report
```

### From a Website

```
User: "Turn the OWASP Testing Guide into skills"

1. WebFetch table of contents
2. Identify sections → skill candidates
3. Present plan (may be 10+ skills)
4. Generate in batches with cross-references
5. Validate and report
```

## Tips

**Do:**
- Always present a plan before generating
- Use the appropriate template for each skill type
- Include "Rationalizations to Reject" for audit/security skills
- Add decision trees for skills with branching logic
- Cross-reference related skills

**Don't:**
- Generate without user approval
- Paste entire reference documents into SKILL.md (link to references/ instead)
- Skip the "When NOT to Use" section
- Hardcode absolute paths
- Exceed 500 lines per SKILL.md
