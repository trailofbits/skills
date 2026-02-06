# Skill Generator

Generate production-quality Claude Code skills from any documentation source — repositories, websites, PDFs, or local files.

## Overview

This plugin encodes the design patterns, quality standards, and generation workflow proven across 50+ skills in the Trail of Bits marketplace. It takes any documentation source and produces properly structured skills with:

- Sharp activation boundaries ("When to Use" / "When NOT to Use")
- Decision trees for branching logic
- Rationalizations to Reject (for security/audit skills)
- Cross-references between related skills
- Progressive disclosure (SKILL.md < 500 lines, details in references/)

## Installation

```bash
# From the skills marketplace
claude skills install skill-generator

# Or manually add to .claude/settings.json
{
  "plugins": [
    "./plugins/skill-generator"
  ]
}
```

## Usage

### Generate Skills from Documentation

```
Generate skills from the Frida documentation at https://frida.re/docs/
```

```
Create skills from ./docs/ directory in this repo
```

```
Turn the OWASP Testing Guide into Claude Code skills
```

### Create a Single Skill

```
Create a new skill for container security auditing
```

### Improve an Existing Skill

```
Review this skill against quality standards and improve it
```

## How It Works

### 1. Discovery

The generator analyzes your documentation source — scanning for topics, classifying them by type, and mapping relationships.

### 2. Planning

A generation plan is presented for your approval before any skills are created. You can add, remove, rename, or reclassify skills.

### 3. Two-Pass Generation

**Pass 1:** All skills are generated in parallel from templates, without cross-references.
**Pass 2:** Cross-references are populated after all skills exist, ensuring no broken links.

### 4. Validation

Every generated skill is checked for structure, content quality, and link integrity.

## Skill Types

| Type | Template | Best For |
|------|----------|----------|
| **Tool** | `templates/tool-skill.md` | CLI tools, analysis software, frameworks |
| **Technique** | `templates/technique-skill.md` | Cross-cutting methodologies (harness writing, coverage) |
| **Guidance** | `templates/guidance-skill.md` | Behavioral rules, best practices, decision frameworks |
| **Audit** | `templates/audit-skill.md` | Security review, vulnerability detection, compliance |

## Structure

```
plugins/skill-generator/
├── .claude-plugin/
│   └── plugin.json
├── skills/
│   └── skill-generator/
│       ├── SKILL.md                        # Main entry point
│       ├── references/
│       │   ├── discovery.md                # Source analysis methodology
│       │   ├── quality-standards.md        # Quality patterns from 50+ skills
│       │   └── validation.md               # Validation checklist
│       └── templates/
│           ├── tool-skill.md               # CLI tools, software
│           ├── technique-skill.md          # Cross-cutting methods
│           ├── guidance-skill.md           # Behavioral guidance
│           └── audit-skill.md              # Security review
└── README.md
```

## Quality Standards

Generated skills follow patterns proven across the Trail of Bits marketplace:

| Pattern | Purpose |
|---------|---------|
| "When to Use" / "When NOT to Use" | Sharp activation boundaries |
| Rationalizations to Reject | Block shortcuts in security skills |
| Decision trees | Guide branching logic |
| Progressive disclosure | Core in SKILL.md, details in references/ |
| Cross-references | Connect related skills |
| Evidence-based findings | Every claim needs proof (audit skills) |
| Anti-patterns with explanations | Teach WHY, not just WHAT |

## Author

Trail of Bits

## License

See repository license.
