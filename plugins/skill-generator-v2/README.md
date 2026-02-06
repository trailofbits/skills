# Skill Generator v2

Generate production-quality Claude Code skills from any documentation source with multi-agent review, quality scoring, and ecosystem-aware duplicate detection.

## What's New in v2

| Enhancement | What It Does |
|-------------|-------------|
| **Duplicate detection** | Scans local, marketplace, and community skills before creating — prevents ecosystem bloat |
| **Thinking lenses** | 6 analytical perspectives (First Principles, Inversion, Pre-Mortem, Devil's Advocate, Second-Order, Constraints) force deep analysis before writing |
| **Two-stage review** | Stage 1: spec compliance ("is this what was planned?"), Stage 2: content quality ("is this good?") — in that order |
| **Scored quality rubric** | 9-criteria weighted score (0-100) replaces binary pass/fail. Minimum 70 to ship |
| **Timelessness scoring** | Ensures skills teach durable concepts, not pinned-version syntax. Target >= 7/10 |
| **Hook/command template** | Scaffolds full plugins with hooks and slash commands, not just knowledge skills |

These techniques are drawn from SkillForge (thinking lenses, duplicate detection), Superpowers (two-stage review), Panaversity (scored rubric), and Trail of Bits (rationalizations, decision trees, progressive disclosure).

## Installation

```bash
# From the skills marketplace
claude skills install skill-generator-v2

# Or manually add to .claude/settings.json
{
  "plugins": [
    "./plugins/skill-generator-v2"
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

### Scaffold a Full Plugin (Skills + Hooks + Commands)

```
Create a plugin with a code style skill and pre-commit formatting hook
```

### Improve an Existing Skill

```
Score this skill against the quality rubric and improve it
```

## How It Works

### 1. Discovery + Duplicate Detection

Scans your documentation source, classifies topics into skill types, and checks for existing skills that already cover the same ground. Duplicates are flagged — you choose whether to create new or improve existing.

### 2. Planning

A generation plan with duplicate check results and timelessness estimates is presented for approval.

### 3. Three-Pass Generation

**Pass 1 (Lenses):** Each topic is analyzed through 4+ thinking lenses to identify failure modes, scope boundaries, and edge cases.
**Pass 2 (Content):** Skills are generated in parallel from templates, incorporating lens insights.
**Pass 3 (Cross-refs):** Related skills are linked after all content exists.

### 4. Two-Stage Review

**Stage 1:** Spec compliance — does the skill match what was planned?
**Stage 2:** Quality scoring — 9-criteria rubric producing a score out of 100.

### 5. Scoring + Iteration

Skills scoring below 70 are revised and re-scored, up to 3 iterations. Timelessness is checked separately (target >= 7/10).

## Skill Types

| Type | Template | Best For |
|------|----------|----------|
| **Tool** | `templates/tool-skill.md` | CLI tools, analysis software, frameworks |
| **Technique** | `templates/technique-skill.md` | Cross-cutting methodologies (harness writing, coverage) |
| **Guidance** | `templates/guidance-skill.md` | Behavioral rules, best practices, decision frameworks |
| **Audit** | `templates/audit-skill.md` | Security review, vulnerability detection, compliance |
| **Hook/Command** | `templates/hook-command-skill.md` | Event hooks, slash commands, automation plugins |

## Structure

```
plugins/skill-generator-v2/
├── .claude-plugin/
│   └── plugin.json
├── skills/
│   └── skill-generator-v2/
│       ├── SKILL.md                        # Main entry point (8-phase workflow)
│       ├── references/
│       │   ├── discovery.md                # Source analysis + duplicate detection
│       │   ├── quality-standards.md        # Thinking lenses + timelessness + ToB patterns
│       │   └── validation.md               # 9-criteria scored rubric
│       └── templates/
│           ├── tool-skill.md               # CLI tools, software
│           ├── technique-skill.md          # Cross-cutting methods
│           ├── guidance-skill.md           # Behavioral guidance
│           ├── audit-skill.md              # Security review
│           └── hook-command-skill.md       # Hooks + commands + skills
└── README.md
```

## Quality Scoring

Every generated skill receives a score out of 100:

| Criterion | Weight |
|-----------|--------|
| Content Quality | 20% |
| Activation Precision | 15% |
| Domain Accuracy | 15% |
| Structure & Anatomy | 10% |
| Timelessness | 10% |
| Reusability | 10% |
| Zero-Shot Usability | 10% |
| Maintainability | 5% |
| Completeness | 5% |

| Score | Rating | Action |
|-------|--------|--------|
| 90-100 | Excellent | Ship as-is |
| 80-89 | Good | Ship with minor notes |
| 70-79 | Acceptable | Ship, log improvements |
| 60-69 | Needs Work | Fix before shipping |
| < 60 | Insufficient | Major rework |

## Author

Trail of Bits

## License

See repository license.
