# Validation Methodology

How to validate generated skills before delivery. V2 adds a scored quality rubric that replaces binary pass/fail with a 100-point score across 9 weighted criteria.

## Quick Validation (Structural)

Run these checks on every generated skill first — they're binary pass/fail:

```
For each SKILL.md:
├─ YAML frontmatter parses correctly
│  ├─ `name` is present, kebab-case, <= 64 chars
│  ├─ `description` is present, <= 1024 chars
│  └─ `description` contains "Use when" or "Use for"
│
├─ Required sections present
│  ├─ "## When to Use" heading exists
│  └─ "## When NOT to Use" heading exists
│
├─ Line count < 500
│
├─ No hardcoded paths
│  └─ No matches for /Users/, /home/, C:\Users\
│
├─ Internal links resolve
│  └─ Every [text](path.md) link points to an existing file
│
├─ Code blocks have language specifiers
│  └─ No bare ``` without a language tag
│
├─ No stale placeholders
│  └─ No {braces} placeholders left from templates
│
└─ Related Skills reference existing skills only
   └─ Every **skill-name** in Related Skills has a corresponding SKILL.md
```

**If any structural check fails, fix it before running the scored rubric.**

## Scored Quality Rubric

After structural validation passes, score the skill across 9 weighted criteria. Each criterion scores 0-3, then is multiplied by its weight to produce a final score out of 100.

### Scoring Scale

| Score | Meaning |
|-------|---------|
| 0 | Missing or fundamentally broken |
| 1 | Present but weak — needs significant improvement |
| 2 | Good — meets expectations with minor gaps |
| 3 | Excellent — exceeds expectations, exemplary |

### The 9 Criteria

#### 1. Structure & Anatomy (Weight: 10%)

| Score | Criteria |
|-------|---------|
| 0 | Missing frontmatter or required sections |
| 1 | Has frontmatter and basic sections, poor organization |
| 2 | Well-organized, all required sections for its type, clear hierarchy |
| 3 | Perfect structure, decision tree present, progressive disclosure with references/ |

#### 2. Content Quality (Weight: 20%)

| Score | Criteria |
|-------|---------|
| 0 | Reference dump or generic content Claude already knows |
| 1 | Some unique guidance but mostly "what" without "why" |
| 2 | Explains WHY, has concrete examples, tables over prose |
| 3 | Every instruction has rationale, multiple concrete examples, anti-patterns with explanations |

#### 3. Activation Precision (Weight: 15%)

| Score | Criteria |
|-------|---------|
| 0 | Description is vague ("helps with security"), no trigger phrases |
| 1 | Has trigger phrase but too broad (would activate on unrelated prompts) |
| 2 | Specific triggers, clear "When to Use", reasonable "When NOT to Use" |
| 3 | Precise triggers tested against both positive and negative cases, no false activations |

#### 4. Domain Accuracy (Weight: 15%)

| Score | Criteria |
|-------|---------|
| 0 | Contains factual errors or outdated information |
| 1 | Mostly correct but some inaccuracies or missing caveats |
| 2 | Technically correct, code examples work, commands are valid |
| 3 | Expert-level accuracy, addresses edge cases, caveats included |

#### 5. Timelessness (Weight: 10%)

| Score | Criteria |
|-------|---------|
| 0 | Pinned to specific versions, will break on next upgrade |
| 1 | Some version pinning, core concepts are version-dependent |
| 2 | Concepts are durable, version-specific details delegated to docs |
| 3 | Teaches principles, resilient to upgrades, explicit version notes |

#### 6. Reusability (Weight: 10%)

| Score | Criteria |
|-------|---------|
| 0 | Only works for one specific project or codebase |
| 1 | Works for similar projects in same language/framework |
| 2 | Works across projects in the skill's domain |
| 3 | Works across projects and includes adaptation guidance for edge cases |

#### 7. Zero-Shot Usability (Weight: 10%)

| Score | Criteria |
|-------|---------|
| 0 | Requires significant prior context to understand |
| 1 | Prerequisites unclear, workflow assumes knowledge |
| 2 | Clear prerequisites, workflow can be followed from scratch |
| 3 | Quick start section, zero-to-working example, troubleshooting for common first-time issues |

#### 8. Maintainability (Weight: 5%)

| Score | Criteria |
|-------|---------|
| 0 | Monolithic, no clear content boundaries |
| 1 | Some structure but hard to update specific sections |
| 2 | Clear section boundaries, references/ used for detailed content |
| 3 | Modular, each section independently updatable, version notes pattern used |

#### 9. Completeness (Weight: 5%)

| Score | Criteria |
|-------|---------|
| 0 | Missing multiple required sections for its type |
| 1 | Has required sections but gaps in content |
| 2 | All required sections filled, no obvious gaps |
| 3 | All sections plus optional enhancements (decision tree, quality checklist) |

### Calculating the Score

```
Final Score = Σ (criterion_score / 3 × weight × 100)

Example:
  Structure:    3/3 × 10% = 10.0
  Content:      2/3 × 20% = 13.3
  Activation:   3/3 × 15% = 15.0
  Domain:       2/3 × 15% = 10.0
  Timelessness: 2/3 × 10% =  6.7
  Reusability:  2/3 × 10% =  6.7
  Zero-Shot:    2/3 × 10% =  6.7
  Maintain:     2/3 ×  5% =  3.3
  Completeness: 3/3 ×  5% =  5.0
  ─────────────────────────────
  TOTAL:                   76.7/100 → Acceptable (ship)
```

### Score Thresholds

| Score | Rating | Action |
|-------|--------|--------|
| 90-100 | Excellent | Ship as-is |
| 80-89 | Good | Ship with minor improvement notes |
| 70-79 | Acceptable | Ship, log improvements for next version |
| 60-69 | Needs Work | Fix lowest-scoring criteria before shipping |
| < 60 | Insufficient | Major rework — identify root cause and rebuild |

**Minimum score to ship: 70/100.**

### Scorecard Template

```markdown
## Scorecard: {skill-name}

| # | Criterion | Weight | Score (0-3) | Weighted |
|---|-----------|--------|-------------|----------|
| 1 | Structure & Anatomy | 10% | {score} | {weighted} |
| 2 | Content Quality | 20% | {score} | {weighted} |
| 3 | Activation Precision | 15% | {score} | {weighted} |
| 4 | Domain Accuracy | 15% | {score} | {weighted} |
| 5 | Timelessness | 10% | {score} | {weighted} |
| 6 | Reusability | 10% | {score} | {weighted} |
| 7 | Zero-Shot Usability | 10% | {score} | {weighted} |
| 8 | Maintainability | 5% | {score} | {weighted} |
| 9 | Completeness | 5% | {score} | {weighted} |
| | **TOTAL** | **100%** | | **{total}/100** |

**Rating:** {Excellent/Good/Acceptable/Needs Work/Insufficient}
**Action:** {Ship/Fix/Rework}

### Improvement Notes
- {Lowest criterion}: {specific improvement suggestion}
- {Second lowest}: {specific improvement suggestion}
```

## Two-Stage Review Process

### Stage 1: Spec Compliance (before scoring)

"Does this skill match what was planned?"

| Check | Question |
|-------|----------|
| Topic coverage | Does it cover the source material from the plan? |
| Type match | Does the content match the assigned type? |
| Scope | Does it stay within its boundaries? |
| Source fidelity | Are code examples preserved accurately? |
| User requirements | Does it address specific user requests? |

**If Stage 1 fails:** Fix content to match plan. Do not score quality on misspecified content.

### Stage 2: Quality Scoring (the rubric above)

Run only after Stage 1 passes. Apply the 9-criteria rubric.

## Section Requirements by Skill Type

| Section | Tool | Technique | Guidance | Audit | Hook/Cmd |
|---------|------|-----------|----------|-------|----------|
| When to Use | Required | Required | Required | Required | Required |
| When NOT to Use | Required | Required | Required | Required | Required |
| Quick Reference | Required | Required | Optional | Required | Required |
| Rationalizations | — | — | — | **Required** | — |
| Core Workflow | Required | Required | Optional | — | Required |
| Audit Workflow | — | — | — | **Required** | — |
| Common Patterns | — | Required | — | — | — |
| Anti-Patterns | Optional | Required | Required | — | Optional |
| Detection Patterns | — | — | — | Required | — |
| Severity Class. | — | — | — | Required | — |
| Decision Tree | Optional | Optional | Optional | Recommended | Optional |
| Tool-Specific | — | Required | — | — | — |
| Quality Checklist | Optional | Optional | Optional | **Required** | Optional |
| Related Skills | Required | Required | Optional | Required | Optional |
| Examples | Optional | Optional | Required | Optional | Required |
| Hook Definitions | — | — | — | — | Required |

## Activation Testing

After scoring, test that the skill activates correctly:

### Test 1: Direct Invocation

**Prompt:** "Use the {skill-name} skill"
**Expected:** Claude loads and references the skill content

### Test 2: Implicit Trigger

**Prompt:** A natural request that should trigger the skill
**Expected:** Claude selects this skill based on description matching

| Skill Type | Example Trigger Prompt |
|------------|----------------------|
| Tool | "Help me set up {tool} for my project" |
| Technique | "How should I write a harness for this parser?" |
| Guidance | "I'm not sure about the requirements, what should I do?" |
| Audit | "Review this code for security issues" |
| Hook/Command | "Set up a pre-commit hook for this project" |

### Test 3: Negative Trigger

**Prompt:** A request that should NOT trigger the skill
**Expected:** Claude does NOT activate this skill

## Bulk Validation Report

When validating multiple skills:

```markdown
# Validation Report

| Skill | Lines | Structural | Score | Timelessness | Rating |
|-------|-------|-----------|-------|-------------|--------|
| {name} | {n} | PASS | {n}/100 | {n}/10 | {rating} |
| {name} | {n} | PASS | {n}/100 | {n}/10 | {rating} |
| {name} | {n} | FAIL: {reason} | — | — | BLOCKED |

## Summary
- Total: {count}
- Shipped (>=70): {count}
- Needs fix (60-69): {count}
- Blocked (structural fail or <60): {count}
- Average score: {score}/100

## Actions Needed
1. {skill}: {lowest criterion} — {specific fix}
```

## Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| YAML parse error | Multi-line description without `>` | Use `>` for multi-line descriptions |
| Missing section | Template not fully populated | Fill from source content |
| Over 500 lines | Too much detail in SKILL.md | Split into references/ |
| Broken link | Reference file not created | Create file or remove link |
| No trigger phrase | Description missing "Use when/for" | Add trigger phrase |
| Stale placeholder | `{variable}` left from template | Replace with actual content |
| Low activation score | Description too generic | Make triggers more specific |
| Low timelessness | Pinned versions, syntax-heavy | Teach concepts, delegate versions |
| Low content quality | "What" without "why" | Add rationale to each instruction |
| Low zero-shot | Assumed prior knowledge | Add prerequisites, quick start |
