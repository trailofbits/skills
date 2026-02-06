# Validation Methodology

How to validate generated skills before delivery.

## Quick Validation

Run these checks on every generated skill:

```
For each SKILL.md:
├─ YAML frontmatter parses correctly
│  ├─ `name` is present, kebab-case, ≤ 64 chars
│  ├─ `description` is present, ≤ 1024 chars
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
│  └─ No bare ``` without a language tag (```bash, ```python, etc.)
│
├─ No stale placeholders
│  └─ No {braces} placeholders left from templates
│
└─ Related Skills reference existing skills only
   └─ Every **skill-name** in Related Skills has a corresponding SKILL.md
```

## Validation Commands

### Frontmatter Check

```bash
# Extract frontmatter and check required fields
SKILL="path/to/SKILL.md"

# Check YAML parses
awk '/^---$/{if(++n==2)exit}n==1' "$SKILL" | head -20

# Check name format (manual inspection)
grep "^name:" "$SKILL"

# Check description has trigger phrase
grep -i "use when\|use for" "$SKILL"
```

### Structure Check

```bash
# Required sections
grep -c "^## When to Use" "$SKILL"          # Should be ≥ 1
grep -c "^## When NOT to Use" "$SKILL"       # Should be ≥ 1

# Line count
wc -l "$SKILL"                               # Should be < 500

# No hardcoded paths
grep -nE '/Users/|/home/|C:\\Users' "$SKILL" # Should return nothing
```

### Link Check

```bash
# Find all internal markdown links and verify they exist
SKILL_DIR=$(dirname "$SKILL")
grep -oE '\[.+\]\(([^)]+)\)' "$SKILL" | \
  grep -oE '\([^)]+\)' | tr -d '()' | \
  while read link; do
    [[ "$link" =~ ^https?:// ]] && continue
    [[ "$link" =~ ^# ]] && continue
    [ -f "$SKILL_DIR/$link" ] && echo "OK: $link" || echo "BROKEN: $link"
  done
```

### Placeholder Check

```bash
# Find unfilled template placeholders
grep -nE '\{[a-z_-]+\}' "$SKILL" | grep -v '{baseDir}'
# Should return nothing (except {baseDir} which is intentional)
```

## Section Requirements by Skill Type

| Section | Tool | Technique | Guidance | Audit |
|---------|------|-----------|----------|-------|
| When to Use | Required | Required | Required | Required |
| When NOT to Use | Required | Required | Required | Required |
| Quick Reference | Required | Required | Optional | Required |
| Rationalizations to Reject | — | — | — | **Required** |
| Core Workflow / Step-by-Step | Required | Required | Optional | — |
| Audit Workflow (phased) | — | — | — | **Required** |
| Common Patterns | — | Required | — | — |
| Anti-Patterns | Optional | Required | Required | — |
| Detection Patterns | — | — | — | Required |
| Severity Classification | — | — | — | Required |
| Decision Tree | Optional | Optional | Optional | Recommended |
| Tool-Specific Guidance | — | Required | — | — |
| Quality Checklist | Optional | Optional | Optional | **Required** |
| Related Skills | Required | Required | Optional | Required |
| Examples | Optional | Optional | Required | Optional |

## Content Quality Checks

### Description Quality

| Check | Pass | Fail |
|-------|------|------|
| Third-person voice | "Analyzes code for..." | "I help with..." |
| Specific trigger | "Use when fuzzing C/C++ with Clang" | "Use for security" |
| Includes differentiator | "Multi-core fuzzing with diverse mutations" | "Fuzzing tool" |

### Example Quality

Every skill should have at least one example that shows:
1. **Input** — what you start with
2. **Action** — what the skill directs you to do
3. **Output** — what you get

### Rationalization Quality (Audit Skills)

Each rationalization must have:
1. A specific shortcut someone might take (in quotes)
2. A concrete explanation of why it leads to missed findings
3. Not generic ("don't skip steps") but domain-specific

## Activation Testing

After validation, test that the skill activates correctly:

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

### Test 3: Negative Trigger

**Prompt:** A request that should NOT trigger the skill
**Expected:** Claude does NOT activate this skill

## Bulk Validation Report

When validating multiple skills:

```markdown
# Validation Report

| Skill | Lines | Frontmatter | Sections | Links | Result |
|-------|-------|-------------|----------|-------|--------|
| {name} | {count} | OK | OK | OK | PASS |
| {name} | {count} | OK | Missing: When NOT to Use | OK | FAIL |
| {name} | {count} | OK | OK | 1 broken | WARN |

## Summary
- Total: {count}
- Passed: {count}
- Failed: {count}
- Warnings: {count}

## Actions Needed
1. {skill}: {what to fix}
```

## Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| YAML parse error | Multi-line description without `>` | Use `>` for multi-line descriptions |
| Missing section | Template not fully populated | Fill from source content or remove if not applicable |
| Over 500 lines | Too much detail in SKILL.md | Split into references/ directory |
| Broken link | Reference file not created | Create file or remove link |
| No trigger phrase | Description missing "Use when/for" | Add trigger phrase to description |
| Stale placeholder | `{variable}` left from template | Replace with actual content |
| Activation conflict | Description too generic | Make trigger phrases more specific |
