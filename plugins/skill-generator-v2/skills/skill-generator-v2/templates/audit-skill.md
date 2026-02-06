# Audit Skill Template

Use for security review, vulnerability detection, compliance checking, and any skill where missed findings have real consequences.

## When to Use This Template

- The subject involves finding vulnerabilities, misconfigurations, or compliance issues
- Missed findings have security or safety consequences
- The skill needs strict workflow enforcement (no skipping steps)
- Examples: code review, vulnerability scanning, configuration auditing, spec compliance

## Template

```markdown
---
name: {audit-name-lowercase}
description: >
  {What this audit skill detects or verifies}.
  Use when {trigger — describe the audit scenario}.
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# {Audit Name}

{1-2 paragraph introduction: what this audit covers, why it matters,
and what the consequences of missing findings are.}

## When to Use

- {Specific audit scenario 1}
- {Specific audit scenario 2}
- {Specific audit scenario 3}

## When NOT to Use

- {Scenario where a different audit is needed}
- {Scenario where the target is out of scope}
- {Scenario where automated tools suffice without this skill}

## Rationalizations to Reject

| Rationalization | Why It's Wrong |
|----------------|----------------|
| "{Common shortcut 1}" | {Why this leads to missed findings} |
| "{Common shortcut 2}" | {Why this leads to missed findings} |
| "{Common shortcut 3}" | {Why this leads to missed findings} |
| "{Common shortcut 4}" | {Why this leads to missed findings} |
| "The tests pass" | Tests prove presence of tested behavior, not absence of bugs |
| "This is an edge case" | Attackers specifically target edge cases |

{Add 4-8 rationalizations specific to this audit domain. These block Claude
from taking shortcuts that lead to false negatives.}

## Quick Reference

{Decision aid for choosing the right approach}

| Scenario | Approach | Severity if Missed |
|----------|----------|--------------------|
| {Scenario 1} | {Approach} | {CRITICAL/HIGH/MEDIUM/LOW} |
| {Scenario 2} | {Approach} | {Severity} |
| {Scenario 3} | {Approach} | {Severity} |

## Severity Classification

| Severity | Criteria | Example |
|----------|----------|---------|
| CRITICAL | {What makes something critical} | {Concrete example} |
| HIGH | {What makes something high} | {Concrete example} |
| MEDIUM | {What makes something medium} | {Concrete example} |
| LOW | {What makes something low} | {Concrete example} |

## Audit Workflow

{Strict phased workflow — each phase MUST complete before the next}

### Phase 1: {Reconnaissance/Triage}

{Understand the target before looking for issues}

**Inputs:** {What you need}
**Outputs:** {What this phase produces}
**Quality gate:** {How to verify this phase is complete}

### Phase 2: {Analysis}

{Core analysis work}

**Inputs:** {What you need from Phase 1}
**Outputs:** {What this phase produces}

#### Checklist

- [ ] {Check 1}
- [ ] {Check 2}
- [ ] {Check 3}
- [ ] {Check 4}

### Phase 3: {Verification}

{Verify findings are real, not false positives}

**For each finding:**
1. Reproduce the issue
2. Confirm exploitability or impact
3. Rule out false positives
4. Classify severity

### Phase 4: {Reporting}

{Produce the final output}

**Finding format:**
\```markdown
### {Finding Title}

**Severity:** {CRITICAL/HIGH/MEDIUM/LOW}
**Location:** {file:line or component}
**Description:** {What the issue is}
**Impact:** {What an attacker or failure scenario looks like}
**Evidence:** {Proof — code snippet, command output, or trace}
**Recommendation:** {How to fix it}
\```

## Detection Patterns

{Specific patterns to look for during analysis}

### {Pattern Category 1}

| Pattern | What to Look For | Severity |
|---------|-----------------|----------|
| {Pattern 1} | {Specific code/config pattern} | {Severity} |
| {Pattern 2} | {Specific code/config pattern} | {Severity} |

### {Pattern Category 2}

| Pattern | What to Look For | Severity |
|---------|-----------------|----------|
| {Pattern 1} | {Specific code/config pattern} | {Severity} |
| {Pattern 2} | {Specific code/config pattern} | {Severity} |

## Red Flags

{Conditions that require immediate escalation or deeper analysis}

| Red Flag | Why It Matters | Action |
|----------|---------------|--------|
| {Red flag 1} | {Why this is dangerous} | {What to do} |
| {Red flag 2} | {Why this is dangerous} | {What to do} |

## Decision Tree

{For navigating complex audit scenarios}

\```
Finding something suspicious?

├─ Is it exploitable by an external attacker?
│  ├─ Yes → CRITICAL or HIGH
│  └─ No, but internal attacker could exploit?
│     ├─ Yes → HIGH or MEDIUM
│     └─ No → Check impact
│
├─ Does it affect data integrity or confidentiality?
│  ├─ Yes → At least MEDIUM
│  └─ No → LOW or informational
│
└─ Is it a defense-in-depth issue?
   ├─ Yes → LOW with recommendation
   └─ No → Informational only
\```

## Quality Checklist

{Final verification before delivering results}

- [ ] All phases of the workflow completed (no phases skipped)
- [ ] Every finding has evidence (code snippet, output, or trace)
- [ ] Severity classifications are justified
- [ ] False positives explicitly ruled out for each finding
- [ ] Recommendations are actionable (not just "fix this")
- [ ] Scope boundaries respected (no out-of-scope findings)
- [ ] Rationalizations in "Rationalizations to Reject" were not used

## Related Skills

### Complementary Audit Skills

| Skill | When to Use Together |
|-------|---------------------|
| **{audit-skill-1}** | {Integration scenario} |
| **{audit-skill-2}** | {Integration scenario} |

### Supporting Tools

| Skill | How It Helps |
|-------|-------------|
| **{tool-skill-1}** | {How this tool supports the audit} |
| **{tool-skill-2}** | {How this tool supports the audit} |

## Resources

**[{Title}]({URL})**
{Brief summary of key insights}
```

## Key Differences From Other Templates

| Aspect | Audit Skill | Tool/Technique Skill |
|--------|------------|---------------------|
| Workflow | Strict phases, no skipping | Flexible, user-directed |
| Must have | Rationalizations to Reject | Quick Reference |
| Key section | Detection Patterns + Severity | Core Workflow + Configuration |
| Quality gate | Evidence-based findings | Correct output |
| Failure mode | Missed vulnerability | Incorrect usage |

## Notes

- The Rationalizations to Reject section is NON-NEGOTIABLE for audit skills
- Every finding MUST have evidence — no "this might be an issue"
- Severity classification must be justified, not guessed
- Phased workflow prevents skipping reconnaissance (a common Claude failure mode)
- Quality checklist at the end catches incomplete work
- Decision trees help with severity classification edge cases
- Keep under 500 lines — extract detection patterns to references/ if extensive
