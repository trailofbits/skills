# Mutation Testing Analysis Report

**Project:** [Project Name]
**Repository:** [Repository URL or Path]
**Analysis Date:** [Date]
**Mutation Testing Tool:** [Tool Name and Version]
**Analyzer:** [Agent and model, if known] with mutation-testing skill

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total mutants generated | [N] |
| Mutants killed | [N] |
| Mutants survived | [N] |
| Equivalent mutants (false positives) | [N] |
| Real surviving mutants | [N] |
| Unresolved survivors | [N] |
| Skipped or inconclusive mutants | [N] |
| Mutation kill rate (raw) | [N]% |
| Adjusted kill rate (excluding equivalent) | [N]% |

### Key Findings

[Describe the concrete testing gaps, affected behavior, and recommended tests. Explain the campaign's scope and rate denominators. Do not infer overall test quality from the adjusted kill rate. These findings concern weaknesses in tests, not confirmed vulnerabilities in the original code.]

### Severity Distribution

| Severity Tier | Count | Percentage of Real Survivors |
|---------------|-------|------------------------------|
| Critical (Security-Sensitive) | [N] | [N]% |
| High (Financial/State Integrity) | [N] | [N]% |
| Medium (Business Logic) | [N] | [N]% |
| Low (Observability) | [N] | [N]% |

---

## Equivalent Mutants (False Positives)

[One to two sentences explaining what equivalent mutants are and how many were identified in this analysis.]

| # | File | Line | Mutation | Equivalence Reason |
|---|------|------|----------|-------------------|
| 1 | [path/to/file] | [N] | `[original]` → `[mutated]` | [Brief explanation of why this is a false positive] |

---

## Tier 1: Critical — Security-Sensitive Findings

[One sentence introducing the tier and the number of findings.]

### Finding C-1: [Descriptive title]

**File:** `[path/to/file]`
**Line:** [N]
**Mutation:** `[original code]` → `[mutated code]`
**Mutation Operator:** [operator type, if known]

**Context:**
[One to two sentences describing what the mutated code does and what security property it enforces.]

**Responsible test file(s):** `[path/to/test/file]`
**Relevant test case(s):** `[test function name(s)]`

**Why this was not caught:**
[One to two paragraphs. Reference the existing test code and explain what assertion, branch, or edge case is missing. Be specific about the gap.]

**Recommended test improvement:**
[Specific, actionable description of what to add or modify in the test. Do not include code snippets — describe the change in prose.]

---

[Repeat for each Tier 1 finding: C-2, C-3, ...]

## Tier 2: High — Financial/State Integrity Findings

[One sentence introducing the tier and the number of findings.]

### Finding H-1: [Descriptive title]

[Same structure as Tier 1 findings.]

---

[Repeat for each Tier 2 finding: H-2, H-3, ...]

## Tier 3: Medium — Business Logic Findings

[One sentence introducing the tier and the number of findings.]

### Finding M-1: [Descriptive title]

[Same structure as Tier 1 findings.]

---

[Repeat for each Tier 3 finding: M-2, M-3, ...]

## Tier 4: Low — Observability Findings

[One sentence introducing the tier and the number of findings.]

### Finding L-1: [Descriptive title]

[Same structure as Tier 1 findings.]

---

[Repeat for each Tier 4 finding: L-2, L-3, ...]

## Recommendations

Organize all recommendations by test file, grouping related improvements across severity tiers. For each test file, list the findings it should address and summarize the changes needed.

## Unresolved Cases

[For each unresolved survivor, state its location, the uncertain behavior, and the evidence needed to classify it. Omit this section if there are none.]

---

## Appendix

### Input Files Analyzed

- [List of mutation result input files provided by the user]

### Source Files with Surviving Mutants

| File | Total Surviving | Critical | High | Medium | Low |
|------|----------------|----------|------|--------|-----|
| [path/to/file] | [N] | [N] | [N] | [N] | [N] |

### Methodology

This analysis follows Trail of Bits' mutation testing analysis methodology. Surviving mutants are classified by the impact type of the mutated code, not by the mutation operator used. Equivalent mutants are identified through type-system analysis and reachability checks. For background on mutation testing, see the Trail of Bits blog post "Use mutation testing to find the bugs your tests do not catch."
