# Analyzing Mutation Testing Results

Analyzes mutation testing campaign results to identify testing gaps, classify surviving mutants by severity, filter equivalent mutants, and produce a structured report.

This workflow is tool-agnostic and language-agnostic. It is used together with the equivalence catalog, severity guide, and report template loaded alongside it; those files hold the criteria, this file holds the procedure.

## When to Use

- The user provides mutation testing results (surviving mutants with file paths, line numbers, and code changes)
- The user wants to know which survivors are real testing gaps versus equivalent mutants
- The user wants a structured report prioritizing which tests to improve

## When NOT to Use

- Running mutation testing tools (this workflow analyzes results, it does not generate them)
- Writing or modifying test code (it recommends improvements, it does not implement them)
- Choosing which mutation testing tool to use
- Coverage analysis without mutation data, or code review and vulnerability discovery (use audit-context-building or wilson)

## Rationalizations to Reject

**"The kill rate is above 80%, so the test suite is adequate."** Aggregate metrics hide individual critical gaps. One survivor in access control matters more than a hundred killed mutants in logging.

**"This is probably an equivalent mutant."** Equivalence is proven from the type system and control flow, never assumed. Absence of a distinguishing test is not proof.

**"Boundary changes like `>` to `>=` are always equivalent."** They are equivalent only when the boundary value is provably unreachable. A reachable boundary is a real finding.

**"The test suite catches this in practice even though the mutant survived."** If the mutant survived, the suite does not catch it. That is what surviving means.

**"Only the top tier is worth reporting."** Lower tiers are still concrete, actionable test improvements. Even event-emission survivors reveal missing assertions that matter for monitoring and integration.

**"I can classify this without reading the source."** Severity depends on what the mutated code does, and equivalence depends on types and reachability. Both require the source at the mutation site.

---

## Workflow

### Phase 1: Parse Input

**Entry:** The user has provided mutation testing results.

1. Read the input and identify its format. Most tools (mewt/muton, mutmut, cargo-mutants, mutahunter) produce JSON or CSV that parses directly from field names; when the structure is not obvious, read the first 50 lines before proceeding. The input-formats reference covers the tools whose output is not self-describing.
2. Confirm it is mutation testing output — expect file paths, line numbers, and a status field.
3. Extract each surviving mutant: file path, line number, original code, mutated code, mutation operator if available. Filter to surviving/uncaught status only.

For mewt/muton projects, run the skill's `scripts/survivors.py` (`uv run <skill dir>/scripts/survivors.py --results <results.json> --status <status.txt>`, or with no flags inside the campaign directory, where it calls `mewt results --format json` and `mewt status` itself). It lists every uncaught mutant with id, slug, 1-based line range, original and mutated text and the tests that passed against it, plus the campaign totals and the test files, so the results JSON does not need to be read. Do not re-derive line numbers from `line_offset` (it is 0-based).

**Exit:** Structured list of surviving mutants.

---

### Phase 2: Gather Context

**Entry:** Phase 1 complete.

When `survivors.py` was used, its numbered source windows and test files are the context: Read further only where a function extends past a window or a test file is marked "not shown". Otherwise, group mutants by source file to batch Read calls and read each mutation site. Either way, establish: what the code does, the types involved, whether the code is reachable, and whether it is security-sensitive, financial, business logic, or observability.

**Exit:** Context gathered for every mutant.

---

### Phase 3: Filter Equivalent Mutants

**Entry:** Phase 2 complete.

Apply the five-check verification procedure from the equivalence catalog to each mutant: type context, reachability, downstream consumption, semantic comparison, and a distinguishing-test attempt. Classify identical behavior as equivalent and an observable difference missed by tests as a testing gap. Keep uncertain cases unresolved and describe the missing evidence.

The catalog also lists the patterns that look equivalent but are not — treat those as real findings.

**Exit:** Each mutant classified as equivalent, a testing gap, or unresolved.

---

### Phase 4: Classify Severity

**Entry:** Phase 3 complete.

Assign each confirmed testing gap a priority tier using the criteria in the severity guide, based on what the mutated code does. Explain uncertain impact instead of automatically raising the tier. These tiers prioritize testing work and do not establish vulnerability severity in the original program.

**Exit:** Every real mutant has a tier.

---

### Phase 5: Analyze Test Gaps

**Entry:** Phase 4 complete.

For each real survivor:

1. **Find the responsible test file.** Most ecosystems follow a convention (`src/x.rs` → `tests/x.rs` or an in-file `#[cfg(test)]` module, `x.py` → `test_x.py`, `x.go` → `x_test.go`, `X.sol` → `X.t.sol`). When the convention does not hold, Grep for imports of the mutated module.
2. **Read the tests that exercise the mutated code** and identify which case should have caught the mutation.
3. **Explain why it did not** — missing assertion, uncovered branch, missing edge case, insufficient input variety, or a test that exercises the code without verifying its output.
4. **State concretely how to close the gap:** which assertion to add, which input to use, which branch to cover.

If no test touches the mutated code at all, say so — that is a stronger finding than a weak assertion.

**Exit:** Every real mutant has a test file, a gap explanation, and a recommendation.

---

### Phase 6: Report

**Entry:** Phase 5 complete.

Write the report to `mutation-testing-report.md` in the working directory, following the structure in the report template.

Compute every statistic from the parsed data. State the denominator for each rate and account for skipped, timed-out, and unresolved cases separately. Report raw and equivalence-adjusted rates only when the supplied data supports them. A rate summarizes this campaign and does not establish overall test adequacy.

Match report length to the number of findings. Each finding needs its context, gap explanation, and recommendation; it does not need restating in a summary section, and tiers with no findings can be omitted rather than padded.

**Exit:** Report written.

---

## Analysis Requirements

- **Every surviving mutant is analyzed individually** — no skipping, summarizing, or batching. Each one gets context, an equivalence check, a severity tier, a test gap, and a recommendation.
- **Work in severity order** (Tier 1 and 2 first) so the highest-value analysis is complete if context runs short.
- **Save intermediate progress** if the session may end before the analysis does.
- Write in formal, objective, third-person voice, active voice, present tense. Use inline code formatting for paths, function names, and snippets. Describe recommended test changes in prose rather than writing out test code.
