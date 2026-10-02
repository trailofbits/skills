---
name: trailmark-variant-neighborhood
description: "Expands one confirmed or suspected vulnerability into a Trailmark graph neighborhood of variant candidates by finding sibling functions, shared callers and callees, common sensitive sinks, common entrypoint paths, interface implementations, override relationships, type/reference neighbors, and structurally similar nodes. Use after one issue is found to seed variant-analysis, semgrep-rule-creator, static-analysis, or manual review with graph-derived candidate locations."
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
  - Write
---

# Trailmark Variant Neighborhood

Expand one seed issue into graph-derived variant candidates. This skill
generates review targets, not confirmed findings.

## When to Use

- A finding is confirmed or plausible and variants may exist
- The vulnerable pattern depends on call context
- The issue involves a shared sink, source, validator, interface, override,
  trait, hook, handler, adapter, or critical type
- The next step is to seed `variant-analysis`, `semgrep-rule-creator`,
  `static-analysis`, or manual review

## When NOT to Use

- No seed issue exists. Use discovery or triage first.
- The pattern is purely syntactic and already obvious. Use
  `semgrep-rule-creator` directly.
- The question is exploit-chain composition across multiple findings. Use a
  composition workflow.
- The goal is remediation verification. Use a remediation-review workflow.
- The seed cannot be bound to a graph node.

## Rationalizations to Reject

| Rationalization | Why It Is Wrong | Required Action |
|---|---|---|
| "Nearby code means variant" | Proximity is only a candidate reason | Rank it as a review target |
| "Only exact same names matter" | Variants often share sinks or preconditions, not names | Expand across callers, callees, interfaces, and types |
| "Every candidate is a finding" | This skill outputs candidates for review | Avoid vulnerability claims |
| "Unreachable candidates can be ignored completely" | They may become reachable after refactors | Rank lower or list as deferred |
| "Graph candidates replace semantic pattern work" | Graph structure finds locations, not root-cause semantics | Hand off to variant-analysis, Semgrep, CodeQL, or manual review |

## Workflow

```
Variant Neighborhood Progress:
- [ ] Step 1: Normalize and bind the seed
- [ ] Step 2: Expand graph neighborhoods
- [ ] Step 3: Rank candidates
- [ ] Step 4: Extract variant pattern guidance
- [ ] Step 5: Emit handoff packet
```

### Step 1: Normalize And Bind The Seed

Accept finding text, file/line, function name, or output from
`trailmark-finding-triage`. Bind the seed to a Trailmark node and record the
root cause in plain language.

If the seed has no concrete graph binding, stop before inventing variants.

### Steps 1–3 in one call

Run the bundled script with the seed's file and line (or its Trailmark node id). It builds the
graph once, binds the seed, expands every dimension below, attaches the ranking signals
(reachability with trust level, taint, privilege boundary, blast radius, distance, penalty
flags), moves test/mock/generated/vendor nodes to `exclusions`, and applies the per-dimension
cap, listing what the cap dropped:

```bash
uv run {baseDir}/scripts/neighborhood.py --target <dir> --seed <file>:<line> [--cap 10] [--language auto] [--out neighborhood.json]
```

Its order is a signal sort, not a verdict. Read each candidate's code before ranking: a
candidate shares the seed's root cause only if the same unsafe data reaches the same kind of
operation, so a caller of the sink that passes constants ranks low even when reachable, and
an override that the graph cannot reach through dynamic dispatch can still rank high. Keep
the "candidate, not finding" wording. The candidate list holds at most the capped set per
dimension that the script returns; name the nodes it dropped under Exclusions and
Limitations rather than ranking them. Test, mock, generated and vendor code stays out of the
candidate list however it was found (script, grep, or reading), and goes under exclusions.

### Step 2: Expand Neighborhoods

Use the dimensions in
[references/neighborhood-patterns.md](references/neighborhood-patterns.md):

- shared callers
- shared callees and sinks
- entrypoint path neighbors
- interface, override, trait, and implementation siblings
- file or module cluster neighbors
- taint or privilege-boundary peers
- type and state-reference neighbors

Bound expansion to avoid candidate floods.

### Step 3: Rank Candidates

Rank with [references/ranking.md](references/ranking.md). Prioritize
entrypoint-reachable, tainted, boundary-adjacent, high-blast-radius, shared
sink, same-interface, and close-distance candidates. Penalize test, mock,
generated, vendor, unreachable, and trusted-internal-only candidates.

### Step 4: Extract Pattern Guidance

Summarize what should be searched for syntactically and what requires semantic
review. Identify whether follow-up belongs in:

- `variant-analysis`
- `semgrep-rule-creator`
- `static-analysis` with CodeQL or SARIF-producing tools
- manual review

### Step 5: Emit Handoff Packet

Use [references/output-format.md](references/output-format.md). Include
ranked candidates, inclusion reasons, exclusions, limitations, and the
variant-analysis handoff.

## Stop Conditions

- No graph binding exists
- Candidate count is too high and the root cause is underspecified
- Trailmark cannot analyze the target language
- The seed is only in test, generated, or vendor code and the user did not say
  that code is in scope
