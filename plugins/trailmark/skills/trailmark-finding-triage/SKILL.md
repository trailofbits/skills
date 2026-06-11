---
name: trailmark-finding-triage
description: "Performs graph-assisted triage of a single security finding, SARIF result, weAudit annotation, suspicious function, or report excerpt using Trailmark reachability, entrypoint paths, taint, privilege-boundary, blast-radius, caller/callee, and neighborhood evidence. Use when deciding whether one candidate issue is reachable, prioritizing a finding before PoC work, preparing evidence for exploit validation, or checking whether a static-analysis result is actionable."
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
  - Write
---

# Trailmark Finding Triage

Build a concise graph evidence packet for one candidate finding. This skill
answers whether the affected code is reachable, what graph evidence supports
or weakens the claim, and what manual review is still required before calling
the issue exploitable.

## When to Use

- Triage one static-analysis result before spending PoC time
- Check whether a manual finding is entrypoint-reachable
- Build an evidence packet for PoC work
- Review a single suspicious function discovered during manual audit
- Decide whether one issue should be promoted, deprioritized, or treated as
  part of a broader chain analysis

## When NOT to Use

- Multiple weak findings might compose into a stronger chain. Use a chain or
  composition workflow instead.
- The user wants a full audit. Use an audit or design-review workflow instead.
- The user wants remediation verification for a known finding. Use a
  remediation-review workflow instead.
- The target is a PR or branch diff. Use `graph-evolution` plus a differential
  review workflow.
- No concrete finding, function, file/line, or suspicious sink exists yet. Use
  discovery skills first.

## Rationalizations to Reject

| Rationalization | Why It Is Wrong | Required Action |
|---|---|---|
| "The scanner says high severity, so reachability is obvious" | Static findings need graph and code context before promotion | Bind the finding to a graph node and check entrypoint paths |
| "No entrypoint path means impossible" | It may mean parser, proxy, or dynamic dispatch limitations | Report the limitation separately from reachability |
| "An auth check appears on the path, so the issue is safe" | The check may enforce the wrong predicate or be bypassed by another path | Treat validation/auth as review targets, not proof |
| "One reachable path is enough for a PoC claim" | The path still needs attacker-controlled inputs and compatible preconditions | Separate graph reachability from exploitability |
| "This is probably a chain" | Single-finding triage stops at one candidate | Hand off related findings to a composition workflow |

## Workflow

```
Finding Triage Progress:
- [ ] Step 1: Normalize the candidate
- [ ] Step 2: Build or reuse the Trailmark graph
- [ ] Step 3: Bind the candidate to graph node(s)
- [ ] Step 4: Analyze reachability, taint, boundaries, and blast radius
- [ ] Step 5: Decide and emit the evidence packet
```

### Step 1: Normalize the Candidate

Accept file/line, function name, SARIF result, weAudit annotation, Markdown
finding excerpt, or a manual claim. Normalize it to:

- title
- source type
- file path and line range if present
- function or node hint
- suspected source, sink, or asset
- claimed impact

If there is no concrete code anchor, stop and ask for one.

For input handling details, see
[references/input-normalization.md](references/input-normalization.md).

### Step 2: Build Or Reuse The Graph

Use the public `trailmark` skill workflow. Prefer an existing fresh exported
graph or `.trailmark/` artifact when present. Otherwise build a graph with
`language="auto"` or the target's explicit language list, then run
`engine.preanalysis()`.

Record the Trailmark version or feature probes used. Feature-gate Trailmark
0.4-only APIs with `hasattr()` or CLI help checks.

### Step 3: Bind The Candidate

Bind by file and line overlap first, then function name plus file. If several
nodes match, list every candidate and select the narrowest enclosing node as
primary. If no node matches, report a binding limitation instead of guessing.

SARIF and weAudit users should reuse the `audit-augmentation` workflow for
matching and then inspect the annotated node.

### Step 4: Analyze Graph Evidence

Run the query recipe in
[references/query-recipes.md](references/query-recipes.md):

- entrypoint paths to the bound node
- trust level of each path when available
- membership in `tainted`, `privilege_boundary`, and `high_blast_radius`
  subgraphs
- direct callers and callees
- high-impact downstream sinks
- sibling or nearby nodes worth manual review

Do not treat graph reachability as proof of exploitability.

### Step 5: Decide And Handoff

Produce one verdict:

| Verdict | Meaning |
|---|---|
| `Promote` | Graph evidence supports reachability and plausible impact |
| `Needs manual review` | Evidence is suggestive but not decisive |
| `Deprioritize` | No reachable path or only trusted/internal paths found |
| `Blocked` | Binding or Trailmark analysis failed |

Write the evidence packet using
[references/output-format.md](references/output-format.md).

Hand off promoted PoC-worthy issues to the user's PoC workflow. Hand off
related findings to a composition workflow. Hand off repeatable root causes to
`variant-analysis` or a custom Semgrep/CodeQL rule workflow.

## Example Prompts

- "Use Trailmark finding triage on `src/Vault.sol:148`; I think withdraw can
  bypass the balance update."
- "Triage this SARIF result before I spend PoC time: `semgrep:error
  unchecked-transfer` in `contracts/Bridge.sol` line 91."
- "This report excerpt claims `parse_packet` is attacker reachable. Build the
  Trailmark evidence packet and tell me what is still missing."
