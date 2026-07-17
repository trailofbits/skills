---
name: trailmark-review-gate
description: "Runs a Trailmark structural review gate over a branch, pull request, fix commit, release diff, or git ref range to detect new entrypoints, new tainted paths, removed validation or authorization calls, privilege-boundary drift, blast-radius growth, complexity growth, and newly reachable sensitive sinks. Use when reviewing a PR, branch, remediation commit, or release diff where graph-level security regressions should be checked before merge."
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
  - Write
---

# Trailmark Review Gate

Apply deterministic security gate rules to Trailmark structural diff evidence.
This skill does not replace line-level review. It produces a compact structural
packet reviewers can cite while they inspect the code.

## When to Use

- Reviewing a branch, pull request, release diff, or fix commit
- Checking whether a change expands attack surface
- Looking for removed validation or authorization on reachable paths
- Comparing before/after taint, privilege-boundary, blast-radius, or
  complexity signals
- Producing graph evidence for a differential review

## When NOT to Use

- Single-snapshot analysis. Use `trailmark` or `trailmark-structural`.
- Text-diff review only. Use `differential-review`.
- Full vulnerability discovery. Use an audit or bug-finding workflow.
- One static finding. Use `trailmark-finding-triage`.
- Tooling is unavailable and the user wants manual review only.

## Rationalizations to Reject

| Rationalization | Why It Is Wrong | Required Action |
|---|---|---|
| "The line diff is small, so no graph gate is needed" | Small changes can create new call paths | Compare before/after graphs |
| "Graph gate passed, so the PR is secure" | The gate only checks structural regressions | Still perform line-level review |
| "Trailmark failed, so pass the gate" | Tool failure is unknown risk, not success | Emit `UNKNOWN` |
| "Tests pass, so removed validation is fine" | Tests may miss affected entrypoint paths | Review the removed path manually |
| "Only new code matters" | Removed auth, validation, and callers can be higher risk than additions | Review removals and path changes |

## Workflow

```
Review Gate Progress:
- [ ] Step 1: Resolve before/after inputs
- [ ] Step 2: Build graph-evolution evidence
- [ ] Step 3: Normalize structural changes
- [ ] Step 4: Apply gate rules
- [ ] Step 5: Emit review packet and actions
```

### Step 1: Resolve Inputs

Accept two refs, a branch name, a commit range, or before/after directories.
Do not check out branches unnecessarily. Prefer `git diff`, `git show`, and
git worktrees, following the `graph-evolution` snapshot workflow.

### Step 2: Build Graph Evidence

Run `graph-evolution` or equivalent Trailmark before/after graph analysis.
Both snapshots must run `engine.preanalysis()` so taint, privilege-boundary,
blast-radius, complexity, and entrypoint signals are available.

Record Trailmark version and any feature probes. If graph construction fails,
emit `UNKNOWN`.

### Step 3: Normalize Changes

Normalize evidence into:

- added, removed, and modified nodes
- added and removed edges
- entrypoint set changes
- taint membership changes
- privilege-boundary membership changes
- blast-radius changes
- complexity changes
- newly reachable sensitive sinks
- unresolved, proxy, or dynamic edge changes

### Step 4: Apply Gate Rules

Apply the rules in [references/gate-rules.md](references/gate-rules.md).
Gate verdicts are:

| Verdict | Meaning |
|---|---|
| `FAIL` | A high-risk structural regression needs review before acceptance |
| `WARN` | A meaningful graph change needs reviewer attention |
| `PASS` | No configured structural gate fired |
| `UNKNOWN` | Trailmark failed or evidence is too incomplete |

### Step 5: Emit Packet

Write the packet using
[references/output-format.md](references/output-format.md), then hand it to
the branch reviewer. Use
[references/review-integration.md](references/review-integration.md) when
combining this packet with `differential-review` or another PR review process.

## Requirements

- Never mutate the user's working branch while comparing refs.
- Never report `PASS` when Trailmark failed.
- Separate graph evidence from manual security judgment.
- Include exact changed nodes or paths for every `FAIL` and `WARN`.
- Include limitations when parser, proxy, unresolved-call, or dynamic-dispatch
  uncertainty affects the verdict.
