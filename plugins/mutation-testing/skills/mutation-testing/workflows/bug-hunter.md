# Bug Hunting with Mutation Testing

Uses mutation testing results as a map to untested code, then hunts for real bugs there.

## Core Principle

**Uncaught mutants reveal blind spots in testing, and blind spots are where bugs hide.**

A missing test is not a bug — it is a signal about where to look. The deliverable of this workflow is confirmed bugs with proof-of-concept reproductions, not a list of coverage gaps. Report an uncaught mutant only after investigating the code behind it and finding something actually wrong.

Use this workflow for security audits, code review, risk assessment of legacy code, and pre-release validation. It does not guide test implementation or assess test quality — for a structured report on testing gaps themselves, use the analyzing-results workflow instead.

---

## Prerequisites

A completed campaign (`mewt run [paths]`) with results available (`mewt status`).

---

## Workflow

### Step 1: Identify High-Risk Code

**Entry:** Campaign finished, results available.

1. Get the overview with `mewt status` and identify files with surviving mutations. Record the campaign scope and inconclusive results before using scores to prioritize.
2. Cross-reference against sensitivity. Security-sensitive areas — auth, crypto, parsing, input validation — and core business logic deserve attention regardless of score; recently changed code with a low score deserves it most.
3. Pull the survivors for those areas:
   ```bash
   mewt results --target 'src/auth/**'
   mewt results --target 'src/crypto/**' --severity high
   ```

Rank targets as: critical code with a low score, then critical code at any score (crypto at 80% is still worth reading), then core logic with a low score, then everything else.

**Exit:** Prioritized list of files to investigate.

---

### Step 2: Prioritize Individual Mutants

**Entry:** Step 1 complete.

Within those files, order the survivors by what they reveal. Consult the High-Risk Patterns below for the combinations that most reliably indicate bugs.

**Investigate immediately:** `ER` in auth, crypto, parsing, or validation; `ER` clusters spanning consecutive lines; `IF` and `IT` both uncaught in security code; `CR` on an authorization check.

**Investigate next:** `ER` in error-handling paths; `IF`/`IT` in complex conditionals; `CR` on state-changing operations; any function with several survivors clustered in it.

**Lower priority:** isolated operator mutations, survivors in utility functions, and dead code — which is tech debt to remove, not a bug to debug.

**Exit:** Prioritized mutant list.

---

### Step 3: Investigate for Bugs

**Entry:** Step 2 complete.

For each high-priority target:

1. **Read the code.** `mewt print mutant --id <id>` shows the mutation; read the surrounding function for context. Establish the intended behavior. Investigate the original source: a defect deliberately introduced by a mutation is not evidence that the original program is vulnerable.
2. **Determine why it is untested.** Dead code (never called), new code (tests not yet written), an edge case tests never trigger, an error path behind happy-path-only tests, or a unit/integration gap. Each points at a different kind of bug.
3. **Assess risk:** can attacker-controlled input reach this code, what happens if it is wrong, and does it sit on a security boundary?
4. **Look for the bug classes that fit the mutation type:**
   - `ER` — walk the code path manually; check error handling and input validation for paths that silently succeed
   - `IF`/`IT` — exercise the untested branch; look for off-by-one errors and unhandled null/empty values
   - `CR` — check whether the statement is necessary at all, and whether its state change actually happens
   - Operator mutations — verify the comparison or arithmetic is the intended one, and test the boundary
5. **Try to reproduce.** Write a proof-of-concept test, run it, and confirm the impact. A hypothesis you could not reproduce is a "likely bug," not a confirmed one.

**Exit:** Each target resolved as a confirmed bug, a likely bug, dead code, or correct-but-weakly-tested code.

---

### Step 4: Document Findings

**Entry:** Step 3 complete.

Each finding gets a location, the evidence (mutation result plus what manual testing showed), the issue, impact and severity, a reproduction, and a fix. Example:

````markdown
## Bug: Expired Tokens Accepted

**Location:** `src/auth/verify.rs:78`

**Evidence:**
- Mutation testing: [ER #42] line 78 is completely untested
- Manual testing: a token that expired an hour ago verifies successfully

**Issue:** The expiry check is inverted. `if token.exp > now { return Err(Expired) }`
returns an error for tokens that are still valid and accepts tokens that have expired.
The error path has no test coverage, so the inversion went unnoticed.

**Impact:** Expired authentication tokens remain valid indefinitely. Severity: CRITICAL.

**Reproduction:**
```rust
#[test]
fn test_expired_token() {
    let token = create_token_with_expiry(-3600); // expired 1 hour ago
    assert!(matches!(verify_token(&token), Err(Expired))); // fails today
}
```

**Fix:** Compare with `<` on line 78.
````

Classify every finding as **confirmed** (reproducible PoC, verified impact), **likely** (strong evidence, not yet reproduced), **dead code** (unreachable, remove it), or **not a bug** (correct code, weak tests). Keep the last two categories out of the bug list — dead code belongs in a cleanup recommendation.

Close with a short summary: campaign statistics, counts per category, the confirmed bugs with locations and severities, and recommendations.

**Exit:** Findings documented.

---

## High-Risk Patterns

**`ER` clusters.** Several consecutive `ER` survivors can indicate an unexecuted block or tests that tolerate errors. Inspect execution and assertions before choosing either explanation. Determine whether the code is reachable in supported use.

**`IF` and `IT` both uncaught on one line.** The tests do not distinguish either constant replacement. The condition might be unexecuted, or both branches might run without assertions on the differing results. Check `mewt results --line 42`, then examine the tests and exercise the branch outcomes.

**`ER` in error handling.** Survivors in `catch` blocks and error-return paths mean failure modes are entirely unvalidated. Ask which errors can actually occur, whether an attacker can trigger them, and whether they leak information or crash the process.

**Many survivors of mixed types in one security-sensitive file.** Critical code with broadly weak coverage. Review the logic by hand rather than mutant by mutant, looking for bypasses in the security checks.

---

## Working Effectively

Investigate one file or area at a time and focus on the top 10-20 priority mutants — comprehensive coverage of a large result set is not the goal, high-impact findings are. Summarize as you go rather than holding every finding in context.

Prioritize ruthlessly when there are too many survivors to investigate: start with `ER` in auth, crypto, and validation, favor clusters over isolated mutants, and accept that some areas go uninvestigated.

When you cannot tell whether untested code is buggy, test it — write the PoC, run the path, and compare actual behavior against intended behavior. When the code turns out to be correct and only the tests are weak, that is a legitimate outcome; say so. If the investigation confirms no bugs, report that outcome with its scope and unresolved cases. It does not establish that the area is free of bugs.
