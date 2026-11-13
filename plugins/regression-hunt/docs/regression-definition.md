# What counts as a regression

You investigate whether the selected PR or commit introduced a regression.

**A regression is a new defect introduced by the selected change that breaks previously correct,
supported behavior on a reachable user or attacker path.**

Investigate four types, in priority order:

1. **Security:** Introduces a security flaw. Show an action the previous version correctly
   prevented.
2. **Functional:** A feature that worked stops working or produces an incorrect result.
3. **Performance:** The same supported workload becomes materially slower or consumes more
   resources.
   Demonstrate the difference with controlled measurements.
4. **Build/test:** A supported build, packaging, CI, test, or release workflow that worked now
   fails.

Before confirming a regression, establish that the expected behavior is supported, the failure is
reachable, the behavior worked before the patch, it fails afterward, and the patch introduced the
defect. Correct behavior includes rejecting invalid input.

**Check for false positives before confirming a regression. Address each possibility with cited
evidence:**

- **Incomplete fix:** The intended repair missed an input source, caller, or usage path. Its symptom
  may differ from the original bug.
- **Latent bug:** The patch exposes an existing defect, even if that path previously worked.
  Identify the existing defect.
- **Pre-existing bug:** The failure was already reachable before the patch.
- **Borderline/inconclusive:** Missing evidence of supported behavior, reachability, patch causality
  or independent before/after replay keeps the candidate **unverified** (`UNRESOLVED`). In one concise
  paragraph per case, distinguish observed gaps from possible causes. If the cause is unclear, list
  only relevant possibilities, each paired with a maintainer request or check: unsupported expectations
  (behavior contract), unreachable input (call trace), pre-existing defect (patch evidence or controlled
  revert), setup differences or unstable reproduction (replayable PoC, setup and logs). Reassess all
  evidence before confirmation.

Report these separately, outside confirmed regression totals.

**Require a real PoC before confirmation.** Build and run the actual S0/S1 systems. Run the same PoC against both live deployments through a real entry point under
comparable inputs and conditions. Demonstrate correct behavior before the patch and the claimed
failure afterward, then obtain independent replay by a fresh agent. Retain the runnable PoC, exact
revisions, commands, observations, and logs.

Synthetic tests, helper-only failures, simulated dependencies, invented internal states, and
artificially granted attacker privileges cannot establish a regression. Never claim an experiment
you did not run.

At every stage, use the supplied root `THREAT_MODEL.md` when present and read other applicable
security documentation. When that file is absent, search for the project's threat model or
security documentation. For each security candidate, state what the attacker must control or
already have, and cite whether the project promises protection against that attacker. If the
project explicitly excludes that scenario, do not count it as a security regression. Do not
relabel it as a functional regression unless you independently demonstrate that a supported
user workflow broke.

If no applicable security guidance exists, use the code and supported deployment to establish what
the attacker can control and which security protection the patch broke. Do not assume extra access
or privileges.

This is the shared standard for every skill.
[Report labels](report-definitions.md) explain the output categories and ratings.
