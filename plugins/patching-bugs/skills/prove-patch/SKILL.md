---
name: prove-patch
description: Use when a local security patch commit needs independent scoped and three-arm proof.
---

# Prove Patch

Use the original baseline, final patch commit, declared `repair_scope`, and unchanged
reproduction package. Read the [record contract](../../references/records.md). Do not
edit the patch or validate an uncommitted tree. Return failures for a new attempt.
Before target commands, follow its [project guidance](../../references/records.md#project-guidance).

1. Review the scoped cases and the patch without the patcher's conclusion. Execute
   each planned input on clean baseline and patched trees with the same retained
   harness source and command. The harness must print exactly one
   `PATCH_CASE {"input": ..., "actual": ...}` from the exercised input and observed
   result, then print `PATCH_REACHED` as its final stdout line immediately before
   the assertion. Representatives must fail on the
   baseline and pass on the patch. Valid controls must pass on both. Keep the
   baseline and patched stdout, stderr, exit status, elapsed time, command, and
   harness source under `receipts/`. A timeout, setup failure, missing marker,
   mismatched input, or ambiguous observation is an evidence gap. A trustworthy
   patched failure is a finding. Never relabel a gap as a pass.
2. Run relevant project checks on the patch and retain the same raw receipts. Use
   baseline comparison for behavior checks and to attribute failed project checks;
   a passing patched suite may omit a baseline run. Include focused tests, regression
   and security checks where relevant. Record specific unproven limits; an empty
   list leaves the result inconclusive.
3. Run the [three-arm helper](../../scripts/arms.py) with the proof-type recipe in
   the record contract, `reproduce.baseline_commit`, and final `patch_commit`.
   Require the baseline to fail, patch to pass, and complete baseline revert to
   fail again. Require `receipts/source.json` to identify the pinned commits and
   the reverted tree to equal the original baseline tree. Require the type's build
   identity result. Retain all source-tree,
   build, and execution receipts.
4. Write `prove.json` and a final manifest covering it and every receipt. Run
   `uv run --no-project <script> manifest <prove-attempt-dir>` and then
   `uv run --no-project <script> check <run-dir>` with the [validator](../../scripts/records.py).
   Independently inspect the [native proof assessment](../../scripts/native_proof.py)
   and raw receipts before reporting a result. A complete proof has no findings or
   gaps. Return exact failures and receipt paths to the orchestrator.

[Prove record schema](../../schemas/prove.schema.json):
```json
{
  "schema_version": 2,
  "attempt": 1,
  "failure_type": "runtime",
  "baseline_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "patch_commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "reverted": "pass",
  "build_identity": "pass",
  "hashes": {
    "baseline": "1111111111111111111111111111111111111111111111111111111111111111",
    "patched": "2222222222222222222222222222222222222222222222222222222222222222",
    "reverted": "1111111111111111111111111111111111111111111111111111111111111111"
  },
  "reverted_hash_note": null,
  "cases": [{
    "check_id": "reported-input",
    "argv": ["python", "receipts/case.py", "reported-input"],
    "source": "receipts/case.py",
    "runs": {
      "baseline": {"exit_code": 1, "elapsed_ms": 15, "stdout": "receipts/case-base.stdout", "stderr": "receipts/case-base.stderr"},
      "patched": {"exit_code": 0, "elapsed_ms": 14, "stdout": "receipts/case-patched.stdout", "stderr": "receipts/case-patched.stderr"}
    }
  }],
  "project_checks": [{
    "check_id": "focused-suite",
    "kind": "suite",
    "argv": ["pytest", "tests/test_upload.py"],
    "baseline": null,
    "patched": {"exit_code": 0, "elapsed_ms": 860, "stdout": "receipts/suite.stdout", "stderr": "receipts/suite.stderr"}
  }],
  "unproven": ["Inputs outside the declared boundary were not assessed."],
  "agent": "prover-1"
}
```

For a bounded class, include at least two distinct failing representatives and a
valid control. The record must cover every planned case by unique `check_id`.
Use the same harness and command on both commits; do not reveal the side to the
harness or change expectations by side. Review the selected cases for relevance;
retained receipts establish only what those cases exercised.
