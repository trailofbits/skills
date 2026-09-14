---
type: llm
focus:
  source: file
  path: mutation-testing-report.md
weight: 2
---
Grade the mutation testing analysis report. The graded text is the report file
itself, so a run that described its findings in chat without writing them into
this file has already failed — judge only what is in the file, and fail it if it
is a stub, an outline, or a plan rather than a completed analysis.

The campaign found 8 surviving mutants in `src/lib.rs`. Fail unless every one of
these claims holds.

1. **The equivalence split on line 37 is correct.** `balance > 0` was mutated two
   ways. `balance != 0` must be classified as an EQUIVALENT mutant / false
   positive, justified by `balance` being an unsigned `u64` — zero is the only
   value not greater than zero, so no input distinguishes them. `balance >= 0`
   must be classified as a REAL finding, not equivalent, justified by the two
   differing at `balance == 0` (the original returns false, the mutant returns
   true) with no test calling `has_funds(0)`. A report that calls both
   equivalent, calls neither equivalent, or swaps them fails this claim
   outright. Rationalizing `>= 0` as equivalent because it is "tautological for
   unsigned" is exactly the error being tested — the mutant is the tautology
   here, not the original, so that reasoning fails.

2. **The two guard mutants are the top-tier findings.** Commenting out the
   `if !is_admin` guard, and replacing its condition with `false`, are both real
   findings placed in the highest tier (Tier 1 / Critical) on access-control or
   authorization grounds. They must not be ranked below the balance-guard or
   logging findings.

3. **The insufficient-funds guard is a real finding below Tier 1.** The two
   mutants on `if amount > account.balance` are real and placed in Tier 2 /
   High, on state-integrity or balance-accounting grounds.

4. **The two commented-out call findings are present and low.** Removing
   `record_withdrawal(amount);` and removing the `eprintln!` inside it are real
   findings in a low tier on observability grounds. Neither may be dismissed as
   equivalent.

5. **All 8 survivors are individually accounted for** — 7 real findings plus 1
   equivalent. No survivor is skipped, batched with another, or summarized away.

6. **Each real finding names a test gap and a concrete fix.** It must point at
   the test file or the absence of one, say why the existing tests missed the
   mutation, and state what input or assertion would catch it. Vague advice such
   as "add more tests" does not satisfy this.

7. **The statistics are computed, not invented.** Any kill rate, survivor count,
   or severity distribution in the report is arithmetically consistent with 29
   mutants generated, 24 tested, 16 caught, 8 uncaught, 5 skipped, and with the
   equivalent mutant excluded from the adjusted rate.

Ignore formatting, section ordering, length, and whether tier labels are worded
exactly as above. Judge only the classifications and the reasoning behind them.
