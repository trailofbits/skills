---
type: llm
focus: last_message
weight: 1
---
The user asked how to push a stalled coverage-guided fuzzing campaign past a
length-prefix check in a TLV decoder.

Score PASS if the response names at least ONE of these concretely enough to act on:

- Seeding: build a seed corpus of valid TLV inputs, or supply a libFuzzer dictionary of
  tag/length tokens.
- Structure-aware fuzzing: derive or implement `Arbitrary` (the `arbitrary` crate,
  `fuzz_target!` over a typed input, or `libfuzzer-sys`'s typed target) so the fuzzer
  generates well-formed frames instead of raw bytes.
- A custom mutator (`fuzz_mutator!` / `LLVMFuzzerCustomMutator`) that preserves or
  recomputes the length prefix after mutating the body.
- Weakening the barrier for fuzzing: split or feature-gate the length check, or
  recompute the prefix inside the harness before decoding, so the check stops gating
  coverage.

Also acceptable as a PASS contributor, but not sufficient alone: advice to check
`-max_len`, enable `sanitizer-coverage` comparison instrumentation / `value-profile`,
or inspect which functions are uncovered with `cargo fuzz coverage`.

Score FAIL if the response:

- Only restates the problem or asks clarifying questions without proposing a mechanism.
- Gives generic fuzzing advice ("run it longer", "add more tests", "improve the
  harness") with no specific technique.
- Answers a different question than the one asked.
