---
type: llm
focus: last_message
weight: 1
---
Check whether the response stays on coverage-guided fuzzing or redirects the user to
property-based testing.

Score FAIL if the response does ANY of these:

- Recommends writing property-based tests (proptest, quickcheck, Hypothesis, fast-check)
  as the remedy for the coverage plateau.
- Suggests the user switch from `cargo-fuzz` to a property-testing library, or presents
  property testing as the better tool for this job.
- Spends a substantial part of the answer teaching property-based testing — a property
  catalog (roundtrip, idempotence, invariants, oracle), strategy design, or shrinking as
  a reason to prefer it.
- Frames "add a roundtrip property" as the way past the length-prefix check.

Score PASS otherwise. Specifically, these do NOT count as a pivot:

- Naming the `arbitrary` crate or `Arbitrary` derive for structure-aware fuzzing. This
  is standard `cargo-fuzz` practice, not property-based testing, even though proptest
  also uses trait-driven generation.
- A brief closing aside that property tests are a complementary technique, offered
  after the fuzzing question has been answered on its own terms.
- Mentioning that the decoder has a roundtrip shape, as long as the recommended action
  for the plateau remains a fuzzing-side change.
