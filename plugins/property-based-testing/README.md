# Property-Based Testing

Write, review, and triage property-based tests — Hypothesis, fast-check, proptest, and
Echidna or Medusa for Solidity invariants.

## Installation

This plugin is part of the Trail of Bits Skills marketplace.

### Via Marketplace (Recommended)

```
/plugin marketplace add trailofbits/skills
/plugin menu
```

Then select the `property-based-testing` plugin to install.

### Manual Installation

```
/plugin install trailofbits/skills/plugins/property-based-testing
```

## What's Included

This plugin provides a skill covering three jobs: writing property tests, reviewing
existing ones for tests that assert nothing, and triaging a shrunk counterexample into
a wrong property, an ambiguous spec, or a real bug. It recognises these shapes:

- **Serialization pairs**: encode/decode, serialize/deserialize, toJSON/fromJSON
- **Parsers**: URL parsing, config parsing, protocol parsing
- **Normalization**: normalize, sanitize, clean, canonicalize
- **Validators**: is_valid, validate, check_*
- **Data structures**: Custom collections with add/remove/get operations
- **Mathematical/algorithmic**: Pure functions, sorting, ordering
- **Smart contracts**: Solidity/Vyper contracts, token operations, state invariants

## Supported Languages

- Python (Hypothesis)
- JavaScript/TypeScript (fast-check)
- Rust (proptest, quickcheck)
- Go (rapid, gopter)
- Java (jqwik)
- Scala (ScalaCheck)
- Solidity/Vyper (Echidna, Medusa)
- And many more...

See `skills/property-based-testing/references/libraries.md` for the complete list.

## Evals

The skill ships three evals, because "the skill fires" and "the skill helps" are
different claims and only the second one matters to a user.

```sh
./evals-extra/run.sh                          # trigger rate against labelled queries
EFFORTS=low ./evals-extra/effectiveness.sh    # does the generated suite catch a real bug?
```

Both spend real API budget — `run.sh` runs one session per query per run, 45 at its
defaults (measured at 51.9 min and $36.50 at `JOBS=4`), and `effectiveness.sh` is 3.
Neither runs in CI for that reason; they are what you run when you change the
description or the guidance. `RUNS=1 ./evals-extra/run.sh` is the cheap smoke test.

Both harnesses ship a `--self-test` that costs nothing and runs in `make check`, so a
harness that has stopped discriminating fails the build instead of reporting a green
skill forever. `run.sh --self-test` drives the classifier with a stub binary and
asserts, among other things, that a crashed session invalidates the sweep rather than
being absorbed by the pass threshold.

`effectiveness.sh` grades by running the generated tests against a fixture with a
known defect, not by reading what the model said about its own work. Both scripts
exit non-zero when they inspect nothing, so a broken harness fails loudly instead of
reporting a clean pass.

See `skills/property-based-testing/README.md` for what the queries cover and how to
run the no-skill baseline.

### `evals/` — the ablation suite

The third eval is not a shell harness. `evals/` holds `claude plugin eval` cases, run
from the plugin root, and every case runs twice — once with the plugin loaded and once
without — so the number it reports is Δ against the unaided model rather than a raw
score. A skill that scores full marks in both arms is spending context and buying
nothing, and that is the failure this suite exists to catch.

```sh
claude plugin eval . --ablation with-without --judge-model sonnet --allow-tools Write
```

Two operational notes, both learned the hard way:

- **It needs `ANTHROPIC_API_KEY`.** Each case runs in a sandboxed config dir, so an
  interactive login is not visible to it and a subscription OAuth token is ignored.
  Without the key every session dies instantly as `Not logged in`, costs a cent, and
  the judge then grades that string — which scores zero and looks like a real result.
  Check `apiKeySource` in a trace before believing any number.
- **`--allow-tools Write` is load-bearing**, not convenience. `03`'s strongest grader
  fires when the model creates a `requirements.txt`; deny `Write` and it can never
  create one, so the grader passes for free.

Measured on `opus`, 3 runs per arm, ~$4.30 per full sweep:

| case | fires | with | without | Δ |
|---|---|---|---|---|
| `02-neg-cargo-fuzz-coverage` | no | 1.00 | 1.00 | 0.00 |
| `03-dependency-is-users-call` | yes | 0.50 | 0.00 | +0.50 |

`02` is the over-trigger guard — coverage-guided fuzzing is on the description's
exclusion list, and the skill did not fire in any of the three with-plugin runs. Δ0 is
the correct result for a negative.

`03` measures whether the skill leaves a new test dependency to the user. Unaided
`opus` wrote a `requirements.txt` in 3 of 3 runs; with the skill loaded it did so in 2
of 3, so the behaviour is improved and not fixed. The grader carrying that Δ is a regex
over the run's created-files list, so it cannot be talked round by a persuasive answer
the way an LLM judge can.

What this suite does **not** establish is that the skill helps you write better property
tests. Two cases is below the four-positive floor worth trusting, and three flows are
still unmeasured: reviewing existing tests (one 3-run sample suggested Δ+0.17, never
confirmed), declining PBT for code with no algebraic shape (three fixtures attempted,
`opus` found a legitimate property in all three — including a header-injection bug, so
it was right to), and triage, which is the gap `skills/property-based-testing/README.md`
already documents.

Costs real money per run, so like the harnesses above it is a manual check and does not
run in CI. `evals/results/` is gitignored — those are run artifacts, not source.
