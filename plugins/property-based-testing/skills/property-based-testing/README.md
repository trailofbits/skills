# Property-Based Testing Skill

Guidance for property-based testing across languages, including Echidna and Medusa for
EVM smart contracts.

## What it does

- **Spots PBT opportunities** — encode/decode pairs, validators, normalizers, pure
  functions with wide input domains, smart-contract invariants
- **Writes property tests** — strategy design, edge-case pinning, settings
- **Reviews existing ones** — tautologies, vacuous `assume()`, missing stronger
  properties
- **Triages failures** — separates a wrong property from an ambiguous spec from a
  real bug

## Structure

```
skills/property-based-testing/
├── SKILL.md                          # Property catalog, failure modes, routing
└── references/
    ├── generating.md                 # Strategy design, settings, edge cases
    ├── refactoring.md                # Rearrangements that expose a property
    ├── reviewing.md                  # Quality issues by severity
    ├── interpreting-failures.md      # Grounding and classifying a failure
    └── libraries.md                  # Library per language; Echidna/Medusa
```

### What was cut, and why

Three reference files were removed rather than rewritten, and one was kept after
initially being cut. Recorded because a deletion with no rationale is indistinguishable
from an oversight:

- **`design.md`** — a Phase 1–5 prose workflow. AGENTS.md is explicit that a procedure
  a model is meant to follow step by step belongs in a script, where it either runs or
  fails, not in prose it can drift from.
- **`strategies.md`** — per-language generator syntax. `st.integers(min_value=1)` and
  `fc.string()` are not knowledge a current model lacks, and paying context for them
  crowds out the judgment it does lack. `generating.md` keeps the parts that are
  decisions rather than syntax: constraints in the strategy instead of `assume()`,
  `@example` pinning, `deadline=None`.
- **`refactoring.md`** — cut, then **restored** in trimmed form. The cut was wrong. Both
  SKILL.md and the strength ordering send you to "this code is a poor PBT candidate",
  and without this file that is a dead end where an answer exists: extract the pure core,
  add the missing inverse, structure-plus-render, return instead of mutate, inject the
  dependency. `evals/03`'s own fixture is the case in point — `send_welcome_email` is
  impure SMTP whose message construction is separable and property-worthy, and the
  measured runs found that seam unprompted. Trimmed on the way back in: the `rg`
  detection one-liners (fragile, and two of them wrong), an effort/risk table and a
  prioritisation list that both restated the strength ordering, and a "generators for
  validators" pattern already covered by `st.composite` in `generating.md`.

The eval harnesses are deliberately **not** inside the skill. They sit at the plugin
root alongside `evals/`, so a directory the model reads guidance from does not also
ship 900 lines of bash, a `requirements.txt` naming hypothesis, and a fixture full of
tests that are broken on purpose:

```
evals-extra/                          # run by hand, never by `make check`
├── run.sh                            # Trigger-rate eval
├── effectiveness.sh                  # Does the suite find a real bug?
├── *.md                              # Labelled queries (query/should_trigger)
└── fixture/                          # Small repo the queries refer to
```

**Every command below runs from the plugin root** (`plugins/property-based-testing/`).

## Evals

Two things are worth measuring and they are not the same thing.

### Why `evals-extra` and not `evals`

A full sweep is 45 Claude sessions, ~52 minutes and ~$36. That is not something to
attach to a routine check, so the directory is named to stay out of the way: nothing
runs these sweeps automatically, and a developer invokes them when the description or
the guidance changes.

The `--self-test` entry points are the exception and do run in `make check`. They use
stub binaries, cost nothing, take about nine seconds, and are what proves the harness
still discriminates — an eval that has quietly stopped measuring reports a green skill
forever. The Makefile discovers them with an `evals*` glob, so the rename does not
smuggle them out of CI.

Two machinery globs depend on that same prefix, and both fail loudly rather than
silently if it drifts: `python-tests` excludes `evals*/fixture/` (which ships a
deliberately vacuous `assume()` test that pytest is meant to fail), and the plugin
validator skips `evals*` when resolving reference links.

**Does the skill fire?** `evals-extra/run.sh` runs each labelled query in
`evals-extra/*.md` against a real session and compares the trigger rate against
`should_trigger`. Eight of the fifteen queries are near-miss negatives — a libFuzzer
harness, a mutation-testing campaign, a Slither scan — because a description that
triggers on everything is as broken as one that never triggers.

```sh
./evals-extra/run.sh                        # 3 runs per query, 4 at a time
RUNS=1 ./evals-extra/run.sh                 # smoke
PLUGIN_DIR=/tmp/old ./evals-extra/run.sh    # score a different copy of the skill
./evals-extra/run.sh --self-test            # free: proves the harness still discriminates
```

One session per query per run, so a sweep is `queries x RUNS` — 45 at present. The
script prints the count on startup; trust that over any number written down here.

Timing and cost, from the 45-session sweep below: **51.9 min at `JOBS=4`, $36.50**
($0.81/session, read from each session's own `total_cost_usd`). Both figures track API
latency, which moves a lot — median session duration was 78s on one sweep and 175s on
another. The wave dispatcher is a barrier, so the slowest session in each wave of
`JOBS` sets that wave's pace.

Two parameters are set from measurement rather than taste, and both were wrong before:

- **`TIMEOUT_S=600`.** The slowest legitimate session in a clean sweep took **449s**.
  At the old 300s it was killed, and four such kills invalidated a whole sweep.
- **`TURNS=200`.** The slowest took **32 turns**. The old cap of 14 truncated five of
  eight sessions in one sample; an interim value of 30 would still have caught this
  one. 200 is 10x the observed natural completion and cannot fire before the timeout
  does — see the note in `run.sh` for why it is kept rather than removed.

Invocation is stochastic, so one run per query measures nothing: the Echidna query
scored 0/1 on one sweep and fired on the next identical run. Read a single-run sweep
as a smoke test only.

**A failed session is not a non-trigger.** A crash, a timeout or a rate-limit produces
no Skill call, which is indistinguishable from a model that considered the skill and
declined — so it used to score as a miss and get absorbed by the floor's leeway. Ten
queries at three runs against a floor of 27 tolerates three misses, so a query that
crashed all three times still totalled 27 and reported a pass. Now the sweep reports
each failure in the `NOTE` column (`timeout` and `crash:*` are distinguished), marks
that query `INVALID` because its denominator is unknown, and exits 3 regardless of
score. Every other query still runs and is still reported.

**But an invocation outranks a failure.** A Skill call is positive and final: nothing
later in the session can un-call it, so the detector runs *before* the exit-status
ladder and a `yes` stands however the process ended. Only the absence of a call depends
on the session having reached a decision. Getting this backwards is what corrupted the
figures below.

**Every session's raw stdout and stderr is kept**, in a directory printed at the start
and end of the run and excluded from the cleanup trap. This is not optional
instrumentation: two sweeps produced ten failures that were undiagnosable afterwards
because the captures were deleted the moment they had been classified. Note that
failures are reported in the final `result` record on **stdout** — in a clean 45-session
sweep, 0 of 90 stderr files had any content at all, so anything reading only stderr
learns nothing. Artifacts accumulate (~4MB/sweep) and are never cleaned up.

| exit | meaning |
|---|---|
| 0 | every query met its expectation and every session returned a verdict |
| 1 | regression — fewer queries passed than `EXPECT_PASS` |
| 2 | harness failure — no queries discovered, or a malformed eval file |
| 3 | invalid — a session crashed, timed out, or returned nothing |

Measured on `opus`, 3 runs per query, 45/45 sessions returning a verdict and `run.sh`
exiting 0 — the first sweep of this suite that is a measurement rather than an
artefact. Per-query rates:

| query | expect | rate |
|---|---|---|
| 01-roundtrip-codec | true | **0/3 FAIL** |
| 02-normalizer-idempotence | true | 2/3 |
| 03-hypothesis-existing | true | 3/3 |
| 04-echidna-invariant | true | 3/3 |
| 05-review-weak-tests | true | 3/3 |
| 07-fuzz-serializer-noname | true | 3/3 |
| 08-sort-comparator | true | 3/3 |
| all 8 negatives | false | 0/3 each |

Totals: **14/15 queries passed, recall 6/7, precision 8/8, raw trigger hits 17/21.**

### The previously recorded figures were wrong, and why

An earlier version of this file recorded 13/15, recall 5/7, 14/21, with 04 and 07 at
1/3 each. Do not trust those. They were produced by a classifier that consulted the
session's exit status *before* checking whether the skill had been invoked, so any
session that called the skill and then hit the 14-turn cap was discarded as a crash.
In one salvaged sample, **9 of 12 sessions were being thrown away and all 12 had
invoked the skill** — including all three runs of 04, the query recorded at 1/3 and
since measured at 3/3.

The bias was not random. Longer, more exploratory queries are both the likeliest to
reach a turn cap and the ones whose positive evidence matters most, so the inversion
depressed recall on precisely the queries under study. Any conclusion drawn from the
old table — in particular that the Echidna/Solidity path triggered poorly — does not
survive.

The gate's floor stays at **13** rather than rising to the measured 14. Three different
positives (01, 04, 07) have been the sole failure in different runs, so a floor of 14
would leave no room for the stochasticity this suite documents everywhere else. One
valid sweep is not enough to tighten a gate.

- **01 (wire-format roundtrip)** is the current miss at 0/3, and it is a genuine
  reversal: in the salvaged sample it invoked the skill on all three runs. Worth a
  second valid sweep before treating it as a description problem.

### Known gap: triage requests do not trigger

Nothing in the suite covers the third job — deciding whether a shrunk counterexample is
a real bug, a wrong property, or an edge case the spec never settled. A query for it
existed and was removed. It sat at 0/3: handed a falsifying input and the code, the
model answers directly and never reaches for guidance, and description wording did not
move that.

It was removed rather than kept as a documented failure because neither label was true.
`should_trigger: true` asserts a trigger the description cannot produce;
`should_trigger: false` asserts the skill should stay out of a job it advertises. The
field is binary and the honest answer is "unmeasured" — nobody has checked whether
loading `references/interpreting-failures.md` improves the classification over the
unaided answer. It was worth nothing as a regression test either: because it never
fired, its score was identical whether that reference file was intact or deleted, so it
could not distinguish the two states.

To readmit it, run the query against the fixture with and without the plugin and
compare the answers. If the guidance improves the classification, `should_trigger: true`
becomes defensible and 0/3 becomes a real bug worth chasing. If it does not, that is a
finding about `interpreting-failures.md` rather than about the description.

One caveat on that 0/3: it was measured by the same classifier that mis-scored 04, so it
is not trustworthy either. It is *less* affected than 04 was — the inversion only
discarded sessions that had invoked the skill, and a session invoking it would have
scored `yes` under either ordering — but the figure was never re-measured, and the
argument for removal rests on the binary-label problem rather than on the number.

Both scripts pin `--model` (`MODEL`, default `opus`) and print it above the table.
Trigger rate is a property of a description *and* a model, so a number recorded
without one cannot be compared to the next one. To judge a description change, score
the old copy and the new one on the same model — `PLUGIN_DIR` exists for exactly
that, and it takes a plugin directory rather than needing a dirty working tree.

**Does it help once it fires?** `evals-extra/effectiveness.sh` asks for property tests on
`fixture/src/codec.py`, which contains a real defect — `canonicalize_url` percent-
encodes with a safe set that omits `%`, so a second pass re-encodes its own escapes
and `canonicalize_url("a b")` is not a fixed point. The script runs the generated
suite against the defective function and again against a patched one, and counts
tests that fail before and pass after. The verdict never comes from the model's own
account of how it did, and never from matching test names.

```sh
EFFORTS=low ./evals-extra/effectiveness.sh  # score the skill as shipped
NOPLUGIN=1 ./evals-extra/effectiveness.sh   # baseline without the skill loaded
```

A bare `./evals-extra/effectiveness.sh` asks for low/medium/high and is **refused**
while `SKILL.md` pins an effort — see below.

Run the baseline before adding to this skill. Opus already writes competent Hypothesis
suites unaided, so content that does not move a number against `NOPLUGIN=1` is
costing context without buying anything.

## Why `effort: low`

Swept, not guessed. `low`, `medium` and `high` all detect the fixture defect, and
`low` did it 4 runs out of 4; the review path at `low` independently named both
planted defects in `fixture/tests/test_parser.py` as CRITICAL. Nothing measured
justifies paying for more, which is what `sweep downward on your own evals` in the
repo's AGENTS.md asks for.

Worth knowing before you change it: `effort` overrides the session level in both
directions, so this drags a deliberate `xhigh` session *down* while the skill is
active. That is the real cost of setting it at all, and it argues for raising the
value — not lowering it further — if the generation path ever starts regressing.

**The pin also breaks the sweep that justified it**, because `--effort` is ignored
once the skill loads: all three arms would run at `low` under the labels they asked
for, and three identical rows are what a healthy sweep looks like too. So
`effectiveness.sh` refuses a multi-level sweep while the pin is there (exit 2) and
tells you to strip it from a copy and use `PLUGIN_DIR`. Re-sweep that way before
changing the pinned value.

## Example prompts

```
"Write property-based tests for this JSON serializer"
"Review this Hypothesis test for quality issues"
"Write Echidna invariants for this staking contract"
"Hypothesis shrank to '\x00' — is this a real bug?"
```
