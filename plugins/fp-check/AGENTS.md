# AGENTS.md — fp-check

fp-check decides whether a suspected security bug is real. Its design premise is
that **every gate is a pure function in a workflow script, never a rule an agent
is asked to honour** — the plugin exists because prose gates were self-reported
and did not hold. Work here in three places: `workflows/*.js` is the logic and all
gate decisions; `skills/fp-check/SKILL.md` is routing, the two user questions and
the dispatch contract; `skills/fp-check/references/*.md` are lookup tables the
agents read at runtime via the `baseDir` argument. `tests/` has four layers,
`evals/` has the paid eval cases.

## Orientation

| Path | What belongs there |
|---|---|
| `workflows/triage-batch.js` | Stage 0, more than one finding. The only script that calls `workflow()`, and the only one that sees a second finding |
| `workflows/triage-static.js` | Stage 1, always runs, reaches a verdict alone |
| `workflows/triage-online.js` | Stage 2, on request, public posture. Fails closed offline |
| `workflows/triage-poc.js` | Stage 3, on request. Builds, executes, then five challenge agents that did not build it |
| `skills/fp-check/SKILL.md` | Under a 500-line validator limit — `wc -l` it before adding, the headroom is thinner than it looks |
| `skills/fp-check/references/` | Read by agents at runtime — a wrong `baseDir` makes every read resolve to nothing, silently |
| `tests/*.test.mjs` | Layer 2: pure helpers and whole-script runs against scripted agents |
| `tests/test_workflow_contract.py` | Layer 1: structural pins, including on SKILL.md |
| `tests/mutation-gate.sh` | Breaks each covered behaviour and requires the suite to go red |

## The rules, each of which was a shipped bug

- A JSON Schema on **every** `agent()` call. Validation is at the tool layer, so
  the model retries instead of returning prose.
- `.filter(Boolean)` after every `parallel()` — a dead agent returns `null`.
- Tally against the **expected** list, never the returned array. Tallying returns
  lets a dead agent shrink the denominator and *raise* confidence.
- A missing verdict counts **against** the finding, never for it — but "against"
  means it cannot reach TRUE POSITIVE, not that it becomes FALSE POSITIVE.
- No `Date.now()` / `Math.random()` / `new Date()` — they throw in workflow scripts.
- `required` in a JSON Schema validates **presence, not content**. Trim before
  trusting any string; `''` and `'   '` satisfy `required`.
- Failing returns carry fully populated payloads, so callers check
  `verification.status`, never the shape.
- Prose in `SKILL.md` and `references/` must match the code. Several defects have
  been a doc telling the orchestrator something the scripts no longer do.

## Do not write a string heuristic that guesses

This is the most expensive lesson in the plugin's history. `capSeverity` and
`citedReference` each regressed in **five consecutive review rounds**, because
every fix traded a false accept for a false reject: substring match → "first level
named" → "highest, only where it lowers", each one breaking a case the previous
one fixed.

The shape that finally held: **extract candidates, and when the answer is
ambiguous, refuse.** `capSeverity` now collects every word-bounded severity token
and branches on the count — exactly one is the rating, more than one returns
`NEEDS_MORE_INFO` rather than picking. `citedReference` recognises advisory
registries by an explicit prefix allowlist instead of by ID shape.

Same move where a grep genuinely cannot decide: `poc-lint.sh` cannot tell a façade
call from a pasted copy, so it emits a **note**, an agent judges it, and the pure
function `artifactProblem` reads that agent's enum. The gate stays in code; the
judgement goes to something that can judge.

If you are tempted to add a sixth condition to a matching rule, that is the signal
to make it refuse instead.

## Testing

```bash
make js-tests                                    # node suites, including Layer 2
cd plugins/fp-check && uv run --no-project --with pytest --with pyyaml \
  --with jsonschema python -m pytest tests -q
bats plugins/fp-check/tests/poc-lint.bats
make validate
bash plugins/fp-check/tests/mutation-gate.sh     # NOT in CI; run it by hand
```

- **Run the mutation gate with `bash`, not `zsh`.** Under zsh `BASH_SOURCE` is
  clobbered and every mutation reports as a survivor.
- **A rewritten comment can make a mutation stale**, which the gate reports as an
  ERROR, not a survivor. Several mutations target comment and prose strings,
  including in `SKILL.md`. Re-point them in the same change.
- **`make check` exits non-zero** on pre-existing `constant-time-analysis`
  failures (missing cross-compile toolchain). Read the per-directory output, not
  the exit code. Note the runner prints each directory header *before* its
  results.
- **Tests pin literal SKILL.md strings** — the namespaced `fp-check:triage-*`
  dispatches, the `    component:` arg line, `**Do not end your turn until the
  workflow has returned.**`, and `and all four \`verification.impact\`` with
  literal spaces. **Re-wrapping a paragraph can turn a test red without changing a
  word**; that is working as intended, not a flaky test.
- **Layer 3 (regrade) does not run.** The checked-in capture predates the merge,
  so `test_regrade.py` skips and its mutation-gate entries stay deferred. One
  paid capture via `tests/capture-runs.sh` re-arms both.

## Terminology

- **layer** — a validation check that *exists* between entry point and sink, with
  a `file:line`. Never the absence of one: an agent asked whether a non-existent
  check stops the payload cannot answer coherently. Declare absence with
  `layers: []` plus `layersSearched`.
- **band** — the confidence band derived from the N/5 challenge tally in Stage 3.
- **census** — Stage 2's search for downstream consumers, decided in code.
- **NEEDS MORE INFO** — insufficient evidence. Distinct from FALSE POSITIVE, and
  conflating them discards real bugs.

## Running the paid evals

Full detail in [tests/README.md](tests/README.md); the three that have each cost a
wasted sweep:

- **Target the plugin by name (`fp-check@<marketplace>`), not by path.** A path
  target does not register the skill, so the run is a baseline with a plugin
  installed.
- **The installed cache is not your working tree.** Bump the version, reinstall,
  and prove it with `diff -r` before believing any result.
- **`--ablation with-without --scaffold --tag static`** are all load-bearing, and
  add `--no-publish` unless the user has authorised uploading the report.
- A **429 spend limit** records as `exit 1: (no stderr)` with `turns: 1`, which is
  indistinguishable from a plugin crash in the result JSON. Check
  `api_error_status` in the trace before attributing it to the plugin.
- `scrub_capture.py` parses JSONL, so it **cannot scrub a pretty-printed eval
  result** from the command line — import it and call `scrub(text, username)`.

## Change discipline

- A bug fix ships with a regression test, and the test must be verified to go
  **red** against the pre-fix code. Pin behaviour with a **table** of cases, not
  one example — validating against a handful of strings is exactly how the two
  functions above regressed five times.
- Keep fixes narrowly scoped to the defect. No opportunistic renames or
  formatting churn.
- Bump `version` in **both** `.claude-plugin/plugin.json` and the root
  `.claude-plugin/marketplace.json` for any behaviour change; the validator only
  checks that they agree.
- The batch and census capabilities are exercised by guards in
  `tests/coverage.test.mjs`; if you add a guard that asserts an ABSENCE, say so
  in the test name, and do not silently "fix" one.
- **`chained-findings` has never been measured.** It is tagged `batch` rather than
  `static` for that reason, so `--tag static` still selects exactly the seven
  cases the static mean is taken over. Admitting it to a mean needs n=3
  discrimination first; see tests/README.md on the two cases that were admitted
  on n=1.
