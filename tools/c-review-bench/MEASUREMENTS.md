# c-review measurements — every cell, oldest first

The single record of what has been measured. Nothing here is repeated in the plugin's own
comments, deliberately: a number copied into source goes stale and no test catches it.

**How to read any number in this file**

- **Token basis is `tokens_fresh`** (input + output + cache creation) unless a row says
  otherwise. Never compare a `tokens_fresh` figure with a `tokens_total` one.
- **Recall and precision are separate.** No F1 anywhere.
- **The variance floor is large.** On `sigil`, two runs of the identical `bare` cell scored
  11 and 10; `taxonomy` swung 12 → 9. Treat **1–2 bugs of 17 as noise**, and up to 4 on the
  wider historical sample. On `zstream`, up to 5.
- **Gate-invalid cells are struck through and excluded from every comparison.**
- A cell is VALID only if its anti-cheat pass found no oracle use. `BLOCKED` (attempted and
  denied by the network guard) is not disqualifying; attempted-and-succeeded is.

---

## 1. sigil — 17 bugs, 901 lines, authored for this harness

### 1.1 The 2026-08-05 arm comparison (18 cells, 44.3M tokens)

| arm | recall (2 cells) | spread | agents | tokens/cell |
|---|---|---|---|---|
| bare | 11, 10 | 1 | 1 | 0.40M, 0.44M |
| taxonomy | 12, 9 | 3 | 1 | 0.40M, 0.59M |
| fanout | 16, 15 | 1 | 13 | 1.79M, 2.11M |
| c-review v2 | 15, 14 | 1 | 31, 32 | 5.13M, 5.38M |

Conclusions that survived: **fanout matched c-review v2 at ~40% of the cost**, and
`taxonomy` was both the noisiest arm and the worst on the HARD tier (1/3 then 0/3, below
`bare`) — knowledge alone did not substitute for compute, and the compute did not need the
orchestration. This is what motivated the v3/v4 rewrite.

### 1.2 v4 and v4.x

| cell | recall | agents | tokens | notes |
|---|---|---|---|---|
| v4 re-score | 16/17 | 9 | 2.48M | **Not a run.** Recorded findings re-scored with a fixed assembler. |
| v4 host, 2026-08-07 | **13/17** | 8 | 2.69M | Contaminated environment, see §4. 2 bugs SUPPRESSED by the merge. |
| v4.0.1 container | **15/17** ‡ | 8 | **1.81M** | Hermetic. `suppressed: 0`. |
| v4.0.1 container, `reviewAgents: 13` | 15/17 § | 17 | 2.28M | 69 lines/agent = fanout's granularity. |

‡ **Degraded collection.** Six of the fifteen hits came from findings admitted under
`--allow-incomplete-findings`; without the waiver the cell scores 9/17. The matched text was
genuine agent output (`title`, `impact`, both graded fields), so nothing was fabricated — but
the number depends on the waiver. Cause in §3.2.

§ **Partial coverage.** `review-unit-11` never wrote a part file, so 12 of 13 slices were
reviewed. A complete run could only match or beat this.

**Slice size bought nothing.** 69 lines/agent vs 225 gave identical recall and an identical
tier breakdown for **+26% tokens and +9 agents**. The one real signal: `pointers_seen` rose
30 vs 17 — smaller slices roughly double out-of-lane observation, and the pointer mechanism
absorbed it (1 promotion) rather than turning it into duplicate findings.

**Trap: `linesPerAgent` is a no-op on a small tree.** On sigil, 300 and 1500 produce
byte-identical assignments, because `enumerate_units.py --agent-min` (default 4) floors both.
An experiment varying it would have spent ~1.8M tokens measuring nothing and reported the
noise as a slice-size effect. Use `reviewAgents` to pin the fan-out.

### 1.3 The merge fix, replayed offline (free)

`CROSS_CLASS_NEARBY_LINES = 0`, replayed against three cells' recorded part files:

| cell | recall before → after | suppressed | decoy FPs |
|---|---|---|---|
| host | **13/17 → 15/17** (EASY 3/5 → 5/5) | 2 → 0 | 3 → 3 |
| container | 15/17 → 15/17 | 0 → 0 | 4 → 4 |
| slice | 15/17 → 15/17 | 0 → 0 | 2 → 2 |

Recovers both lost bugs, changes nothing else, no precision cost.

### 1.4 v5.0.0, 2026-08-09 — the best sigil cell recorded

| cell | recall | agents | tokens | wall | gate |
|---|---|---|---|---|---|
| v5.0.0 container | **16/17** (94.1%) | 8 | **2.10M** | 35 min | VALID |

`suppressed 0, near-miss 1, miss 0`. By tier: EASY 5/5, MEDIUM 9/9, HARD 2/3. Decoys: 4
charged of 10; 0 control-tree claims; 5 unmatched findings needing human triage.

**Collected with no waiver.** `incomplete_findings: []`, so unlike §1.2's `‡` cell this
number does not depend on `--allow-incomplete-findings` — the comparable v4.0.1 figure is
15/17 *with* the waiver and 9/17 without. Cost rose 1.81M → 2.10M (+16%) against that cell.

The one non-hit is SGL-B14 (`nonce-iv-reuse`, HARD) as NEAR_MISS: the finding lands within
12 lines but names `tags_equal` rather than `tag_check` and carries none of the expected
keywords, so the grader will not credit it. Whether that is a miss or a grading artifact
needs someone who did not run the cell to decide.

**Ledger coverage 75.9% — 116 required, 116 answered, 88 satisfied.** The v5 gate rejected
28 answered rows as unsupported by their own evidence. Recall rose while measured coverage
fell, because the coverage number got stricter, not because less was read. Do not compare
this percentage with a pre-5.0.0 one.

---

## 2. packetloom — built to separate two hypotheses

Corpus design: [CORPUS-DESIGN-DISCRIMINATING.md](../../CORPUS-DESIGN-DISCRIMINATING.md).
Bug ids carry the experimental group (`PL-B*` enumeration-shaped, `PL-C*` locally visible)
independently of difficulty, so "better at enumeration-shaped bugs" can be told apart from
"better at hard bugs".

> **The corpus was expanded on 2026-08-09 and §2.1's rows describe a different tree.**
> It went from 16 bugs / 6 decoys / 1,846 lines to **30 bugs / 10 decoys / 3,434 lines**,
> adding `backoff.c`, `credit.c`, `optparse.c`, `reasm_oo.c`, `stats.c` and `timer.c`.
> Nothing in §2.1 is comparable with §2.2, and no fanout cell exists on the new tree.

### 2.1 The 16-bug corpus, c-review v4 vs fanout

Corpus design: [CORPUS-DESIGN-DISCRIMINATING.md](../../CORPUS-DESIGN-DISCRIMINATING.md).
Bug ids carry the experimental group (`PL-B*` enumeration-shaped, `PL-C*` locally visible)
Both arms ran in the same hermetic container; all four cells VALID.

| replicate | c-review | fanout |
|---|---|---|
| 1 | 15/16 | 14/16 |
| 2 | **16/16** | 15/16 |

| group | n | c-review r1 / r2 | fanout r1 / r2 |
|---|---|---|---|
| enumeration `PL-B*` | 10 | 9 / **10** | 8 / 9 |
| control `PL-C*` | 6 | 6 / 6 | 6 / 6 |

Cost: c-review 2.33M / 2.48M over 8 agents; fanout 1.82M / 1.94M over 18. **fanout was
cheaper on this corpus**, inverting sigil's ordering — do not repeat "c-review is cheaper per
line" as a general claim.

**Against the design's own falsification criteria (§0 of the design doc):**

- **The control set is level, 6/6 vs 6/6, in four cells out of four.** The corpus passes its
  own fairness check: control bugs were free points for both arms, so fanout is not simply
  losing everywhere and the enumeration comparison is not confounded.
- **The enumeration gap is +1, twice. That is not "clearly ahead."** The design set the bar
  at ~2 bugs on a 10-bug set. Reproducible direction, still under the corpus's own threshold.
- **PL-B08** — an unchecked return inside a five-call teardown — is the bug fanout missed in
  **both** replicates. That is the enumeration shape behaving as designed: invisible on a
  single read, findable by listing all five cleanup calls and checking which test their return.
- Decoys: 6 planted, **0 charges on either arm** in three of four cells (one in fanout r2).

**Honest verdict: consistent with the hypothesis, replicated, and short of the design's own
bar for confirming it.**

**Outstanding, and the design requires it before this corpus settles anything (§9 step 2):**
a person other than the corpus's author must read the ten enumeration bugs cold, without the
mechanism column, and confirm each is genuinely invisible on a single careful pass. If they
are not, that is the alternative explanation for fanout's 8–9 out of 10 and these cells
cannot distinguish it.

### 2.2 The 30-bug corpus, c-review v5.0.0, 2026-08-09

One cell. **No fanout counterpart exists on this tree**, so nothing here is an arm comparison.

| cell | recall | agents | tokens | wall | gate |
|---|---|---|---|---|---|
| v5.0.0 container | **24/30** (80.0%) | 8 | 2.71M | 45 min | VALID |

`suppressed 0, near-miss 2, miss 4`. Decoys: 2 charged of 10; 0 control-tree claims; 19
unmatched findings needing human triage.

**The tier breakdown is inverted and that is the finding worth chasing:**

| tier | n | hit |
|---|---|---|
| HARD | 10 | **10/10** |
| MEDIUM | 9 | 8/9 |
| EASY | 11 | **6/11** |

Every HARD bug was found and nearly half the EASY ones were not. The five EASY non-hits:

- **PL-B09, PL-B16, PL-B20** — all `oob-read`, all outright MISS. Three misses in one class
  is a pattern, not variance, and `oob-read` exists precisely because `buffer-overflow` is
  the out-of-bounds *write*. Worth checking whether the class brief or the `bounds` ledger
  question is steering reviewers to writes only.
- **PL-C08, PL-C10** — both `buffer-overflow`, both NEAR_MISS at the right function
  (`reasm_oo_peek`, `stats_name_copy`), failing only the grader's keyword groups
  (`no check` / `never checked` / …). These may be grading artifacts rather than misses;
  someone who did not run the cell should decide.

PL-B08 — the unchecked return in a five-call teardown that fanout missed in both §2.1
replicates — was MISSED here too, on the larger tree.

**Ledger coverage 46.6% — 427 required, 427 answered, 199 satisfied.** Every owed row was
written and more than half were rejected by the gate. Markedly worse than sigil's 75.9% on
the same plugin build, and the obvious hypothesis is unit count: 154 units across 3,434
lines against sigil's 43 across 901. Not investigated.

**PL-B09 is a grading artifact, not a lost bug.** c-review filed it at both the cause site
(the dispatch table) and the consequence site; the dedup agent correctly merged them, and the
surviving write-up names the dispatch table, so a human lands on the right code. It scores
SUPPRESSED only because `lib/grade.py` matches the primary's site and ignores
`also_known_as`. Detected-and-usefully-reported recall is 16/16. Teaching the grader to
consider merged sites would raise the number, which is exactly why it was left alone —
someone who did not run the cell should decide that on its merits.

---

## 3. zstream — 15 bugs, 9,260 lines, de-identified zlib. **Do not use.**

| arm | recall | agents | tokens | gate |
|---|---|---|---|---|
| bare | 2, 4 | 1 | 0.75M, 0.47M | VALID |
| taxonomy | 3, 4 | 1 | 0.89M, 0.89M | VALID |
| fanout | 7, 7 | 13 | 4.52M, 4.12M | VALID |
| c-review v2 guarded | 9, 4 | 23, 25 | 5.16M, 4.89M | VALID |
| ~~c-review v3~~ | ~~11, 14~~ | 37, 38 | 9.34M, 9.67M | **INVALID** |

**De-identification does not survive recall.** Both v3 cells voided because agents recognised
de-identified zlib from memory and said so. Blocking the network did not help — the guard
worked perfectly and the cells still voided. This is not a plugin problem and no prompt fixes
it; the corpus is unusable for a strong model. `jsengine` (68 KLOC, derived from quickjs) has
the same defect and has never been run.

---

## 4. Environment contamination — every cell before 2026-08-07 ran polluted

Established from a cell's own `"subtype":"init"` record, which is written to the session log:

| | host cell | container cell |
|---|---|---|
| plugins | 20 | **1** |
| skills | 48 | **18** |
| plugin skills | c-review, concept-prover, contrarian, exa, slack… | **`c-review:c-review` only** |
| memory path | live host directory | container-local |
| foreign `SessionStart` hook | **executed 4×** | **0** |

The host session offered a security reviewer *other security-review skills*, and an unrelated
plugin's hook executed inside the measurement, injecting its stdout into the context.
`--strict-mcp-config` closes the MCP surface and nothing else.

Every historical cell above ran this way, so arm-to-arm comparisons remain roughly
like-for-like, but **no number predating the container measures the plugin in a clean room**.
The container is also ~33% cheaper (1.81M vs 2.69M on the same cell), because the host was
dragging 48 skills of context into every agent.

---

## 5. Harness defects found by running the measurement

Every one produced a plausible wrong number or blocked the mandated sequence, and none was
visible in a passing test suite. Recorded because this class of bug is the expensive one.

| defect | effect |
|---|---|
| Validator used `grep -oP` (rejected by BSD grep) with stderr to `/dev/null` | printed "all valid" having matched nothing, for months |
| Eval grader judged the response text, not the artifact | a run that skipped the work scored a pass |
| Citation gate validated only citations that were present | a document with zero citations passed |
| `collect` matched on arm+corpus, ignoring variant | a control-tree result was collected as a bench result |
| Result read while the workflow was still writing it | three published numbers wrong |
| Driver's persist-recovery outlived the persist agent | refused a good cell; cost one run |
| Assembler exited 0 with zero *producing* parts | a dead run reported as "found nothing" |
| Hand assembly passed no `--expect` | `agent_failures: []` on a run with a lost slice |
| Workflow rejected a JSON-encoded `args` string | lost a full cell ~45 min in |
| `run-cell.sh` exits **0** on a void cell | two dead packetloom cells both reported `rc=0`; a scripted sequence cannot tell a scored cell from a failed one without reading the log |
| `drive.py:35` hardcodes a **host** path for its cost step | crashes inside the container after the cell has completed, so no `.meta.json` is written. The cell is fine; collect host-side with `bench.py cost` |
| The driver nudges an already-finished session | packetloom attempt 1 finished in ~51 min, then took 70 more nudging a dead session to the 7200s deadline. `!! gave up waiting` reads like a slow cell and was not one |

**The rule they all violate: a checker that inspects zero items must fail, not pass.**

---

## 6. Standing cautions

- **Never `git checkout` a corpus recipe.** That restores the answers to disk while leaving
  the sealed archive in place, and the seal is silently gone. Use `bench.py unseal`, and
  re-seal with the same key. On 2026-08-09 this happened to `packetloom/recipe.public.json`
  and reverted the corpus from 30 bugs to 16 in the only file a reader checks. It was
  recoverable **only because the private recipe travels inside `sealed.tar.gz.enc` and
  `seal` regenerates the public file from it** — that is the design working, not luck.
- **Budget three attempts per cell.** Of three packetloom cells on 2026-08-09, one scored:
  the first lost a review slice (one agent wrote no part file, and v5's `--expect` allowlist
  correctly refused to assemble a short document), the second died on
  `401 OAuth access token has been revoked` mid-run. Check the token before a long cell —
  the failure arrives an hour in and voids everything after it.
- **While a corpus is sealed, ~40 harness tests fail.** That is expected, not a regression.
- **Report unique true positives, and state the variance floor before any ranking.**
- **Name the token basis on every table.**
