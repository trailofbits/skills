# c-review — measurement summary

Copy-paste this into the PR. Full record, every cell: [`MEASUREMENTS.md`](MEASUREMENTS.md).

---

## Setup

Corpora with bugs **we injected ourselves**, so no CVE database holds the answers. Each arm
reviews the same tree and a grader matches findings against ground truth by site. An
anti-cheat pass parses transcripts for real tool calls; a cell that consulted an upstream
source is **excluded**, not annotated. Token basis is `tokens_fresh` (input + output + cache
creation) throughout.

Baselines: **bare** (one plain prompt) · **taxonomy** (bug-class knowledge inlined, one
agent) · **fanout** (one agent per bug class).

## Results — sigil, 17 injected bugs, 901 lines

| arm | recall | agents | tokens/cell |
|---|---|---|---|
| bare | 11, 10 | 1 | 0.40M, 0.44M |
| taxonomy | 12, 9 | 1 | 0.40M, 0.59M |
| fanout | 16, 15 | 13 | 1.79M, 2.11M |
| **c-review v5.0.0** | **16/17** (94.1%) | **8** | **2.10M** |

c-review by tier: **EASY 5/5, MEDIUM 9/9, HARD 2/3**; 4 of 10 decoys charged. Per-tier
figures were not recorded for the baseline cells, except that `taxonomy` scored 1/3 then 0/3
on HARD — below `bare`.

> **Variance floor is large — treat 1–2 bugs of 17 as noise.** Two runs of the identical
> `bare` cell scored 11 and 10; `taxonomy` swung 12 → 9. Baselines are two cells each from
> 2026-08-05; c-review is one cell from 2026-08-09.
>
> **The environments differ and it matters for the cost column.** The baselines ran on the
> polluted host (~48 skills dragged into every agent); c-review ran hermetic (1 plugin, 18
> skills, network blocked), which measured ~33% cheaper on an identical cell. A hermetic
> `fanout` would very likely land under 2.10M. No such cell exists.

c-review's cell is **VALID** on the anti-cheat gate and collected with **no
`--allow-incomplete-findings` waiver**, so the number does not depend on admitting partial
findings. `suppressed 0, miss 0`; the one non-hit is a NEAR_MISS on the nonce-reuse bug,
found at the right site but phrased so the grader would not credit it.

### Second corpus, no baseline: packetloom, 30 bugs, 3,434 lines

| arm | recall | agents | tokens | EASY | MEDIUM | HARD |
|---|---|---|---|---|---|---|
| **c-review v5.0.0** | **24/30** (80.0%) | 8 | 2.71M | 6/11 | 8/9 | **10/10** |

The corpus was expanded from 16 bugs / 1,846 lines to 30 / 3,434, so every earlier row
against it — including its `fanout` cells — describes a different tree. Nothing here is a
comparison.

## Conclusion

1. **Far clear of a single prompt.** 10–11 of 17 for `bare`, **16 of 17** for c-review — and
   10/10 on packetloom's HARD tier, which is exactly where `taxonomy` collapsed (1/3, 0/3).
   Bug-class knowledge alone did not substitute for compute; this does.
2. **Parity with the strongest baseline on recall, not a win.** `fanout`'s best sigil cell is
   also 16/17. c-review gets there with 8 agents instead of 13.
3. **The cost comparison is not clean and should not be claimed either way**, for the
   environment reason above.
4. **So the argument is coverage, not recall or cost.** Every line is owned by exactly one
   agent and that ownership is generated from a parse, so what was *not* reviewed is a number
   rather than an assumption. `fanout` cannot say that at any price.

### Three things a reader should have

- **HARD 10/10 but EASY 6/11 on packetloom.** Three of the five EASY non-hits are the same
  class, `oob-read`, all outright misses; the other two are `buffer-overflow` NEAR_MISSes at
  the right function that failed only the grader's keyword groups. Real blind spot or grading
  artifact is unresolved, and worth chasing before anyone quotes 80%.
- **Coverage is reported honestly and it is not high** — 75.9% of checks satisfied on sigil,
  46.6% on packetloom, with every owed row answered in both. The gate rejects rows whose
  evidence does not support them, so this measures the reviewers, not the tree. Not
  comparable with any pre-5.0.0 coverage figure.
- **One lost slice voids the whole run.** Of three packetloom attempts, one scored: the first
  lost a review agent's part file and the `--expect` allowlist refused to assemble a short
  document; the second died on an expired OAuth token. Failing closed is right for an audit,
  but it is a real operational cost.

### Still outstanding

No hermetic `fanout` cell, and no `fanout` cell at all on the 30-bug packetloom — so the
head-to-head is one environment and one corpus out of date. Separately, someone other than
the corpus author must read packetloom's enumeration-shaped bugs cold and confirm each is
genuinely invisible on a single careful pass.
