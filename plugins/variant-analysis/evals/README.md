# variant-analysis skill eval

Seven triage-panel cases measuring the `variant-analysis` **skill** — whether it finds
look-alike instances of a seeded bug, and whether it rules out the ones that only look
alike. Search recall against a real codebase is covered separately by `../tests/`.

```sh
claude plugin eval . --ablation with-without --judge-model sonnet
```

The headline number is **Δ**: with-plugin score minus without-plugin score. Every case runs
in both arms, three runs each.

`--judge-model sonnet` is required, not a preference. The default judge is haiku, and every
precision grader here turns on a distinction haiku will miss: "this is the same bug" (fail)
versus "this is safe from that bug, but here is a different problem with it" (pass). With a
small judge the suite still produces numbers; they stop meaning anything.

## Cases

| Case | Shape | Ground truth |
|---|---|---|
| `01-shell-sink-family` | Explicit triage ask, Python | 2 real (both a *different* sink API than the seed), 4 safe |
| `02-just-found-this` | Conversational, mid-audit, no format ask | 2 real, 3 safe |
| `03-path-traversal-java` | Explicit, Java | 2 real (incl. zip-slip), 4 safe |
| `04-invariant-bug` | Explicit, non-injection (TOCTOU) | 2 real, 4 safe |
| `05-all-safe-panel` | Explicit, **zero** real variants | 0 real, 5 safe |
| `06-neg-explain-function` | "What does this function do?" | must NOT fire |
| `07-neg-initial-discovery` | "Audit this module" — no known bug | must NOT fire |

Cases 01 and 03 are built so a literal, no-generalization run scores **non-zero but wrong**:
it finds the candidates sharing the seed's exact sink API and misses the ones that require
generalizing to the root cause. That is the "one manifestation only" failure mode, and it is
the sharpest signal in the suite.

Case 05 is the only case that punishes over-reporting. Every other case rewards finding
things. Do not remove it.

## Grader design

Recall and precision are graded **separately** per case, so a score change tells you which
one moved.

Precision graders are **claim-based**: the only question is whether the response claims a
safe candidate is an instance of the seed's root cause. Flagging a *genuinely different*
weakness at a safe site — ffmpeg protocol prefixes, ImageMagick delegates, symlink-follow on
read — passes, with a real severity attached, so long as it is clear that finding is distinct
from the bug being hunted. That is correct auditor behavior and the graders must not punish
it.

This framing was arrived at the hard way. Three calibration pilots produced five failures in
which the model was right and the grader was wrong: two fixtures labelled "safe" that were
genuinely exploitable (a `getCanonicalPath().startsWith(String)` prefix check; an
`os.makedirs(exist_ok=True)` open to symlink pre-planting), and three rubric defects (a
severity clause contradicting a claim clause; a vague "dominated by" test; a caller-tracing
prohibition broad enough to catch ordinary audit follow-up). If you add a case, expect to
pilot it two or three times before the rubric is trustworthy.

The `skill-fired` graders on cases 01–02 are **display-only** under ablation — reported, not
scored, in either arm, so they never move Δ. They tell you the trigger rate independently of
answer quality. Carrying no `arm:` and no `weight:` is the mechanism; adding either would
start scoring a check the baseline arm can never pass.

The negative cases 06–07 briefly carried the mirror image of that, a `skill-not-fired`
grader with `arm: both`. Scored, and unfailable in both directions: the baseline arm has no
plugin so `Skill` never fires, and the with-plugin arm does not fire on these shapes either.
A grader no arm can fail is worth deleting rather than reweighting, so it is gone. The
`type: llm` grader on each of those cases carries the check that matters — whether the
answer stayed an explanation or an audit instead of turning into a variant hunt.

## Two limitations, stated plainly

**Δ is saturated.** Every case scores 1.00 in the without-plugin arm as of the last
calibration: bare Opus 5 handles these panels unaided. Δ can therefore only go *down*. This
is a precision-regression guard and a trigger detector, not an uplift measure. Creating
headroom needs harder panels, or the codebase-search dimension this suite deliberately omits.

**The skill does not fire *on these cases*.** Across 40+ runs and four pilots there were
zero `Skill` invocations here. The skill was present in the model's skills list and the
`Skill` tool was available; the model declined it every time and answered unaided. So on
this suite both arms are the same unaided model and Δ measures noise.

That was first read as a defect in the skill description. It is not — it is a property of
the case shape. A later cold run, 9 runs across three prompt shapes, isolated the cause:

| Prompt shape | Codebase on disk? | Fired |
|---|---|---|
| Conversational: "found a bug in `x.py`, are there others?" | yes | 2/3 |
| The description's trigger language, near-verbatim | yes | 3/3 |
| Inline candidate panel, no files — **the shape of every case here** | no | 0/3 |

Every case in this directory pastes its candidates into the prompt, so there is no tree to
sweep and nothing for the skill to do that the model cannot do inline. Declining it is
arguably correct. Two consequences worth keeping straight:

- The non-firing result here is **not** evidence the skill is undiscoverable in real use.
- Giving these cases files on disk would fix the saturation above *and* the trigger rate at
  once, since it restores the dimension that actually makes the skill worth invoking. That
  is the single highest-value change to this suite and it is not a small one.

One more thing the cold run showed: when something does fire on a real codebase it is
usually `/variant-analysis:variants` (4 of 5 firing runs) rather than the skill itself
(1 of 9). The plugin's entry-point table says so.

## Cost

~$6.53 and ~36 minutes for a full run (7 cases × 3 runs × 2 arms), judge cost included.
Per-case figures range from $0.46 to $1.22. `--runs 1` gives a ~$2.20 smoke test.

## Versioning note

Changes confined to this directory alter no runtime behavior, so a consumer gains nothing
from a version bump. CI's version-increment check does not know that — it fires on any
touched plugin. Either bump `plugin.json`, or apply the `no-version-bump` label to the PR.
Note that `AGENTS.md` currently scopes that label to typo-only changes; using it for eval
scaffolding is a deliberate widening of that policy.
