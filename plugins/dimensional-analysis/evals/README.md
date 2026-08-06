# dimensional-analysis skill eval

Four cases measuring the `dimensional-analysis` **skill** on Python rather than
Solidity. `references/bug-patterns.md` says the patterns "occur in any language
performing arithmetic with mixed units and scaling factors (Rust, TypeScript, Python,
etc.)", and then carries 59 Solidity code blocks and no Python ones, so nothing
measures that claim. The arithmetic here is exchange execution accounting: base
amounts, quote amounts, prices, basis points, funding intervals.

```sh
claude plugin eval . --ablation with-without --judge-model sonnet
```

The headline number is **Δ**: with-plugin score minus without-plugin score. Every case
runs in both arms, three runs each.

`--judge-model sonnet` is required, not a preference. Case 03 turns on the difference
between "this looks like the oracle-precision bug pattern" and "this is that pattern
applied correctly"; a small judge collapses the two and the suite still emits numbers
that no longer mean anything.

## Cases

| Case | Shape | Ground truth |
|---|---|---|
| `01-quote-per-base` | Four sibling executors, one wrong | 1 real, 3 correct |
| `02-neg-correct-denominator` | Case 01's bug, after the fix | 0 real |
| `03-all-correct-panel` | Five helpers that resemble known patterns | 0 real, 5 correct |
| `04-neg-explain-function` | "What does this do?" | must stay an explanation |
| `05-scaling-direction` | Three conversions, one wrong exponent | 1 real, 2 correct |

Nine scored graders: two recall, four precision, two that require a conclusion to be
reached at all, one that requires the answer to stay an answer. That is less
recall-weighted than the `variant-analysis` suite next door, which runs four positive
cases to three negative, and the reason is that the failure this plugin is likelier to
have on unfamiliar code is over-reporting rather than blindness. Every helper in these
cases has units in it, so a run that has decided units are suspicious can flag all of
them and look busy. If piloting shows the precision floor is never in danger, the
cheapest rebalance is a third positive case rather than a reweight.

Case 01 is a real bug, not a constructed one, and the four snippets are the upstream
code rather than a paraphrase of it. `net_pnl_quote / executed_amount_base` divides a
quote amount by a base amount and reports the result as a return percentage; the
leftover `{quote/base}` is a price, so the number is wrong by the entry price.
Measured on the upstream code, a round trip returning 0.27% was reported as 800%. It
shipped in two executors and was reported upstream as
[hummingbot#8408](https://github.com/hummingbot/hummingbot/pull/8408).

The quote dimension of the numerator is not annotated anywhere, which is the point:
`executed_amount_base * average_executed_price` has to be reduced to `{quote}` before
the division reads as wrong. A run that only checks whether names agree cannot get
there.

That origin is what makes case 02 worth having. It is the same function after the fix,
with `executed_amount_base` and `average_executed_price` still in scope and still the
wrong things to divide by. A run that pattern-matches on nearby mixed units flags it;
a run that reads the arithmetic does not.

Case 01 rewards naming the dimensions rather than noticing the odd one out. Three of
the four siblings agree, so "this one differs from the others" reaches the right file
by counting rather than by dimensional reasoning, and that inference does not transfer
to a codebase where the wrong form is the majority. The recall grader requires the
unit argument, and requires the proposed fix to land back in `{quote/quote}`.

Case 03 is the broadest trap for over-reporting: five helpers, no bugs, and every one
of them shaped to look like one. Case 02 is the narrow version of the same trap, aimed
at a single function. Between them they are the whole of the precision floor, so if
either goes, the suite stops being able to tell a working run from an eager one. Each
of case 03's helpers resembles a named pattern from `references/bug-patterns.md` while
being correct:

| Helper | Resembles | Why it is correct |
|---|---|---|
| `to_internal` | Pattern 1, Pattern 6 (wrong scaling direction) | `10 ** (18 - 8)` is the right direction and magnitude for an 8-decimal feed |
| `apply_fee_bps` | Pattern 10 (fee applied to wrong dimension) | basis points are parts per 10,000, so `quote * bps / 10_000` stays quote |
| `funding_owed` | Pattern 11 (time unit confusion) | the seconds-to-hours conversion is present, and `{quote}*{1/h}*{h}` is quote |
| `average_entry` | Pattern 12 (division before multiplication) | summing quote and base before dividing is the correct volume weighting |
| `fill_notional` | the multiply-instead-of-divide reading | `{base} * {quote/base}` is quote |

That section of the reference has its own "False Positive Avoidance" guidance. Case 03
is where it gets measured.

Case 05 is the only constructed case in the suite; the rest come from real code. It
puts the plugin's own home turf in Python: `price_to_internal`
multiplies by `10 ** FEED_DECIMALS` where the gap between the two representations is
`INTERNAL_DECIMALS - FEED_DECIMALS`, so every mark comes out 100 times too small. Its
two siblings use that difference correctly, once upward and once downward, which is
what stops "the exponent looks odd" from reaching the answer.

Case 03's `to_internal` is the same conversion done right, so the pair reads as a
discrimination test across the suite: the identical shape appears once as a correct
helper the run must leave alone and once as the bug it must find.

## Scope

These cases measure the **validate** end of the pipeline: whether an arithmetic defect
is found and whether correct arithmetic is left alone. `SKILL.md` describes a wider
workflow of discover, annotate, propagate, then validate, and nothing here scores the
annotation output itself, only that recommending annotation is never punished. A suite
for the annotation pass wants fixture files on disk and a diff-shaped grader, which is
a different build.

Nothing here has been piloted against a live run. The `variant-analysis` README says
to expect two or three calibration passes before a rubric is trustworthy, and its
account of what those passes turned up, fixtures labelled safe that were not, a
severity clause fighting a claim clause, is the reason to say plainly that this suite
has had none. The ground truth has been checked by hand and by arithmetic; the rubrics
have not been checked against a judge.

## Grader design

Recall and precision are graded **separately** on cases 01 and 05, so a score change
tells you which one moved.

Precision graders are **claim-based**: the only question is whether the response claims
a dimensionally correct site has a unit defect. Raising a genuinely different concern
at one of those sites, an unguarded zero denominator, `Decimal` versus `float`,
truncation instead of rounding, a negative exponent if a feed ever reports more than
18 decimals, passes. That is correct reviewer behaviour and the graders must not
punish it. The distinction is claim-based, not severity-based: "this one is also
dimensionally wrong" fails; "this one is dimensionally fine, but here is a separate
concern" passes.

Recommending that units be annotated passes everywhere, including on the negative
cases. Annotation is what the plugin exists to do, and a suite that treats it as a
false positive would score the skill down for working.

Cases 02 and 03 pair their precision grader with one that only asks whether a
conclusion was reached. A precision check alone is passable by silence: a response
that narrates the code and never commits has claimed no defect, so it clears the
precision bar without answering the question. The conclusion graders judge commitment
and ignore correctness; the precision graders judge correctness and ignore
commitment. Neither should be folded into the other, because a run can fail one while
passing the other and it matters which.

Validation does not cover any of this. `validate_reference_links` in
`.github/scripts/validate_plugin_metadata.py` skips any path with `evals` in it, so
`make validate` reports on the plugin around this directory rather than on the
directory itself. The links here were checked by hand.

The `skill-fired` grader on case 01 is **display-only** under ablation: no `arm:` and
no `weight:`, so it is reported rather than scored and never moves Δ. It gives the
trigger rate independently of answer quality. Cases 02 to 04 carry no such grader on
purpose. A `skill-not-fired` check would be unfailable in both arms: the baseline arm
has no plugin, so `Skill` never fires there, and a grader no arm can fail is worth
deleting rather than reweighting.

## What the trigger rate is measuring

The skill's `description` routes on "annotate units", "perform a dimensional analysis",
or "a DeFi protocol, offchain code, or other blockchain-related codebase". `SKILL.md`'s
own "When to Use" is wider than that: it lists "financial code" and "hunting for
arithmetic bugs caused by unit mismatches", neither of which mentions a chain.

None of the five cases asks for a dimensional analysis by name, because a suite that
does is measuring compliance rather than routing. They name the domain instead, which
is what a person reviewing this code would actually say. That leaves the description's
blockchain clause carrying the routing, and the `skill-fired` rate on case 01 is what
tells you whether it carries it. A low rate there with a healthy Δ elsewhere is a
finding about the description, not about the analysis.

Case 04 is the one shape the skill is documented to decline. "When NOT to Use" says a
quick spot-check of a single formula should be read directly rather than run through
the pipeline, and case 04 is exactly one formula.
