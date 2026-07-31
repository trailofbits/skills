# Analysis Format

The output format for a per-requirement analysis. The agent defines what to check; this defines how to write it
down. One document per requirement.

## Structure

Sections in this order, separated by `---`:

```markdown
## REQ-04 — <the requirement in a few words>

> "<the requirement quoted verbatim>"
> — SPEC.md §3.2

**Verdict:** partial · confidence: high

**What this demands of an implementation:** the property that has to hold, restated concretely enough to look
for. Name the quantities and where they come from.

**Where enforcement lives:**

​```solidity
// Vault.sol:L80-L85
<the code>
​```
- What it checks, and against what.
- Which paths reach it, and which do not.

**Paths walked:**
- `redeem` → `_collateralPreserved`: Standard tier reaches the comparison at L84. ✓
- `redeem` → `_collateralPreserved`: Senior tier returns `true` at L82 without comparing. ✗ — the gap.

**Searched:**
- `locked` → 4 hits: L24 declaration, L57 write, L84 comparison, L98 transfer in `reassign`
- `tier` → 3 hits, none in a bounds check other than L81
- modifiers on `redeem` → `notPaused` only; no collateral check
- callers of `redeem` → none in scope; it is an entrypoint

**How the verdict was reached:** why this verdict and not the adjacent one. For `partial`, why it is not
`contradicted`; for `absent`, why the searches above are exhaustive rather than merely unsuccessful.

**Open questions:**
- unclear; need to inspect X
```

## Conventions

Cite code as `File.ext:L45` or `L89-L135`. Quote the document verbatim and cite its section — a paraphrase
silently substitutes your reading for the requirement.

The **Searched** section is what makes an `absent` verdict worth anything. Record the pattern and its result,
including the searches that found something irrelevant. `0 hits` and `6 hits, all in tests` are both evidence;
"I looked and found nothing" is not.

Spend words where the code earns them. A requirement enforced in one line takes one line to confirm. Branches,
call chains, and the paths where enforcement goes missing are where the depth belongs. There is no minimum
number of anything, and padding a section to fill this template produces text that looks like analysis and
isn't.

Leave a section out only when it is genuinely empty, and say so: "No enforcement found anywhere." A missing
section could mean "none" or "never checked", and the reader cannot tell which.

## Before you finish

Every claim either cites a line or sits in Open Questions. Every path through each function called was walked,
not only the one that returns successfully.

Cut the hedges. "Probably", "seems to", and "should be" each become a claim with a line number or an open
question.

Finishing with open questions is a complete analysis. Finishing with open questions you never wrote down is not.
