# Analysis Format

The output format for a per-function analysis. The skill body defines what to analyze; this defines how to
write it down.

## Structure

One document per function, sections in this order, separated by `---`:

```markdown
## `functionName` in path/to/file.ext (L40-L88)

**Purpose:** Its role in the system and what breaks without it.

**Inputs & Assumptions:**
- `param` (type): what it is. Trust: untrusted | semi-trusted | trusted.
- Implicit: state read, caller identity, environment, clock.
- Preconditions: what must hold on entry, and what establishes each.

**Outputs & Effects:**
- Returns, state writes, events or messages, external interactions, postconditions.

**Block-by-Block:**

​```language
// L52-L54
<the code>
​```
- **What:** one sentence.
- **Why here:** what its position in the order buys.
- **Assumes:** what must hold for it to be correct.
- **Establishes:** the invariant it creates, if any.
- **Depended on by:** the later logic that rests on it.

**Cross-Function Dependencies:**
- Callee `name` (internal | external-source-available | external-black-box): what this function depends on it
  to establish, and on which paths.
- Callers: who reaches this, and what they assume it enforces.
- Shared state: which other functions touch it.
- Invariant couplings: how this function's invariants interact with the system's.

**Open Questions:**
- unclear; need to inspect X
```

## Conventions

Cite lines as `L45` or `L98-L102`. Label code blocks with the language. For every assumption, say what makes
it true — and write `nothing found` when nothing does.

Spend words where the code earns them. Branches, calls out, and anything that changes stored data deserve
real attention; three lines that copy a value deserve three lines back. There is no minimum number of
anything. Padding a section to hit a count produces text that looks like analysis and isn't.

Leave a section out only when it is genuinely empty, and say so: "No external calls." A missing section could
mean "none" or "never checked", and the reader cannot tell which.

## Before you finish

Check that every claim either cites a line or sits in Open Questions. Check that you followed every path
through each function called, not just the one that succeeds. If something you wrote earlier turns out to be
wrong, fix it where it stands and say what changed.

Cut the hedges. "Probably", "seems to", and "should be" each become either a claim with a line number or an
open question.

Finishing with open questions is a complete analysis. Finishing with open questions you never wrote down is
not.
