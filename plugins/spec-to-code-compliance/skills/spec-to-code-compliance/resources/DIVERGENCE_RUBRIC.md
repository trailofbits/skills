# Divergence Rubric

Severity is about consequence, not about how far the code strayed from the words. A requirement the code
satisfies by different means than the document describes is documentation drift. A requirement the code appears
to satisfy and does not is the finding.

## Severity

**Critical** — value or control moves in a way the document rules out, and someone outside the trust boundary
can cause it. A missing bound that lets a caller withdraw more than they hold. An access check the document
requires and the code omits on a path reachable by an untrusted actor. A formula divergence that accumulates
against users every time it runs.

**High** — the same class of consequence, but gated: it needs a privileged role, an unusual state, or a
precondition the attacker does not directly control. Also the case where enforcement exists on the paths anyone
would test and is missing on one path that is reachable.

**Medium** — a real gap whose consequence depends on something not established. A missing error case that
currently cannot be reached but nothing prevents from becoming reachable. An ambiguity in the document that has
let two components diverge in how they read it.

**Low** — no behavioral consequence. The code is correct and the document describes it wrongly, or the code
enforces more than the document asks. Say plainly that the fix belongs in the document.

## The two directions of a gap

When code and document disagree, decide which one is wrong before assigning severity. If the code's behavior is
the intended one, the finding is that the document misdescribes it — and that is still a finding, because the
document is what the client publishes and what the next reader will believe.

`stronger-than-spec` is the case people skip. The code enforces something no document mentions, so it works
today and nothing records that anything depends on it. That is Low now and a regression later.

## What raises and lowers severity

Raises: an untrusted actor can reach it; it needs no unusual state; it runs on every call rather than an edge
case; the document names the requirement as mandatory; other code depends on the requirement holding.

Lowers: it needs a role only the client holds; a second mechanism happens to enforce the same thing; the
divergence is in a path that cannot currently be reached, with the reason it cannot stated.

Neither: how emphatically the document states it. A MUST the code satisfies through a different mechanism is not
a finding, and a quietly-worded sentence about accounting can describe the most serious gap in the system.

## Stating the consequence

A divergence whose consequence is spelled out gets fixed; one stated as a mismatch gets discussed. So where you
can show it, show it: who acts, in what order, and what they end up with.

Where you cannot, say what would have to be true for it to matter, and leave it there. An invented attack
sequence or a made-up dollar figure discredits the real finding underneath it, and a reviewer who catches one
fabricated number stops trusting the other findings in the report.

## Requirements that cannot be checked

A requirement too vague to check against any implementation is a finding in its own right, filed against the
document. So is a requirement one document states and another contradicts. In both cases the code may be fine —
what is broken is that nobody can say whether it is.
