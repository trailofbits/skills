# Contributing to c-review

Design rationale and the rules that hold the pipeline together. Every load-bearing rule
here came from a measured failure — undoing one regresses the plugin. Read this before
changing a prompt, a gate rule or how agents are dispatched.

User-facing docs are [README.md](README.md) (what it does) and
[skills/c-review/SKILL.md](skills/c-review/SKILL.md) (what the model executes). Keep both
free of design rationale; it belongs here.

## Why location, not bug class

**This plugin used to be class-partitioned** — one agent per bug class — and the
measurement that killed that design was blunt: an *undirected* fan-out of generic agents
over contiguous line ranges matched the class-partitioned pipeline on recall at **~40% of
its cost**, twice, on both corpora. Class-per-agent was paying 2.5× for nothing.

So location does the dividing now, and the reason to prefer it over an undirected region
split is **not** recall or cost — a region fan-out is comparable on the first and cheaper
on the second. It is that the partition is generated from a parse at function granularity,
and that a gate afterwards checks the reading actually happened. A region fan-out assigns
coverage; this measures it.

The two axes still find **different** bugs, so both run. Class-partitioned agents skim a
whole tree asking one question and are good at scattered single-site slips, particularly in
cold error paths. Location does the dividing; the class catalogue is a bounded sweep over
ground nothing covered. **Do not go back to a class-per-agent fan-out.**

A label does not buy recall on its own, which is why `logic-flaw` — the least specific
class in the catalogue — is kept rather than split up, and why it reliably produces the
most credited findings.

The fan-out is deliberately small (about 8–10 agents): the two axes measurement says
matter get agents, and a design spending three times as many was measured at no more
recall. Everything deterministic is code rather than an agent.

## The ledger

Each unit owes a row per question in a fixed set of ten — bounds at every write,
integer width and signedness, allocation/free pairing, `sizeof` arithmetic, NUL
termination, unchecked returns, the caller contract, banned APIs, macro contracts and
initialisation. A question is only asked where `enumerate_units.py` counted a non-empty
population for it.

Five rules make it a gate rather than a checkbox:

1. **A finding raises the prior; it never closes the unit.** A `finding` row still owes an
   account of the rest of its population, and the gate fails the row that skips it. The
   failure it exists to stop: a reviewer that finds one bug in a function treats the
   function as done, and a second bug in the same function is never looked for.
2. **A verdict must account for a counted population.** `sites_accounted` must cover every
   site line the parse counted — for `needs-human` as much as for `clean`, or the escape
   hatch becomes the cheapest route to 100%. A row claiming clean over twelve write sites
   while citing none is a gate failure.
3. **The diff is against the code-generated list, never the agent's own account of what it
   reviewed.** Validating the rows that are present rather than the rows that are owed lets
   a fabricated clean row pass.
4. **The recompute is bound to the enumeration.** Every worker has Write over the run
   directory and the source tree, so "recomputed from the source" on its own means only
   "measured against whatever the agents left behind": a `sites` key written into
   `units.json` would switch the recompute off per unit, and function bodies rewritten with
   their line counts preserved would keep every unit id alive while emptying the
   populations. Both score 100% with zero violations against an unbound recompute. So the
   gate recomputes unconditionally **and** diffs the unit ids, the required questions, the
   per-question `site_counts` and the enumerate-time denominator against what
   `enumerate_units.py` recorded. A missing or non-integer denominator is a refusal rather
   than a skipped check.
5. **The producing workers have no shell.** Withholding the line numbers is not enough on
   its own, because the code that derives them ships beside them and only needs execution
   to run: `enumerate_units.sites_by_id()` is public, pure, and takes `units.json` — which
   sits in the run directory — as its only argument. Review, sweep and dedup agents are
   therefore dispatched through `agents/c-review-worker.md`, whose `tools:` list is Read,
   Grep, Glob and Write. **That tool scope is the control; a prompt instruction is not
   one.** If you change how those agents are dispatched, you are changing the control —
   note that `producingOpts()` assigns `agentType` last on purpose, because a caller
   passing `agentType: undefined` would otherwise win and the subagent would inherit Bash.

The site line numbers are in **neither** the assignment file nor `units.json`, nor in any
other file the run writes. They are recomputed from the source when the gate runs; the
reviewer gets only the count per question. Relocating them rather than not writing them
does not help — any file in the run directory holding these numbers is one `grep -rn`
away, whatever a prompt names.

### What the gate claims, and what it does not

It measures an **honest** reviewer: one that skipped units, thinned its ledger, answered on
evidence text alone, invented rows, or reviewed a tree that moved underneath it. Two
qualifications, because the unqualified sentence is the one a skimmer keeps:

- A moved tree is caught only when the move **changed a site count**.
- An invented unit id shaped like an invariant-audit id (`struct.field` — no colon, no
  slash, no source extension, no path the unit list names) is reported as
  `unverifiable_rows` rather than `unknown_units`, because that is where the invariant
  audit files by design.

It is **not** a control against an adversary, and no version of it has been. Every input it
reads — `units.json`, the part files, the source tree — is writable by the agents it
scores, and a run directory has nowhere to keep a secret from an agent that can read it.
Two limitations follow, both measured and both open:

- A caller that rewrites a function body to a stub, preserves its line span so the unit id
  survives, and edits that unit's `required_questions`, `site_counts` and
  `totals.checks_required` to match produces a self-consistent pair the binding cannot
  distinguish from a genuinely unquestioned unit.
- A count-preserving source edit — a three-statement reorder — is invisible to the binding
  and lands on the reviewer as violations rather than as the source change it is.

**Do not try to close the second with a per-(unit, question) digest.** It has been tried and
it makes things worse: any digest the run can write, the reviewer can read, and its two
bounding parameters — `site_counts` (k) and the unit's line span (n) — ship in the same
object, which turns recovering the population into a `C(n, k)` search rather than a preimage
attack. 68.5% of a 154-unit corpus's site lines were recovered that way in seconds.

The detect and assemble agents each run a command, so both have a shell and both are
**trusted, not controlled** — and the assemble agent runs last, after every part file
exists. Read a green gate as "no gap this could see", not as "not tampered with". If you
need the stronger property it has to come from outside this pipeline: a clean checkout the
agents cannot write, diffed against the one they reviewed.

Coverage is reported as **checks satisfied / checks required**, not "functions touched": a
function can be touched by every agent while most of its questions go unanswered.
Satisfied, not completed — a row the gate rejected was answered but is not coverage, and
reporting only what was answered lets a run with live violations print 100%.

## Persistence is code, never an agent

No agent ever retypes another's findings: each writes only its own part file and
`assemble_findings.py` builds the document from those files. A transcription step scales
badly with exactly the thing the pipeline is trying to produce, and it fails quietly — an
assembler that reads zero producing parts and exits 0 is indistinguishable from a clean run
in any count the workflow can return.

So the counts are asserted rather than reported: the workflow tells the assembler how many
findings each part should hold, and a part file shorter than what its agent returned is a
hard failure rather than a shorter report.

The same rule governs every script here — a checker that inspects zero items must fail.
`enumerate_units.py` fails when it parses no units, `check_ledger.py` fails when there is
nothing to check, and `assemble_findings.py` fails when there are no part files.

## No false-positive judge

Severity is assigned by the reviewer that found the bug and nothing rejects anything. The
reviewer scores against the threat model but is told to file everything and say what the
threat model does to it, never to drop a finding: nothing downstream re-reads its units, so
a bug a reviewer judges out of scope is a bug nobody looks at again. `findings.json`
records `severity_source: "reviewer"` and `run.judge_ran: false`, `REPORT.md` says the
severities are unreviewed, and the skill is required to say so next to the findings.

Judge cost scales with finding count, so reinstating one is a re-measurement rather than a
toggle, and what it would cost in precision has not been measured on a valid cell.

If you do reinstate one, three things are already known and save a cycle:

- **Cost is coupled to recall.** One judge agent per finding means finding 13 bugs instead
  of 4 triples the judge bill — the better the review, the worse the bill. Batching judges by
  source file cut **32 agents to 7 with identical discrimination**.
- **A judge that never rejects anything has not been tested.** The old FP judge returned
  4/4 then 13/13 `TRUE_POSITIVE`. Zero rejections cannot distinguish a good judge with
  nothing to reject from one that accepts whatever it is handed.
- **Seed plausible-but-wrong findings to measure it.** Eight seeded false positives — a guard
  called missing at a line where it demonstrably exists 14 lines above, attacker control
  asserted over an app-supplied parameter, a mitigation called absent while citing the line
  that contains it — were rejected **8/8** in both configurations while killing at most one
  real finding. Without the seeds both configurations scored 100% and measured nothing.

**Dedup is deterministic first, an agent only for the residue.** `assemble_findings.py`
merges identical `(file, line, class)`, and any two findings in the same function within
three lines of each other — including across differing bug classes, which the exact match
cannot see, but only when they sit on the same line. Only what survives both rules reaches
an agent, and there is exactly one, capped by prompt budget rather than by fanning out.
Under a location partition cross-reviewer duplication is near zero by construction, so this
phase usually costs nothing at all.

## The invariant audit

**Off unless `invariantAudit: true`.** It is a whole extra agent and the shared-state-struct
bugs it targets have never been measured on a valid cell — unknown, not disproven, which is
why it is kept rather than deleted. A default run does not audit struct fields, and the
workflow log names the structs it left unaudited.

A rule on a field of a shared state struct that one path breaks can surface under any
symptom label — out-of-bounds write, unsigned overflow, uninitialised use, a broken encoding
invariant, a double free — so a class label you grep for finds symptom sites and not the
mechanism.

So it is a task, not a label: list the struct's fields, state each field's invariant, find
every writer and every reader, and prove the rule at each. It is C-specific by construction
— `malloc` does not zero, lifetime is manual, and no single function owns the field.
`state-field-invariant` exists in the catalogue as that audit's output; used as a search
term it reproduces the failure it describes.

## Bug classes

**Fifty-six classes in eighteen groups.** Groups are not agent units, so group size does not
affect the fan-out and a single-class group is fine. They do three jobs: the coarse platform
gate, batching the completeness sweep, and the reporting taxonomy.

Always on (13 groups; two classes drop under `REMOTE`): memory bounds · string handling ·
format and input APIs · object lifecycle · integer overflow and bounds arithmetic ·
conversions, precedence and undefined behavior · return values and errno · files and
sockets · concurrency · ambient state and DoS · build hardening · library API contract
misuse · logic, protocol and crypto.

Conditional: C++ lifetime and C++ class semantics (`is_cpp`); Windows processes, Windows
filesystem and paths, Windows IPC and crypto (`is_windows`). POSIX-only classes drop when
the code does not use POSIX APIs, and every gateable class also needs the detect phase to
cite a real candidate site before the sweep will spend an agent on it. A class with no grep
to gate it on — `buffer-overflow`, `memory-leak`, `error-handling` and the rest that are
present in essentially any C — is never put to the detect phase, so it is always swept when
silent.

The catalogue groups related classes so the completeness sweep has something worth
iterating; grouping is not expected to move recall. Two classes are worth calling out:

- **`oob-read`** closes a real hole: `buffer-overflow` is explicitly the out-of-bounds
  *write*, and `oob-comparison` only covers comparisons.
- **`state-field-invariant`** is the invariant audit's output, described above.

`validated-value-substitution` and `invariant-at-one-call-site` are deliberately not
separate classes — neither is C-specific, and both are named patterns inside `logic-flaw`'s
brief instead.

## Design decisions worth keeping

- **No clearing from recalled knowledge.** Every negative conclusion rests on the code in
  front of the reviewer, and any claimed mitigation cites a `path:line`. This is the rule
  that cost the most to learn: the heaviest worker in an early run (13 passes, 160,747
  tokens, 15% of the whole run) cleared *every* pass by asserting that upstream CVE fixes
  were already present. They were not — the guards were verifiably missing in source — and
  two ground-truth bugs inside that worker's own remit were suppressed. The coverage gate
  then recorded it as a clean row, because it audits whether a row was written, not whether
  a search happened. **An audit trail that can certify work nobody did is worse than none.**
- **Platform gating is on API usage, not on a single include.** A portability shim that
  includes `<windows.h>` is not a Windows codebase, and treating it as one spends the
  fan-out on code that cannot hold the bug.
- **No stay-in-lane rule.** Every reviewer may report any class. Telling workers another
  worker covers their gaps is false wherever the manifest does not enumerate the class.
- **A filed finding closes a finding, not a class.** Filing one stack-exhaustion bug does
  not mean every recursive construct in the file has been enumerated.
- **The banned-API check demands a flow.** A bare `strcpy` is not reportable on presence
  alone — the finding must show the data flow to the sink. "Presence is the bug" wired to
  something forbidden from rejecting it is an unrejectable-finding pump.
- **Cold error paths are read deliberately**, because that is exactly what an
  attacker-reachability prior deprioritises. Reachability weights depth, never coverage:
  every unit has an owner.
- **External sources are declared, not forbidden.** Consulting upstream is legitimate in a
  real audit; it only invalidates a benchmark run against a public corpus. Reviewers
  declare it, the harness excludes any arm that used an oracle, and nothing in the review
  path penalises the declaration.

## What the measurements established

### How to falsify this design

"Better than nothing" is not the question, and the bare prompt is the bar rather than a
strawman. Four arms exist because each isolates one variable:

| Arm | What it isolates |
|---|---|
| `bare` | one agent, one prompt. The floor — and it once beat c-review on recall at a ninth of the cost |
| `fanout` | N generic agents, N matched to c-review's real agent count. Separates **structure** from **compute** |
| `taxonomy` | one agent handed the bug-class list inline, no fan-out. Separates **knowledge** from **architecture** |
| `c-review` | the plugin |

**`taxonomy` is the decisive arm.** If one agent holding the class list matches the whole
pipeline, the orchestration is decoration. That is not hypothetical: when first run,
`taxonomy` at 198 K tokens matched and beat c-review v1 at 1.07 M. Two independent sides of
an adversarial review converged on this arm as the one that matters. Any change that claims
to improve the plugin should be checked against it, not against the plugin's own past.

### Cost is agent count, not per-agent verbosity

Measured across a rewrite: per-agent cost stayed flat (**76,124 → 78,242 tokens/agent,
1.03×**) while agent count went **14 → 34 (2.43×)**. Total followed agent count almost
exactly. Two consequences that contradict the obvious intuition:

- The only large lever is **how many agents**, so `reviewAgents` and `linesPerAgent` are the
  cost knobs and prompt length is not.
- **Simplifying prompts was cost-neutral per agent and recall went up.** Removing every
  regex search seed did not make agents read less. Do not trim a prompt to save money; it
  does not work, and it can cost recall.

### Where every arm fails

Bugs **outside classic memory-safety taxonomy**. On the expat corpus no clean arm found
either HARD bug — a namespace-delimiter injection (pure logic, no memory corruption) and an
encoding invariant enforced at some call sites of a shared macro but not others. The
catalogue has no real owner for authorization logic, injection, protocol state machines,
deserialization, or crypto on POSIX targets.

This is why a corpus needs a HARD tier and why **tier breakdown must be reported separately
from the total** — a headline recall number hides exactly the class of bug this plugin is
weakest at.

### Group balance

The worker owning 13 of 40 passes was simultaneously the least accountable agent and the one
that fabricated clearances. A load spread of ~2.4× is workable. Avoid junk-drawer groups that
mix "check a build flag" with "audit every comparator for transitivity": the cheap check
crowds out the expensive one inside a single agent's budget.

## Evaluation

The plugin is measured, not argued. The measurements come from an internal benchmark harness
that is **not part of this repository** — it is kept separately because it carries sealed
corpora whose answers must not be public. Nothing in this plugin resolves to it; every claim
below is stated so it stands without the harness in front of you.

Do not quote a per-cell number into a doc in this plugin: a number in a doc goes stale and
no test catches it. Ask for the harness if you need to re-measure before changing a
load-bearing rule.

Bugs are injected at sites we chose rather than taken from public CVEs, so no database holds
the answers, and the real-C corpora are de-identified. **De-identification is not sufficient
on its own**: a strong model can recognise a de-identified corpus from memory and fetch
upstream, which voids the cell. Network access is blocked by a `PreToolUse` hook during
evaluation runs, and an authored corpus is preferred over a de-identified one.

**Report recall and precision separately, never F1**, and never a raw finding count without
adjudication. Beyond the primary numbers, three secondary metrics each earn their keep:
**unique true positives** (the only metric that can justify an expensive arm whose total
recall merely ties), **suppressed count** (bugs found by a worker then killed downstream —
a different failure from never-found, needing a different fix), and **repeatability** across
identical runs, which is what gives the noise floor.

Two things the recall number alone cannot tell you, both of which the harness reports:

- **Whether the arm used an oracle.** Transcripts are parsed and only real `tool_use` blocks
  count — the string `WebFetch` appears in almost every transcript as a tool *definition*, so
  a substring scan would flag every arm including the honest ones. An arm with a violation is
  **excluded** from the comparison, not annotated.
- **What the bugs cost to find.** Tokens, agents and wall time per arm.

Seeded decoy bugs whose "fix" is already present are graded inside the normal arm comparison.
