# c-review

C/C++ security code review. Bug-class knowledge based on the
[Trail of Bits Testing Handbook](https://appsec.guide/docs/languages/c-cpp/).

Invoke with `/c-review:c-review`. Artifacts land in
`$(pwd)/.c-review-results/<iso-timestamp>/`.

## What it does

The skill collects four parameters and hands the review to a workflow script
(`workflows/c-review.js`). The workflow owns concurrency, retries and result
collection. Work is divided **by source location**, not by bug class.

```
/c-review:c-review
└── SKILL.md: collect parameters, resolve paths, one Workflow call
    └── workflows/c-review.js
        ├── Detect    1 agent  enumerate_units.py generates the unit list; platform flags
        │                      from real API usage; state structs; per-class evidence
        ├── Review    4-14     one agent per contiguous slice of the unit list; findings
        │                      with severity, plus a ledger row per (unit x question)
        ├── Sweep     2        the class axis: one agent over every class with no entry
        │                      anywhere, one auditing shared-state struct fields
        ├── Dedup     0-1      only what the assembler cannot merge deterministically
        └── Assemble  1        assemble_findings.py: ledger gate, merges, all artifacts
```

**About 11-12 agents on a mid-size target.** The two axes the measurement says matter —
bug classes and coverage — both survive; almost everything else was cut, because an
earlier design spent three times the agents for no more recall. Gone: the false-positive
and severity judge, a separate ledger-gate agent, a separate second-pass phase, a separate
merge-record writer, and all but one dedup agent. The gate and the deterministic merges
are now code inside the assembler; severity is assigned by the reviewer that found the bug.

| Parameter | Values | Effect |
|---|---|---|
| `threat_model` | `REMOTE` / `LOCAL_UNPRIVILEGED` / `BOTH` | Drives which classes are in scope and the severity table the judge uses |
| `worker_model` | `haiku` / `sonnet` / `opus` / `inherit` | Model for every agent in the workflow |
| `severity_filter` | `all` / `medium` / `high` | What reaches `REPORT.md` and `REPORT.sarif` |
| `scope_subpath` | repo-relative dir, optional | Where findings may live, and the tree the unit list is generated from. Context is read from the whole repo regardless |

Five workflow arguments are optional and rarely set by hand:

| Argument | Default | Effect |
|---|---|---|
| `maxUnitLines` | `150` | Cap on a review unit; larger functions split at syntactic seams |
| `reviewAgents` | derived | Pins the review fan-out outright instead of deriving it (clamped 4–14) |
| `linesPerAgent` | `1500` | Source lines per review agent; lower it to fan out wider at proportionally higher cost |
| `injectFindings` | absent | **Eval-only hook.** Appends synthetic findings before dedup. Never use it in a real review — whatever is passed is reported as if a reviewer found it |

`uv` must be on PATH. Three phases run Python scripts through it, and the first of them
generates the unit list the whole review is partitioned from.

## Why location, not bug class

Twenty arm-cells over two corpora, 54.3 M tokens. A 13-agent undirected fan-out over
contiguous line ranges matched the class-partitioned pipeline at ~40% of the cost, twice,
on both corpora — and the two axes found **different** bugs, each missing the other's in
both of its runs:

| only the class axis found | only the location axis found |
|---|---|
| a missing `free` on an `open()` failure path | an unsigned-overflow wrap case entered when `wnext < op` |
| a `(void)` cast hiding an unchecked return | a header window size stored without a bound check |
| a 64-bit offset clamp done at the wrong width | |
| a state that returns success on a `Z_BUF_ERROR` path | |

Their union beat either axis alone by a wide margin. So both run, but location does the
dividing — it gives coverage you can prove, every line owned by exactly
one agent — and the class catalogue becomes a bounded sweep over ground nothing covered.
Class-partitioned agents skim a whole tree asking one question and are good at scattered
single-site slips; three of the four they uniquely found are in cold error paths.

A label does not buy recall. An `integer-safety` group existed and missed an
unsigned-overflow bug in both of its runs while undirected region readers found it in
both. `logic-flaw`, the least specific class in the catalogue, produced more credited
findings than any other — 28 of 102.

## The ledger

Each unit owes a row per question in a fixed C question set — bounds at every write,
integer width and signedness, allocation/free pairing, `sizeof` arithmetic, NUL
termination, unchecked returns, the caller contract, banned APIs, macro contracts. A
question is only asked where `enumerate_units.py` counted a non-empty population for it.

Three rules make it a gate rather than a checkbox:

1. **A finding raises the prior; it never closes the unit.** Every unit with a finding
   gets a second reader whose only brief is "what else is wrong here?" The 628-line
   function with four planted bugs was also the one with the most misses — nobody ever
   found all four, and reviewers who found two stopped.
2. **A `clean` verdict must account for a counted population.** `sites_accounted` must
   cover every site line the parse counted. A row claiming clean over twelve write sites
   while citing none is a gate failure.
3. **The diff is against the code-generated list, never the agent's own account of what
   it reviewed.** That distinction is the whole difference between this and the previous
   validator, which certified 40/40 clean rows while one worker had fabricated thirteen.

Coverage is reported as **checks completed / checks required**. "Functions touched" would
have shown that 628-line function as fully covered in all four runs that found two or
three of its four bugs.

## The invariant audit

Five bugs no partition reliably reached wore five different class labels —
out-of-bounds write, unsigned overflow, uninitialised use, a broken encoding invariant,
a double free — and were one mechanism: a rule on a field of a shared state struct that
one path breaks. Classes already existed for two of their symptoms and still missed them.

So it is a task, not a label: list the struct's fields, state each field's invariant, find
every writer and every reader, and prove the rule at each. It is C-specific by
construction — `malloc` does not zero, lifetime is manual, and no single function owns the
field. `state-field-invariant` exists in the catalogue as that audit's output; used as a
search term it reproduces the failure it describes.

## Output

```
.c-review-results/<stamp>/
├── units.json        the generated unit list, site populations and assignments
├── assignments/      one file per review agent
├── parts/            one file per agent: exactly what that agent produced
├── ledger-gate.json  checks required vs completed, missing rows, violations
├── findings.json     every finding, including merged duplicates and rejected candidates
├── REPORT.md         severity-grouped, filtered, deterministic render of findings.json
└── REPORT.sarif      SARIF 2.1.0 export of the same reported set
```

Every artifact is built by `scripts/assemble_findings.py` from the part files. `REPORT.md`
and `REPORT.sarif` share one definition of "reported", so the two cannot describe
different sets.

### Persistence is code, and that is the point

The previous last phase handed one agent the entire findings payload and asked it to
retype it into a heredoc. Measured across four cells:

| candidates in payload | shipped | evidence fields lost |
|---|---|---|
| 86 | 23 | on 23/23 |
| 75 | 23 | on 22/23 |
| 25 | 25 | none |
| 15 | 15 | none |

Faithful at 15 and 25, destroyed at 75 and 86 — the failure scaled with the pipeline's own
success — and one guarded run shipped an **empty** findings array while its own stats block
read 14 findings, 2 CRITICAL.

Now every agent writes only its own output, and the workflow tells the assembler how many
findings each part should hold. A part file shorter than what its agent returned is a hard
failure, so a summarised part is caught rather than shipped.

## What was cut, and what it cost

Removing the judge is the one change with a measured downside, so it is recorded rather
than glossed: on the cells where it ran it rejected roughly a third of primaries, and about
half of those were threat-model scope rather than genuine false positives. Per-cell figures
are in [MEASUREMENTS.md](../../tools/c-review-bench/MEASUREMENTS.md).

The scope rejections are recovered for free: the review prompt now carries the threat
model and tells reviewers not to file what it excludes. The rest ship. `findings.json`
records `severity_source: "reviewer"` and `run.judge_ran: false`, `REPORT.md` says the
severities are unreviewed, and the skill is required to say so next to the findings.
Judge cost scales with finding count, which is exactly where this pipeline's cost ran
away, so reinstating one is a re-measurement rather than a toggle.

**Dedup is deterministic first, an agent only for the residue.** `assemble_findings.py`
merges identical `(file, line, class)` and, since v4, any two findings in the same
function within three lines of each other — including across differing bug classes,
which the exact match cannot see. Only what survives both rules reaches an agent, and
there is exactly one, capped by prompt budget rather than by fanning out. Under a
location partition cross-reviewer duplication is near zero by construction, so this
phase usually costs nothing at all.

## Bug classes

**Fifty-six classes in eighteen groups**, consolidated from 66. Groups are no longer agent
units, so their sizes no longer matter and two are single-class. They keep three jobs: the
coarse platform gate, batching the completeness sweep, and the reporting taxonomy.

Always on (13 groups; two classes drop under `REMOTE`):

memory bounds · string handling · format and input APIs · object lifecycle · integer
overflow and bounds arithmetic · conversions, precedence and undefined behavior · return
values and errno · files and sockets · concurrency · ambient state and DoS · build
hardening · library API contract misuse · logic, protocol and crypto

Conditional: C++ lifetime and C++ class semantics (`is_cpp`); Windows processes, Windows
filesystem and paths, Windows IPC and crypto (`is_windows`). POSIX-only classes drop when
the code does not use POSIX APIs, and every gateable class also needs the detect phase to
cite a real candidate site before the sweep will spend an agent on it.

The consolidation is catalogue hygiene and is **not** expected to move recall — it exists
so the completeness sweep has a catalogue worth iterating. Fourteen entries were merged
into the class they were a special case of (the three string-sizing errors into one; the
errno, EINTR and negative-return shapes into `error-handling`), one hygiene lint was
dropped, and two were added:

- **`oob-read`** closes a real hole: `buffer-overflow` is explicitly the out-of-bounds
  *write*, and `oob-comparison` only covers comparisons. No measured recall gain — the two
  out-of-bounds reads in the corpus were both found, credited to neighbouring classes.
- **`state-field-invariant`** is the invariant audit's output, described above.

Two proposed additions were **withdrawn**: neither `validated-value-substitution` nor
`invariant-at-one-call-site` is C-specific, and existing classes already caught every
instance that gets caught at all — the substitution shape 2 of 2 times, the macro-invariant
shape 2 of 2 times, both without a class of their own. They are named patterns inside
`logic-flaw`'s brief instead.

## Evaluation

`tools/c-review-bench/` holds the benchmark harness: corpora whose bugs are **injected by
us**, a grader, an oracle detector, a judge benchmark, and deterministic tests that run in
`make check`. tools/c-review-bench/MEASUREMENTS.md, tools/c-review-bench/MEASUREMENTS.md and tools/c-review-bench/MEASUREMENTS.md record
what each number was and how to reproduce it.

The original corpus — libexpat at a tag with seven public CVEs — has been retired. It
measured whether a reviewer could look the answer up: three of sixteen hunters did, and
four of five ground-truth hits in the headline run came from the contaminated one. Every
bug in the current corpora was injected at a site we chose, and the real-C corpora are
de-identified.

De-identification is not sufficient on its own. In one run two reviewers recognised a
de-identified corpus as zlib despite 1,034 renamed identifiers and fetched upstream; that
cell was voided. The network is now blocked by a `PreToolUse` hook, which **cost nothing**
— oracle runs scored 6 and 7, guarded runs 9 and 4, mean 6.5 either way.

Three things the recall number alone cannot tell you, all of which the harness reports:

- **Whether the arm used an oracle.** Transcripts are parsed and only real `tool_use`
  blocks count — the string `WebFetch` appears in almost every transcript as a tool
  *definition*, so a substring scan would flag every arm including the honest ones. An arm
  with a violation is **excluded** from the comparison, not annotated.
- **What the bugs cost to find.** Tokens, agents and wall time per arm.
- **Judgement.** Every early run returned 100% `TRUE_POSITIVE`, which cannot distinguish a
  good judge with nothing to reject from one that accepts whatever it is handed.
  `judge_bench/` seeds plausible-but-wrong findings and scores retention and rejection
  separately. The judge tier suppressed nothing in either valid guarded run
  (`suppressed: 0`), so it is kept for precision and deliberately not grown — its cost
  scales with finding count.

No scorer here will score nothing: each exits non-zero rather than reporting `0/N` from an
empty inspection, and the same rule governs the plugin's own scripts — `enumerate_units.py`
fails when it parses no units, `check_ledger.py` fails when there is nothing to check, and
`assemble_findings.py` fails when there are no part files.

## Design decisions worth keeping

Undoing any of these regresses the plugin, and each one is a measured failure rather than
a preference:

- **No clearing from recalled knowledge.** One worker cleared thirteen passes by asserting
  upstream CVE fixes were present when they were not, suppressing two ground-truth bugs
  inside its own remit that three cheaper configurations found by plain reading.
- **Platform gating is on API usage, not on a single include.** Three Windows worker
  groups once fired at a portable XML parser because a compatibility header included
  `<windows.h>` — 27% of the fan-out, all of it finding nothing.
- **No stay-in-lane rule.** An early version told workers to skip bugs outside their class
  because "another worker covers them", which was false for every class the manifest did
  not enumerate.
- **A filed finding closes a finding, not a class.** One run filed a single
  stack-exhaustion bug, wrote `reported` over "all recursive constructs", and never
  enumerated the second recursion in the same file — a ground-truth CVE the previous
  architecture had found.
- **The banned-API check demands a flow.** The old brief said of a bare `strcpy` that "the
  presence is the bug, no data-flow trace needed", wired to a judge forbidden from
  rejecting it. That is an unrejectable-finding pump; it never fired on the measured
  corpora because neither uses `strcpy`, and it would fire on the first legacy target.

## Not for

- Kernel drivers or modules (Linux, Windows, macOS)
- Managed languages (Java, C#, Python, Go, Rust)
- Embedded or bare-metal code with no libc
