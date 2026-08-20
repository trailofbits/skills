# c-review

C/C++ security code review. Bug-class knowledge based on the
[Trail of Bits Testing Handbook](https://appsec.guide/docs/languages/c-cpp/).

Invoke with `/c-review:c-review`. Artifacts land in
`$(pwd)/.c-review-results/<iso-timestamp>/`.

`uv` must be on PATH — two phases run Python through it.

## How it works

Most review tools split the work by **bug type**: one agent hunts buffer overflows, another
hunts use-after-free, and so on. c-review splits it by **place in the source** instead.

A parser first cuts the codebase into **units** — one function, or a slice of a long
function, capped at 150 lines. Every line of the tree lands in exactly one unit, and each
unit belongs to exactly one agent. That is the coverage claim: not "the agents said they
read it", but "a parser assigned it and we can check".

Then each agent works through its units by **asking the same fixed set of ten questions of
every one**:

> bounds at every write · integer width and signedness · allocation/free pairing ·
> `sizeof` arithmetic · NUL termination · unchecked return values · what the unit assumes
> of its caller · banned APIs · macro contracts · initialisation

A question is only asked where the parser found something for it to be about — no writes in
the function, no bounds question. And crucially, the parser **counts** the relevant spots
(the twelve writes, the four `malloc` calls) and tells the agent the *number* but not the
line numbers. The agent has to read the code to find them.

For each question the agent writes down what it found — the lines it examined and what was
at them, whether or not it filed a bug. Those written answers are the **coverage record**
(called the *ledger* in the code and artifacts). At the end, `check_ledger.py` re-derives
the spots from the source and checks the agent's answers against them. An agent that
skipped a function, or claimed "no bugs here" over twelve writes while naming none, fails
that check and the run is reported as **assembled but unverified**.

Two things this buys, both of which a plain "review this code" prompt gives up:

- **A bug found does not end the question.** A finding is a reason to look harder in that
  function, not to move on — the record still owes an account of the other eleven writes.
- **Coverage is a number you can check**, reported as *checks satisfied / checks required*
  rather than "functions touched". A function can be touched by every agent while most of
  its questions go unanswered.

The bug-type catalogue — 56 classes in 18 groups — still exists, in two roles. Review
agents get the class **names** so they can label what they find. Then a **sweep** phase
takes the classes that got no finding anywhere — minus the ones the platform gate, the
threat model or Detect's candidate-site check already removed — and sends one agent to look
for them across the whole tree, which catches the scattered single-site slips a reader
working through a region in order tends to walk past.

## Pipeline

```
/c-review:c-review
└── SKILL.md                    collect parameters, resolve paths, one Workflow call
    └── workflows/c-review.js
        ├── 1. Detect               1 agent
        ├── 2. Review            4-14 agents
        ├── 3. Sweep              0-2 agents
        ├── 4. Dedup              0-1 agent
        └── 5. Assemble             1 agent
```

| Phase | What it does |
|---|---|
| **Detect** | Runs the parser to build the unit list. Also works out which platform the code targets (from real API usage, not from a single `#include`), which structs hold shared state, and which bug classes have any candidate site at all |
| **Review** | The main pass. One agent per contiguous slice of the unit list; each returns findings with severity, plus one coverage-record row per (unit × question) |
| **Sweep** | The bug-type axis: one agent covering every class that got no finding anywhere and that Detect did not rule out. Plus the shared-state struct audit, only on request |
| **Dedup** | Only the near-duplicate findings the assembler cannot merge by rule. Usually skipped |
| **Assemble** | Runs the coverage check, merges duplicates, and writes every artifact |

**About 8-10 agents on a mid-size target.** Everything that can be deterministic is code
rather than an agent: the coverage check and the duplicate merges both live in the
assembler, so no agent ever retypes another agent's findings.

**There is no false-positive judge.** Severity is assigned by the reviewer that found the
bug and nothing rejects anything, so treat the output as unadjudicated — `findings.json`
records `severity_source: "reviewer"` and `run.judge_ran: false`. Expect some findings to
be wrong or out of scope.

## Why the review agents have no shell

The coverage check only means something if the agent had to read the code to pass it. But
the code that *computes* the answer — which lines each question is about — ships inside this
plugin, and `units.json` sits in the run directory. One shell command over
`enumerate_units.py` would reproduce the whole answer key without opening a single source
file, and a review agent could then write a perfect coverage record having reviewed nothing.
That is not hypothetical: it was demonstrated end to end, scoring 100% coverage with zero
violations.

Hiding the file does not fix it, because the agent can read the plugin too. So the review,
sweep and dedup agents are dispatched through **`agents/c-review-worker.md`**, whose
`tools:` list is `Read, Grep, Glob, Write` — no shell, so the derivation cannot be run. That
tool list is the control; a "please don't" in a prompt is not.

Two consequences worth knowing:

- **It is a hard dependency.** If that file is missing or renamed, every producing agent
  fails to start and the run produces nothing.
- **The detect and assemble agents keep their shell**, because their whole job is to run a
  command. They are trusted rather than controlled, which is why a green coverage check
  means "no gap this could see", not "nobody tampered with it". See
  [AGENTS.md](AGENTS.md) for the full threat model and its two known holes.

## What each file does

| File | Role |
|---|---|
| `skills/c-review/SKILL.md` | The entry point. Collects the four parameters, resolves paths, makes one `Workflow` call, returns the report |
| `workflows/c-review.js` | The orchestrator: the bug-class catalogue, every agent prompt, the phase sequence, and the deterministic duplicate merges |
| `agents/c-review-worker.md` | The tool scope for review, sweep and dedup agents — see above |
| `scripts/enumerate_units.py` | Parses the tree and cuts it into units, deciding which questions each unit owes and counting the spots each question is about. Everything downstream is partitioned from this |
| `scripts/check_ledger.py` | The coverage check: re-derives those spots from the source and diffs them against what the agents wrote down |
| `scripts/assemble_findings.py` | Reads the per-agent part files, runs the coverage check, merges duplicates, and writes all four artifacts |
| `scripts/findings_model.py` | Shared loader; decides which findings count as "reported", so the report and the SARIF cannot disagree |
| `scripts/render_report.py` | Writes `REPORT.md` |
| `scripts/generate_sarif.py` | Writes `REPORT.sarif` (SARIF 2.1.0) |
| `tests/` | The suite, kept out of `scripts/` so what ships and what only proves it works are separable — the tests are larger than the code they cover |

Everything under `scripts/` is plain Python with no agent in the loop, which is the point:
merging, filtering and coverage-checking are deterministic, so they are code.

## Parameters

| Parameter | Values | Effect |
|---|---|---|
| `threat_model` | `REMOTE` / `LOCAL_UNPRIVILEGED` / `BOTH` | Which bug classes are in scope, and the severity table the reviewer scores against |
| `worker_model` | `haiku` / `sonnet` / `opus` / `inherit` | Model for every agent in the workflow |
| `severity_filter` | `all` / `medium` / `high` | What reaches `REPORT.md` and `REPORT.sarif` |
| `scope_subpath` | repo-relative dir, optional | Where findings may live, and the tree the unit list is built from. Reading for context defaults to the whole repo and is a separate knob (`contextRoots`) |

Five workflow arguments are optional and rarely set by hand: `maxUnitLines` (150),
`reviewAgents` (derived), `linesPerAgent` (1500), `invariantAudit` (off) and
`benchmarkMode` (eval-only). See [SKILL.md](skills/c-review/SKILL.md) for what each does
and the traps in `linesPerAgent`.

## Output

```
.c-review-results/<stamp>/
├── REPORT.md         ← start here: severity-grouped, filtered, human-readable
├── REPORT.sarif      the same reported set as SARIF 2.1.0, for CI
├── findings.json     every finding, including ones merged as duplicates
├── ledger-gate.json  the coverage check: how many checks were required, how many were
│                     satisfied, which rows were missing, and every violation
├── units.json        the unit list, with per-question COUNTS — never the line numbers
├── detect.json       platform flags, entry points, shared-state structs
├── assignments/      one file per review agent: the units it owns
└── parts/            one file per agent: exactly what that agent produced
```

`REPORT.md` and `REPORT.sarif` share one definition of "reported", so the two cannot
describe different sets. `parts/`, `assignments/` and the four artifacts are cleared at the
start of every run, so a run that fails partway cannot leave the previous run's files
sitting in place looking current.

## Not for

- Kernel drivers or modules (Linux, Windows, macOS)
- Managed languages (Java, C#, Python, Go, Rust)
- Embedded or bare-metal code with no libc

## Contributing

Design rationale, the coverage-record rules, the coverage check's threat model and its
known limitations are in [AGENTS.md](AGENTS.md). Read it before changing a prompt, a gate
rule or how agents are dispatched — the rules there come from measured failures.
