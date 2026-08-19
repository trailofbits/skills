# Spec-to-Code Compliance

Check code against the documentation that specifies it. Every gap is either a bug or a documentation fix, and
which one it is is the finding.

**Author:** Omar Inuwa

## Install

```
/plugin install trailofbits/skills/plugins/spec-to-code-compliance
```

## Use

```
/spec-to-code-compliance:spec-compliance ./contracts
```

The slash command takes a path. To name the specification directly or widen the fan-out, ask for the run in
words — "run spec-compliance on ./contracts against SPEC.md, checking 20 requirements" — and the values reach
the script as `{path, spec, limit}`. Typing that object after the slash command does not work: it arrives as a
string and is treated as the path.

Writes `spec-compliance/REPORT.md` and one analysis per requirement under `spec-compliance/requirements/`. The
session gets the alignment matrix and the surviving divergences, not the analysis.

## How it works

1. **Extract** — find the documents describing intended behavior, and split them into individually checkable
   requirements, quoted verbatim. Compound claims are split: a sentence requiring two things is two
   requirements, because the code can get one right and the other wrong.
2. **Align** — one agent per requirement hunts the code for that requirement alone, reading the enforcement, its
   callees, and its callers. A separate agent sweeps the reverse direction for behavior no document mentions.
3. **Verify** — each divergence goes to two agents that did not produce it, one re-reading the code and one
   re-reading the document, both trying to refute it. What either knocks down is dropped.
4. **Report** — alignment matrix, surviving divergences worst first, undocumented behavior, and the problems in
   the documentation itself.

Per-requirement fan-out is what makes the check honest. Judging a requirement means reading a call chain; thirty
requirements is thirty call chains, which does not fit one context window. Done inline, the first few
requirements get a real check and the rest get a plausible one — and a verdict resting on a promising function
name reads exactly like one resting on having read the function.

## Verdicts

| Verdict | Meaning |
|---|---|
| `implemented` | The enforcement was found and read |
| `partial` | Holds on some paths, not others — usually the most serious verdict in a report |
| `contradicted` | The code does something incompatible with the requirement |
| `absent` | Looked and it is not there; rests entirely on the recorded searches |
| `stronger-than-spec` | The code enforces more than the document asks, so nothing records the dependency |
| `undecidable` | The requirement is too vague to check — a finding against the document |

## Components

- `workflows/spec-compliance.js` — the orchestration
- `agents/spec-compliance-checker.md` — the per-requirement worker; dispatch it directly for a single requirement
- `resources/ANALYSIS_FORMAT.md` — the on-disk format for a per-requirement analysis
- `resources/DOMAIN_NOTES.md` — what counts as a specification and where enforcement hides, across contracts,
  C and C++, services, and firmware, plus scoping a check against an RFC or standard
- `resources/WORKED_EXAMPLE.md` — three requirements chased to a verdict, for calibration
- `resources/DIVERGENCE_RUBRIC.md` — severity, and the two directions of a gap

Resources live under `skills/spec-to-code-compliance/`.

## Migrating from 1.x

`/trailofbits:spec-compliance <spec> <codebase>` is removed. The entry point is
`/spec-to-code-compliance:spec-compliance <path>`, and the arguments inverted: the path comes first and the
specification is discovered rather than named. Pass `{path, spec}` when you want to point at it directly.

PDF whitepapers work. DOCX and Notion exports do not — 1.x claimed to normalize them and had no converter; the
discovery step now names an unreadable document instead of guessing at its contents.

The report is no longer a fixed 16 sections. Sections with nothing in them are left out rather than filled.

## Related

- `audit-context-building` — build the system model first when the code is unfamiliar
- `issue-writer` — turn surviving divergences into client-facing findings
