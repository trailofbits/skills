# Arm `wilson` — the wilson-audit plugin as shipped

**Cell:** `{{ARM}}` on corpus `{{CORPUS}}` (`{{VARIANT}}` variant), {{LOC}} lines.
**Estimated cost:** {{ESTIMATE}}

> **This arm has never completed a run.** Read
> [WILSON-ARM-FEASIBILITY.md](../../../WILSON-ARM-FEASIBILITY.md) before using it. Two
> things are unproven and both change what the cell measures if they go the wrong way:
> the plugin must be installed and enabled for the session, and `wilson-audit`'s Phase 3
> dispatches hunters as plain `Task` subagents with a natural-language prompt — whether
> such a subagent can invoke the parent session's *plugin* skills by name is untested.
> If the hunters cannot load `/hunt-appsec-taossa` and friends, the fan-out silently
> collapses into one agent doing everything, and the number describes something else.
> Check the transcripts for hunter subagents before collecting.

The subject under test is `wilson-audit`, the single skill that is the whole pipeline
(build-docs → orchestrate → hunters → primitive ladder → chain builder → judge → dedupe
→ export). The `wilson` dispatcher skill is **not** what a packet names: it exists to
route a human to `wilson-audit`, and going through it makes the cell depend on its
routing judgment rather than on the audit pipeline.

## Prerequisite, and it is a real one

`wilson@trailofbits-internal` must be installed **and** enabled for the session. It is
not enough that the marketplace is known. Verify before the run, not after:

```sh
jq -e '.plugins["wilson@trailofbits-internal"]' ~/.claude/plugins/installed_plugins.json
jq -e '.enabledPlugins["wilson@trailofbits-internal"]' <the --settings file this run uses>
```

Both must exit 0. A cell that ran without the plugin loaded measures a generic agent
that was asked for a skill it never had, which is not this arm and must not be collected
as it.

## How to run it

From a session whose working directory **is** `{{TREE}}`, one prompt, no follow-ups:

```
Use the wilson-audit skill to run a complete automated security audit of {{TREE}}.

output_path: {{RESULT_PATH}}.d (the directory already exists; use exactly this and do
not ask for it)
confidence_threshold: 50 (use exactly this and do not ask for it)

Threat model: {{THREAT_MODEL}}. The attacker controls {{ATTACKER_CONTROLS}}.
Scope for findings: {{SCOPE}} (relative to that directory).

Work only from the code in that directory. Do not read anything outside it — not a
sibling directory, not a parent, not a cache. Do not fetch anything, do not search the
web, and do not consult any repository, history, advisory or package index.
```

`wilson-audit`'s SKILL.md prompts interactively for `output_path` and
`confidence_threshold`; `claude -p` is a single turn and cannot answer a question. Both
values are pre-supplied above for the same reason `bare` pre-supplies its result path
and `c-review` passes `outputDir` as an explicit argument. SKILL.md content is a strong
prior on behaviour, not a contract — if the transcript shows it asked anyway and then
picked a default, the artifacts are somewhere other than where this packet says, and the
cell is recoverable only if you find them.

- Do not tell the reviewer that bugs were injected, how many there are, or where.
- Say nothing about the corpus's provenance.
- Do not name a hunter here. Hunter selection is `orchestrate-appsec`'s job and naming
  one makes this a different cell — see the TAOSSA-only variant below.

## The TAOSSA-only variant, if you run it

Run it as its **own cell**, never averaged with the full pipeline. Of the eight default
AppSec discovery hunters only `taossa` is unambiguously built for C; four of the rest
are written for web concepts that do not exist in a C memory-safety corpus, so a full
pipeline number mixes real TAOSSA hits with near-zero-signal noise. Add to the prompt:

```
Skip /orchestrate-appsec's hunter selection. Assign only /hunt-appsec-taossa.
```

The isolation is enforced by instruction, not by any plugin mechanism — there is no
`--disable` flag. **A run whose transcripts show other hunters dispatched despite this
must be discarded, not averaged in.** Wilson tags every finding with `hunter_name`, so
report TAOSSA's contribution separately either way.

## Collecting

Wilson writes `final_report.json`, whose shape is not the harness's generic finding
shape. Convert it first — do not hand `final_report.json` to `collect` directly:

```sh
uv run python -c "
from lib.wilson_result import convert_file
convert_file('{{RESULT_PATH}}.d/final_report.json', '{{RESULT_PATH}}')
"
uv run bench.py collect --run <RUN_DIR> --arm {{ARM}} --corpus {{CORPUS}} \
  --result {{RESULT_PATH}} --meta {{META_PATH}} --transcript ~/.claude/projects/<slug>/
```

`lib/wilson_result.py` has 10 tests and **has never seen a real report**. Read its
`wilson_conversion` block in the output before trusting the number: it reports how many
findings arrived with no usable location. Wilson's `normalize_finding()` drops the
`location` object entirely, so a location survives only inside an `evidence[]` item that
carries both a `path` and an integer `line_start`. Findings without one are kept, marked
`wilson_has_location: false`, and given a sentinel file that cannot match any corpus
path — they land in `UNMATCHED` for a human rather than being dropped, because dropping
them would shrink the precision denominator. If that count is most of the findings, the
recall number is measuring the converter's location recovery, not Wilson.

Point `--transcript` at the whole project directory: the hunters are subagents with
their own transcripts, and one oracle violation in any of them invalidates the arm.

## What to record

Write `{{META_PATH}}` after the run:

```json
{
  "complete": true,
  "agents": <1 top-level + every hunter/judge/dedupe subagent, from the transcripts>,
  "tokens": <total across every subagent in this cell>,
  "wall_seconds": <elapsed>,
  "model": "<the model this whole run uses>",
  "notes": "hunters dispatched: <names from the transcripts>; findings with no location: <n>/<total>; plugin verified installed+enabled: yes/no"
}
```

`notes` carries the two things that decide whether this cell is comparable at all: which
hunters actually ran, and how much of the report the converter could locate.
