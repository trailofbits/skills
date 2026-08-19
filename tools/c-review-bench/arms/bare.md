# Arm `bare` — one agent, one prompt

**Cell:** `{{ARM}}` on corpus `{{CORPUS}}` (`{{VARIANT}}` variant), {{LOC}} lines.
**Estimated cost:** {{ESTIMATE}}

This is the baseline every other arm has to beat. In the previous measurement it beat
c-review on recall at a ninth of the cost, so it is not a strawman and must not be
weakened to make another arm look better.

## How to run it

Spawn **exactly one** general-purpose agent with the prompt below. One agent: if it
fans out internally the cell is void, because it is then a different arm. Give it no
extra context beyond the prompt — no bug-class list, no hints, no mention that bugs
were injected or how many.

```
Review the C code in {{TREE}} for security vulnerabilities.

Threat model: {{THREAT_MODEL}}. The attacker controls {{ATTACKER_CONTROLS}}.
Scope for findings: {{SCOPE}} (relative to that directory).

Work only from the code in that directory. Do not read anything outside it — not a
sibling directory, not a parent, not a cache. Do not fetch anything, do not search the
web, and do not consult any repository, history, advisory or package index.

Review the code yourself. Do not invoke a skill, a workflow or another agent: this cell
is measuring one generic reviewer, and running a review tool makes it a measurement of
that tool instead. If a skill offers itself, decline it.

Write your findings as JSON to {{RESULT_PATH}} in exactly this shape:

{
  "findings": [
    {
      "id": "F-1",
      "file": "src/example.c",
      "line": 42,
      "function": "enclosing_function_name",
      "bug_class": "your own label",
      "title": "one line",
      "description": "the broken invariant and what the attacker controls",
      "code": "the real snippet, copied not paraphrased",
      "data_flow": "source, sink, and what validation exists between them",
      "reachability": "the call chain from an entry point, or the honest limit of what you traced",
      "impact": "what an attacker gets",
      "recommendation": "the fix",
      "confidence": "High | Medium | Low",
      "severity": "LOW | MEDIUM | HIGH | CRITICAL"
    }
  ],
  "external_sources_consulted": false,
  "external_sources_detail": "none"
}

`file` is relative to {{TREE}}. `line` is the line the defect is on. `function` is the
single enclosing function, or "(file-level)". Report everything you believe is a real
vulnerability with a severity attached; do not pre-filter to the severe ones.

If you did consult anything outside that directory, set external_sources_consulted to
true and say what. Declaring it costs you nothing and is not penalised. Failing to
declare it invalidates the measurement.
```

## After it returns

1. Write `{{META_PATH}}`:

```json
{
  "complete": true,
  "agents": 1,
  "tokens": <total tokens for this cell, from the agent result>,
  "wall_seconds": <elapsed>,
  "model": "<the model you ran it on>",
  "notes": ""
}
```

`"complete": true` is the completion marker — write the meta file only after the agent
has returned. `collect` refuses a result without it, and refuses one whose bytes are
still changing.

2. Collect it, passing the session transcript so the anti-cheat gate has something to
   inspect. Without a transcript the arm scores `UNVERIFIABLE` and is excluded:

```sh
uv run bench.py collect --run <RUN_DIR> --arm {{ARM}} --corpus {{CORPUS}} \
  --result {{RESULT_PATH}} --meta {{META_PATH}} \
  --transcript ~/.claude/projects/<project-slug>/<session>.jsonl
```
