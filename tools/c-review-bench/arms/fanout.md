# Arm `fanout` — {{N}} generic agents, partitioned by region

**Cell:** `{{ARM}}` on corpus `{{CORPUS}}` (`{{VARIANT}}` variant), {{LOC}} lines.
**Estimated cost:** {{ESTIMATE}}

This is the matched-compute baseline: the same number of agents c-review spends, with
no taxonomy, no judges and no orchestration. It answers the question that decides
whether the plugin's structure is worth anything — *is c-review better than the same
compute spent naively?* In the previous measurement this arm beat c-review on recall.

It is deliberately a **strong** baseline. Regions are contiguous and disjoint so no two
agents read the same code, and every agent may read outside its region for context.
Handing {{N}} agents the same prompt over the whole tree would be a strawman.

`{{N}}` is matched to c-review's agent count on this corpus. If the c-review cell has
already run, take the count from its collected result rather than the estimate and
re-plan with `--fanout-n`.

## Regions

{{REGIONS}}

## How to run it

Spawn {{N}} general-purpose agents **in parallel**, one per region, each with this
prompt and its own region substituted:

```
Review part of a C codebase for security vulnerabilities.

Code root: {{TREE}}
Your region: <the files and line ranges for your index from the list above>
Threat model: {{THREAT_MODEL}}. The attacker controls {{ATTACKER_CONTROLS}}.

Findings must live in your region. You may read anything under the code root for
context — callers, headers, build files — to establish reachability.

Work only from the code in that directory. Do not read anything outside it — not a
sibling directory, not a parent, not a cache. Do not fetch anything, do not search the
web, and do not consult any repository, history, advisory or package index.

Review the code yourself. Do not invoke a skill, a workflow or another agent: this cell
is measuring generic reviewers on a partition, and running a review tool makes it a
measurement of that tool instead. If a skill offers itself, decline it.

Write your findings as JSON to <your own result path> in exactly this shape:

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

Report everything you believe is a real vulnerability with a severity attached; do not
pre-filter to the severe ones. If you consulted anything outside the code root, set
external_sources_consulted to true and say what — declaring it is not penalised, and
failing to declare it invalidates the measurement.
```

## After they return

1. Merge the per-agent JSON into one `{{RESULT_PATH}}`: concatenate the `findings`
   arrays, renumber `id` so they stay unique, OR the `external_sources_consulted`
   flags, and set `found_by` on each finding to its region index so the grader can
   report which region produced which hit.
2. Write `{{META_PATH}}`:

```json
{
  "complete": true,
  "agents": {{N}},
  "tokens": <sum across all agents>,
  "wall_seconds": <wall clock for the whole wave>,
  "model": "<the model you ran them on>",
  "notes": ""
}
```

`"complete": true` is the completion marker — write this file only after every agent
has returned.

3. Collect, passing every transcript:

```sh
uv run bench.py collect --run <RUN_DIR> --arm {{ARM}} --corpus {{CORPUS}} \
  --result {{RESULT_PATH}} --meta {{META_PATH}} \
  --transcript ~/.claude/projects/<project-slug>/
```

Pointing `--transcript` at a directory scans every session file in it, which is what a
fan-out needs: one oracle violation anywhere in the wave invalidates the arm.

## If `{{VARIANT}}` is `control`

The tree is the bug-free corpus: same code, same decoys, no injected bugs. Every
finding that claims an injected bug is a false positive by construction. Say nothing
about this to the agents — the point is that the arm cannot tell.
