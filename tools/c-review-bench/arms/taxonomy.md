# Arm `taxonomy` — one agent holding c-review's whole bug-class catalogue

**Cell:** `{{ARM}}` on corpus `{{CORPUS}}` (`{{VARIANT}}` variant), {{LOC}} lines.
**Estimated cost:** {{ESTIMATE}}

One agent, one pass, no fan-out — but handed the entire class catalogue that c-review
distributes across its hunters. This separates two things the plugin bundles: *the
knowledge* and *the orchestration*. If this arm matches c-review, the fan-out is not
what is finding the bugs. In the previous measurement it tied the bare prompt on recall
at 1.7x the cost, which is evidence a checklist can anchor a reviewer as easily as it
can direct one.

The catalogue below is extracted from the shipped `workflows/c-review.js` at plan time,
so it is what the plugin actually uses rather than a copy that has drifted.

## How to run it

Spawn **exactly one** general-purpose agent. Paste the catalogue into its prompt.

```
Review the C code in {{TREE}} for security vulnerabilities.

Threat model: {{THREAT_MODEL}}. The attacker controls {{ATTACKER_CONTROLS}}.
Scope for findings: {{SCOPE}} (relative to that directory).

These are the bug classes worth looking for, each with the part that is easy to get
wrong. You are not restricted to them: report anything you find, whether or not it has
a class here.

{{TAXONOMY}}

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
      "bug_class": "the class id from the list, or your own label if none fits",
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
pre-filter to the severe ones. If you consulted anything outside that directory, set
external_sources_consulted to true and say what — declaring it is not penalised, and
failing to declare it invalidates the measurement.
```

## After it returns

1. Write `{{META_PATH}}` — only after the agent has returned, because
   `"complete": true` is the completion marker `collect` requires:

```json
{
  "complete": true,
  "agents": 1,
  "tokens": <total tokens for this cell>,
  "wall_seconds": <elapsed>,
  "model": "<the model you ran it on>",
  "notes": ""
}
```

2. Collect it with its transcript:

```sh
uv run bench.py collect --run <RUN_DIR> --arm {{ARM}} --corpus {{CORPUS}} \
  --result {{RESULT_PATH}} --meta {{META_PATH}} \
  --transcript ~/.claude/projects/<project-slug>/<session>.jsonl
```

## If `{{VARIANT}}` is `control`

The tree is the bug-free corpus: same code, same decoys, no injected bugs. Every
finding that claims an injected bug is a false positive by construction, and the agent
must not be told which variant it is reviewing.
