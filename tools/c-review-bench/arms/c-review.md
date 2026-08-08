# Arm `c-review` — the plugin as shipped

**Cell:** `{{ARM}}` on corpus `{{CORPUS}}` (`{{VARIANT}}` variant), {{LOC}} lines.
**Estimated cost:** {{ESTIMATE}}

The subject under test. Run it exactly as a user would: through its own skill and its
own workflow, with no benchmark-specific arguments. Every deviation makes the number
describe something other than the shipped plugin.

## How to run it

From a session whose working directory **is** `{{TREE}}`:

```
Workflow({
  scriptPath: "{{PLUGIN_ROOT}}/workflows/c-review.js",
  args: {
    outputDir:        "{{TREE}}/.c-review-results/<utc-timestamp>",
    pluginRoot:       "{{PLUGIN_ROOT}}",
    threatModel:      "{{THREAT_MODEL_ENUM}}",
    severityFilter:   "all",
    findingScopeRoot: "{{SCOPE}}",
    contextRoots:     ".",
    workerModel:      "<the model this whole run uses>"
  }
})
```

`threatModel` is c-review's **enum**, not the prose the baselines are given. The recipe's
`threat_model` is written for a human prompt — `sigil`'s reads "REMOTE and
LOCAL_UNPRIVILEGED" — and pasting that here throws at argument validation before a single
agent spawns, which is how this cell came to be the only one that could not run. `plan`
maps the prose onto the enum and refuses to guess when it cannot.

- `severityFilter: "all"` — the grader distinguishes reported from suppressed findings,
  and a filter that drops a correct finding shows up as `SUPPRESSED` rather than as a
  miss. Filtering at the source would hide that distinction.
- Do **not** pass `injectFindings`. It is the judge-benchmark hook, and anything passed
  to it is reported as though a hunter found it.
- Do not tell the reviewer that bugs were injected, how many there are, or where. Do not
  paste the threat model anywhere except the workflow argument above.
- Say nothing about the corpus's provenance. The de-identification is what makes an
  upstream diff useless; a hint about the base project undoes it.

## What to record

The workflow returns the agent count and the artifact paths; the token total comes from
the session. Write `{{META_PATH}}` **after** the workflow call returns:

```json
{
  "complete": true,
  "agents": <1 detect + hunters + dedup + judges + persist, from the workflow log>,
  "tokens": <total across every subagent in this cell>,
  "wall_seconds": <elapsed>,
  "model": "<workerModel>",
  "notes": "groupsFailed: <...>, unjudged: <...>, artifactsWritten: <...>"
}
```

`notes` matters here. A failed hunter group is uncovered ground, and a recall number
computed over a partial run is not comparable with one over a complete run — record it
rather than discovering it later.

## Collecting

`collect` reads c-review's native `findings.json` directly and converts it through the
plugin's own `findings_model`, so "reported" means exactly what a user sees in
`REPORT.md`:

```sh
uv run bench.py collect --run <RUN_DIR> --arm {{ARM}} --corpus {{CORPUS}} \
  --result {{TREE}}/.c-review-results/<stamp>/findings.json \
  --meta {{META_PATH}} \
  --transcript ~/.claude/projects/<project-slug>/
```

Copy `findings.json` to `{{RESULT_PATH}}` first if you would rather keep the run
directory self-contained; either path works, and `collect` records the digest of
whichever it read.

Point `--transcript` at the whole project directory: the hunters are subagents with
their own transcripts, and one oracle violation in any of them invalidates the arm. The
hunters' self-declared `external_sources_consulted` is read out of `findings.json` as
well, and either signal is disqualifying for the benchmark. Neither is penalised in a
real review — consulting upstream is legitimate there, and only a benchmark cares.

## If `{{VARIANT}}` is `control`

The tree is the bug-free corpus: same code, same decoys, no injected bugs. Every finding
that claims an injected bug is a false positive by construction. Run it identically.
