---
name: trailmark-structural
description: "Runs full Trailmark structural analysis on Trailmark 0.2.x by building a graph, running `preanalysis()`, and reporting hotspots, taint, blast radius, privilege boundaries, and attack surface. Use when vivisect needs detailed structural data for a target. Triggers: structural analysis, blast radius, taint analysis, complexity hotspots."
allowed-tools:
  - Bash
  - Read
  - Grep
  - Glob
---

# Trailmark Structural Analysis

Builds a Trailmark graph and runs `engine.preanalysis()` to compute all
four pre-analysis passes.

## When to Use

- Vivisect Phase 1 needs full structural data (hotspots, taint, blast radius, privilege boundaries)
- Detailed pre-analysis passes for a specific target scope
- Generating complexity and taint data for audit prioritization

## When NOT to Use

- Quick overview only (use `trailmark-summary` instead)
- Ad-hoc code graph queries (use the main `trailmark` skill directly)
- Target is a single small file where structural analysis adds no value

## Rationalizations to Reject

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "Summary analysis is enough" | Summary skips taint, blast radius, and privilege boundary data | Run full structural analysis when detailed data is needed |
| "One pass is sufficient" | Passes cross-reference each other — taint without blast radius misses critical nodes | Run all four passes |
| "Tool isn't installed, I'll analyze manually" | Manual analysis misses what tooling catches | Report "trailmark is not installed" and return |
| "Empty pass output means the pass failed" | Some passes produce no data for some codebases (e.g., no privilege boundaries) | Return full output regardless |

## Usage

The target directory is passed via the `args` parameter.

## Execution

**Step 1: Check that trailmark is available.**

```bash
trailmark analyze --help 2>/dev/null || \
  uv run trailmark analyze --help 2>/dev/null
```

If neither command works, report "trailmark is not installed"
and return. Do NOT run `pip install`, `uv pip install`,
`git clone`, or any install command. The user must install
trailmark themselves.

**Step 2: Detect languages with Trailmark's parse API.**

```bash
python3 -c 'from trailmark.parse import detect_languages; import json; print(json.dumps(detect_languages(r"{args}")))' 2>/dev/null
```

If the import fails, rerun the same command under `uv run python -c ...`.
If the result is `[]`, report "Trailmark found no supported languages under
target" and return.

**Step 3: Run the full structural analysis via `QueryEngine`.**

Run this snippet with `python3`. If the import fails, rerun the same snippet
under `uv run python`.

```bash
python3 - <<'PY'
import json

from trailmark.parse import detect_languages
from trailmark.query.api import QueryEngine

target = r"{args}"
languages = detect_languages(target)
engine = QueryEngine.from_directory(target, language="auto")
preanalysis = engine.preanalysis()

def summarize_subgraph(name: str, limit: int = 25) -> dict[str, object]:
    nodes = engine.subgraph(name)
    return {
        "count": len(nodes),
        "sample_ids": [node["id"] for node in nodes[:limit]],
    }

payload = {
    "languages": languages,
    "summary": engine.summary(),
    "preanalysis": preanalysis,
    "attack_surface": engine.attack_surface()[:25],
    "hotspots": engine.complexity_hotspots(10)[:25],
    "subgraphs": {
        name: summarize_subgraph(name)
        for name in engine.subgraph_names()
    },
}

print(json.dumps(payload, indent=2))
PY
```

**Step 4: Verify the output.**

The output should include:
- `languages`
- `summary`
- `preanalysis`
- `hotspots` (possibly empty)
- `subgraphs` with counts and sample IDs

Some subgraphs may have zero nodes for some codebases (this is
normal). Return the full JSON payload regardless.
