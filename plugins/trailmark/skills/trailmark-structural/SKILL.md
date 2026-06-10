---
name: trailmark-structural
description: "Runs full Trailmark structural analysis by building a graph, running `preanalysis()`, and reporting hotspots, taint, blast radius, privilege boundaries, attack surface, and version-gated Trailmark 0.4.x data such as proxy counts, subgraph edges, and type/reference summaries. Use when vivisect needs detailed structural data for a target. Triggers: structural analysis, blast radius, taint analysis, complexity hotspots, proxy nodes, type references."
allowed-tools: Bash Read Grep Glob
---

# Trailmark Structural Analysis

Builds a Trailmark graph and runs `engine.preanalysis()` to compute all
four pre-analysis passes. The core workflow is v0.2-safe; v0.4-only details
are included only after checking method availability.

## When to Use

- Vivisect Phase 1 needs full structural data (hotspots, taint, blast radius, privilege boundaries)
- Detailed pre-analysis passes for a specific target scope
- Generating complexity and taint data for audit prioritization
- Inspecting proxy/unresolved-call counts, subgraph edges, or type-reference
  summaries when Trailmark 0.4.0+ is installed

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
| "A v0.4 field is always present" | Users may still have Trailmark 0.2.x installed | Probe with `hasattr()` before querying v0.4-only methods |

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

Optionally record the version:

```bash
trailmark --version 2>/dev/null || uv run trailmark --version 2>/dev/null || true
```

Do not fail if this command is missing; use API feature probes below.

**Step 2: Detect languages with Trailmark's parse API.**

```bash
python3 - "{args}" <<'PY'
import json
import sys

from trailmark.parse import detect_languages

print(json.dumps(detect_languages(sys.argv[1])))
PY
```

If the import fails, rerun the same snippet with `uv run python - "{args}"`.
If the result is `[]`, report "Trailmark found no supported languages under
target" and return.

**Step 3: Run the full structural analysis via `QueryEngine`.**

Run this snippet with `python3`. If the import fails, rerun the same snippet
under `uv run python - "{args}"`.

```bash
python3 - "{args}" <<'PY'
import json
import sys

from trailmark.parse import detect_languages
from trailmark.query.api import QueryEngine

target = sys.argv[1]
languages = detect_languages(target)
engine = QueryEngine.from_directory(target, language="auto")
preanalysis = engine.preanalysis()

def summarize_subgraph(name: str, limit: int = 25) -> dict[str, object]:
    nodes = engine.subgraph(name)
    summary = {
        "count": len(nodes),
        "sample_ids": [node["id"] for node in nodes[:limit]],
    }
    if hasattr(engine, "subgraph_edges"):
        summary["edge_count"] = len(engine.subgraph_edges(name))
    return summary

graph = json.loads(engine.to_json())
nodes = graph.get("nodes", {})
proxy_nodes = [
    node_id for node_id, node in nodes.items()
    if node.get("kind") == "proxy" or node.get("origin") == "proxy"
]

payload = {
    "languages": languages,
    "summary": engine.summary(),
    "preanalysis": preanalysis,
    "attack_surface": engine.attack_surface()[:25],
    "hotspots": engine.complexity_hotspots(10)[:25],
    "proxy_nodes": proxy_nodes[:25],
    "subgraphs": {
        name: summarize_subgraph(name)
        for name in engine.subgraph_names()
    },
}

if hasattr(engine, "type_references"):
    payload["type_reference_samples"] = {
        node_id: engine.type_references(node_id)[:10]
        for node_id in list(nodes)[:25]
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
- `proxy_nodes` (empty on v0.2.x or when there are no unresolved calls)
- `subgraphs` with counts and sample IDs

Some subgraphs may have zero nodes for some codebases (this is
normal). Return the full JSON payload regardless.
