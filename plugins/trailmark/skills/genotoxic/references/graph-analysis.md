# Graph Analysis for Mutant Triage

How to use trailmark's code graph data to contextualize survived mutants
and assign them to the correct triage bucket.

## Contents

- Mapping mutants to graph nodes
- Reachability analysis
- Blast radius calculation
- Complexity correlation
- Annotation-driven triage
- Batch triage workflow
- Mapping necessist removals to graph nodes
- Merging mutation and necessist results

---

## Mapping Mutants to Graph Nodes

Each survived mutant has a `file_path` and `line` number. Map it to the
containing function in the trailmark graph:

```python
def find_containing_node(nodes: dict, file_path: str, line: int):
    """Find the graph node that contains a given source line."""
    candidates = []
    for node_id, node in nodes.items():
        loc = node.get("location", {})
        if not loc:
            continue
        if loc["file_path"] != file_path:
            continue
        if loc["start_line"] <= line <= loc["end_line"]:
            candidates.append((node_id, node))

    if not candidates:
        return None

    # Prefer the most specific (smallest range) containing node
    candidates.sort(
        key=lambda x: (
            x[1]["location"]["end_line"]
            - x[1]["location"]["start_line"]
        )
    )
    return candidates[0][1]
```

**Why smallest range?** A line inside a method is also inside its
containing class. The method node is the more useful context for triage.

---

## Reachability Analysis

Determine whether a mutated function is reachable from untrusted input.

### From Entrypoints

```python
def is_entrypoint_reachable(engine, node_id: str) -> bool:
    """Check if any entrypoint can reach this node."""
    for ep in engine.attack_surface():
        paths = engine.paths_between(ep["node_id"], node_id)
        if paths:
            return True
    return False
```

### Entrypoint Path Details

For fuzzing targets, include the specific entrypoint paths in the report:

```python
def entrypoint_paths(engine, node_id: str) -> list[dict]:
    """Get all entrypoint paths to this node with metadata."""
    results = []
    for ep in engine.attack_surface():
        paths = engine.paths_between(ep["node_id"], node_id)
        for path in paths:
            results.append({
                "entrypoint": ep["node_id"],
                "trust_level": ep["trust_level"],
                "kind": ep["kind"],
                "path": path,
                "hops": len(path),
            })
    return results
```

### Trust Level Weighting

Not all entrypoints are equally dangerous:

| Trust Level | Weight | Examples |
|-------------|--------|---------|
| `untrusted_external` | 3x | User input, network data |
| `semi_trusted_external` | 2x | Partner APIs, OAuth tokens |
| `trusted_internal` | 1x | Internal service calls |

Higher-weight entrypoints push mutants toward the fuzzing bucket.

---

## Blast Radius Calculation

Blast radius measures how many other functions depend on the mutated
function. Higher blast radius means a bug has wider impact.

### Direct Callers

```python
def blast_radius(engine, node_id: str) -> dict:
    """Calculate blast radius for a node."""
    callers = engine.callers_of(node_id)
    callees = engine.callees_of(node_id)

    return {
        "direct_callers": len(callers),
        "direct_callees": len(callees),
        "caller_ids": [c["id"] for c in callers],
    }
```

### Transitive Impact

For critical functions, calculate transitive callers (all functions
that eventually call this one):

```python
from trailmark.storage.graph_store import GraphStore

# Build the store from the graph
store = GraphStore(graph)

# All nodes that can reach this function
# (predecessors in the call graph)
transitive = store.entrypoint_paths_to(node_id)
transitive_count = len(set(
    node for path in transitive for node in path
))
```

### Blast Radius Classification

| Direct Callers | Transitive Callers | Classification |
|----------------|-------------------|----------------|
| 0 | 0 | Dead code (false positive) |
| 1-5 | 1-10 | LOW |
| 6-20 | 11-50 | MEDIUM |
| 21-50 | 51-100 | HIGH |
| 50+ | 100+ | CRITICAL |

---

## Complexity Correlation

Cross-reference survived mutants with complexity data to distinguish
"simple enough to unit test" from "complex enough to fuzz."

### Per-Function Complexity

```python
def complexity_context(engine, node_id: str) -> dict:
    """Get complexity context for triage decision."""
    hotspots = engine.complexity_hotspots(threshold=1)
    for h in hotspots:
        if h["id"] == node_id:
            return {
                "cyclomatic_complexity": h["cyclomatic_complexity"],
                "is_hotspot": h["cyclomatic_complexity"] >= 10,
            }
    return {"cyclomatic_complexity": 0, "is_hotspot": False}
```

### Decision Matrix

| CC | Entrypoint Reachable | Blast Radius | Bucket |
|----|---------------------|--------------|--------|
| <5 | No | Any | Missing Tests |
| <5 | Yes | LOW | Missing Tests |
| <5 | Yes | HIGH+ | Missing Tests (priority) |
| 5-10 | No | LOW | Missing Tests |
| 5-10 | No | HIGH+ | Missing Tests (priority) |
| 5-10 | Yes | Any | Fuzzing Target |
| >10 | Any | Any | Fuzzing Target |

---

## Annotation-Driven Triage

Use trailmark annotations to record triage decisions and refine
classification over time.

### Recording Decisions

```python
from trailmark.models import AnnotationKind

# Mark a function as triaged
engine.annotate(
    node_id,
    AnnotationKind.ASSUMPTION,
    "genotoxic: false_positive (equivalent mutant in logging)",
    source="llm",
)

# Mark a fuzzing target with rationale
engine.annotate(
    node_id,
    AnnotationKind.ASSUMPTION,
    "genotoxic: fuzzing_target (CC=14, entrypoint-reachable via /api/parse)",
    source="llm",
)
```

### Querying Previous Triage

```python
# Check if a function was previously triaged
annotations = engine.annotations_of(node_id)
genotoxic_annotations = [
    a for a in annotations
    if a["description"].startswith("genotoxic:")
]
```

This enables incremental triage across multiple mutation testing runs.

---

## Batch Triage Workflow

For large codebases with many survived mutants, process in batch:

```python
import json

def batch_triage(engine, survived_mutants: list[dict]) -> dict:
    """Classify all survived mutants."""
    graph_json = json.loads(engine.to_json())
    nodes = graph_json["nodes"]

    results = {
        "false_positives": [],
        "missing_tests": [],
        "fuzzing_targets": [],
    }

    for mutant in survived_mutants:
        node = find_containing_node(
            nodes, mutant["file_path"], mutant["line"]
        )
        if not node:
            results["false_positives"].append({
                **mutant,
                "reason": "no containing function in graph",
            })
            continue

        node_id = node["id"]
        callers = engine.callers_of(node_id)
        cc = node.get("cyclomatic_complexity", 0) or 0

        # Dead code
        if not callers:
            results["false_positives"].append({
                **mutant,
                "reason": "no callers (dead code)",
                "node_id": node_id,
            })
            continue

        reachable = is_entrypoint_reachable(engine, node_id)

        # Fuzzing criteria
        if (cc > 10 and reachable) or (len(callers) > 10 and cc > 5):
            ep_paths = entrypoint_paths(engine, node_id)
            results["fuzzing_targets"].append({
                **mutant,
                "node_id": node_id,
                "cyclomatic_complexity": cc,
                "caller_count": len(callers),
                "entrypoint_paths": ep_paths,
                "blast_radius": blast_radius(engine, node_id),
            })
            continue

        # Default: missing tests
        results["missing_tests"].append({
            **mutant,
            "node_id": node_id,
            "cyclomatic_complexity": cc,
            "caller_count": len(callers),
            "entrypoint_reachable": reachable,
        })

    return results
```

### Performance Considerations

- **Path queries are expensive.** Cache `paths_between` results when
  checking multiple mutants against the same entrypoints.
- **Process by function, not by mutant.** Multiple mutants in the same
  function share the same graph context. Group mutants by containing
  function first, query graph once per function.
- **Use `complexity_hotspots` as a prefilter.** Functions with CC < 5
  are almost never fuzzing targets. Skip reachability analysis for them
  unless caller count is very high.

---

## Mapping Necessist Removals to Graph Nodes

Necessist findings reference **test code** locations, but triage requires
the **production function** that the removed statement exercises. Extract
the called function name from the removed statement and match it against
graph nodes.

```python
import re


def map_removal_to_production_node(
    nodes: dict,
    removed_statement: str,
    test_file_path: str,
) -> dict | None:
    """Map a necessist removal to the production function it exercises."""
    # Extract function/method name from the removed statement.
    # Handles: obj.method(args), function(args), obj.method!(args)
    match = re.search(
        r"(?:(\w+)\.)?(\w+!?)\s*\(", removed_statement
    )
    if not match:
        return None

    func_name = match.group(2)

    # Search graph nodes for matching function name
    candidates = [
        (nid, n) for nid, n in nodes.items()
        if n.get("name") == func_name
        and "test" not in n.get("location", {})
            .get("file_path", "").lower()
    ]

    if len(candidates) == 1:
        return candidates[0][1]

    # Disambiguate: prefer node in the production module
    # that mirrors the test file path
    prod_path = infer_production_path(test_file_path)
    for nid, n in candidates:
        if n.get("location", {}).get("file_path") == prod_path:
            return n

    # Fall back to first non-test candidate
    return candidates[0][1] if candidates else None


def infer_production_path(test_file_path: str) -> str:
    """Heuristic: map test file to likely production file.

    tests/test_parser.py  → src/parser.py
    test/parser_test.go   → parser.go
    tests/Parser.test.ts  → src/Parser.ts
    """
    path = test_file_path
    # Strip test directory prefixes
    path = re.sub(r"^tests?/", "src/", path)
    # Strip test_ prefix or _test / .test suffix
    path = re.sub(r"test_(\w+)", r"\1", path)
    path = re.sub(r"(\w+)_test\.", r"\1.", path)
    path = re.sub(r"(\w+)\.test\.", r"\1.", path)
    return path
```

**When mapping fails:** If no production node matches, classify the
removal as a false positive with reason "unmappable to production code."
This is conservative — the removal may still be meaningful, but without
graph context triage cannot assign a confident bucket.

---

## Merging Mutation and Necessist Results

When both mutation testing and necessist produce findings for the same
production function, this is a **corroborated** finding: the function
has both uncaught production mutations and unnecessary test statements.
Corroborated findings are highest confidence.

```python
def merge_results(
    mutation_results: dict,
    necessist_results: dict,
) -> dict:
    """Merge mutation and necessist triage results.

    Identifies corroborated findings where both tools flag
    the same production function.
    """
    merged = {
        "corroborated": [],
        "false_positives": (
            mutation_results["false_positives"]
            + necessist_results["false_positives"]
        ),
        "missing_tests": [],
        "fuzzing_targets": [],
    }

    # Index necessist findings by production node_id
    necessist_by_node = {}
    for item in (
        necessist_results["missing_tests"]
        + necessist_results["fuzzing_targets"]
    ):
        nid = item.get("node_id")
        if nid:
            necessist_by_node.setdefault(nid, []).append(item)

    # Check mutation findings for corroboration
    for bucket in ("missing_tests", "fuzzing_targets"):
        for item in mutation_results[bucket]:
            nid = item.get("node_id")
            if nid and nid in necessist_by_node:
                merged["corroborated"].append({
                    "node_id": nid,
                    "mutation": item,
                    "necessist": necessist_by_node.pop(nid),
                })
            else:
                merged[bucket].append(item)

    # Add remaining non-corroborated necessist findings
    for items in necessist_by_node.values():
        for item in items:
            bucket = (
                "fuzzing_targets"
                if item in necessist_results["fuzzing_targets"]
                else "missing_tests"
            )
            merged[bucket].append(item)

    return merged
```

Corroborated findings should appear in a dedicated report section
before the individual buckets, since they represent the highest-value
action items.
