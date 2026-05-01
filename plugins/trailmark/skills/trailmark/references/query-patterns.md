# Trailmark Query Patterns for Security Analysis

Common patterns for using Trailmark in security reviews.

## 1. Mapping Attack Surface

Find all entrypoints and trace what they can reach:

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("{targetDir}", language="auto")

# All entrypoints
for ep in engine.attack_surface():
    print(f"{ep['node_id']}: {ep['trust_level']} ({ep['kind']})")
```

## 2. Complexity Hotspots

High-complexity functions are more likely to contain bugs:

```python
for hotspot in engine.complexity_hotspots(threshold=10):
    loc = hotspot["location"]
    print(
        f"{hotspot['id']}  "
        f"complexity={hotspot['cyclomatic_complexity']}  "
        f"{loc['file_path']}:{loc['start_line']}"
    )
```

## 3. Call Path Analysis

Find how user input reaches a sensitive function:

```python
paths = engine.paths_between("handle_request", "execute_query")
for path in paths:
    print(" -> ".join(path))
```

## 4. Caller Analysis

Find all callers of a security-sensitive function to check if they
all validate input properly:

```python
callers = engine.callers_of("execute_query")
for caller in callers:
    print(f"{caller['id']} at {caller['location']['file_path']}:{caller['location']['start_line']}")
```

## 5. Reachability from Entrypoints

Check if a function is reachable from any entrypoint:

```python
paths = engine.entrypoint_paths_to("sensitive_function_id")
if paths:
    print(f"Reachable via {len(paths)} path(s)")
else:
    print("Not reachable from any entrypoint")
```

## 6. Full Graph Export

Export for use with other tools:

```python
import json

json_str = engine.to_json()
with open("graph.json", "w") as f:
    f.write(json_str)

# Current export includes: summary, nodes, edges, subgraphs.
# Query attack_surface() and annotations_of() directly for entrypoint
# metadata and per-node annotations.
```

## 7. Multi-Language Analysis

Ask Trailmark which languages it supports, detect what exists under the
target tree, then choose `auto` or an explicit list:

```python
from trailmark.parse import detect_languages, supported_languages
from trailmark.query.api import QueryEngine

print(supported_languages())
print(detect_languages("{targetDir}"))

engine = QueryEngine.from_directory("{targetDir}", language="auto")
engine = QueryEngine.from_directory("{targetDir}", language="python,rust")
```

## 8. CLI Patterns

```bash
# Quick summary with auto-detection
uv run trailmark analyze --language auto --summary {targetDir}

# Analyze explicit languages
uv run trailmark analyze --language rust --summary {targetDir}
uv run trailmark analyze --language python,rust --complexity 8 {targetDir}

# Entrypoint inventory
uv run trailmark entrypoints --language auto {targetDir}

# Full JSON output for piping to other tools
uv run trailmark analyze {targetDir} | jq '.nodes | to_entries[] | select(.value.cyclomatic_complexity > 10)'
```

## 9. Annotation Workflow

Add semantic annotations after analyzing code with an LLM. Annotations
persist on the in-memory graph and can be queried later:

```python
from trailmark.models import AnnotationKind

# Add annotations (returns False if node not found)
engine.annotate("handle_request", AnnotationKind.ASSUMPTION, "input is URL-encoded", source="llm")
engine.annotate("validate_token", AnnotationKind.PRECONDITION, "token is non-empty string", source="llm")

# Query annotations on a specific function
for ann in engine.annotations_of("handle_request"):
    print(f"[{ann['kind']}] {ann['description']} (source: {ann['source']})")

# Filter by kind
assumptions = engine.annotations_of("handle_request", kind=AnnotationKind.ASSUMPTION)

# Clear annotations (all, or by kind)
engine.clear_annotations("handle_request", kind=AnnotationKind.ASSUMPTION)
engine.clear_annotations("handle_request")
```

**Annotation kinds:** `ASSUMPTION`, `PRECONDITION`, `POSTCONDITION`, `INVARIANT`.
Pre-analysis adds: `BLAST_RADIUS`, `PRIVILEGE_BOUNDARY`, `TAINT_PROPAGATION`.
Audit augmentation adds: `FINDING`, `AUDIT_NOTE` (set by `augment_sarif()` /
`augment_weaudit()`).

**Source convention:** Use `"llm"` for LLM-inferred annotations, `"docstring"`
for annotations extracted from source, `"manual"` for human-added annotations.
