# Trailmark Query Patterns for Security Analysis

Common patterns for using Trailmark in security reviews.

## Version-Gated Queries

Use v0.2-safe APIs unless the installed build is Trailmark 0.4.0 or newer, or
the method exists when probed with `hasattr()`.

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("{targetDir}", language="auto")

if hasattr(engine, "entrypoint_paths_to"):
    paths = engine.entrypoint_paths_to("sensitive_sink")  # v0.4+
else:
    paths = []
    for ep in engine.attack_surface():
        paths.extend(engine.paths_between(ep["node_id"], "sensitive_sink"))
```

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
if hasattr(engine, "entrypoint_paths_to"):
    paths = engine.entrypoint_paths_to("sensitive_function_id")
else:
    paths = []
    for ep in engine.attack_surface():
        paths.extend(engine.paths_between(ep["node_id"], "sensitive_function_id"))

if paths:
    print(f"Reachable via {len(paths)} path(s)")
else:
    print("Not reachable from any entrypoint")
```

For Trailmark 0.4.0+, prefer `entrypoint_paths_to()` because it searches all
detected entrypoints directly. On older versions, use `attack_surface()` plus
`paths_between()` as shown in the version-gated example above.

## 6. Transitive Slices

Trailmark 0.4.0+ exposes upward and downward transitive slices:

```python
if hasattr(engine, "ancestors_of"):
    callers_to_sink = engine.ancestors_of("execute_query")
    downstream = engine.reachable_from("handle_request")
else:
    callers_to_sink = engine.callers_of("execute_query")
    downstream = engine.callees_of("handle_request")
```

Use `ancestors_of()` for "who could eventually reach this sink?" and
`reachable_from()` for "what could this entrypoint or helper eventually call?"

## 7. Subgraph Connections

After `engine.preanalysis()`, Trailmark 0.4.0+ can connect named subgraphs and
return induced edges:

```python
engine.preanalysis()

if hasattr(engine, "connect_subgraphs"):
    paths = engine.connect_subgraphs("tainted", "privilege_boundary")
if hasattr(engine, "subgraph_edges"):
    tainted_edges = engine.subgraph_edges("tainted")
```

Use this when prioritizing tainted paths that cross trust boundaries.

## 8. Type and Generic Queries

Trailmark 0.4.0+ records type references and generic parameters where parsers
can extract them:

```python
if hasattr(engine, "type_references"):
    refs = engine.type_references("deserialize_request")
if hasattr(engine, "generic_parameters"):
    params = engine.generic_parameters("Container")
```

Use these to find parser, deserializer, FFI, or generic-bound hotspots where
declared types are narrower than the effective input domain.

## 9. Full Graph Export

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

Trailmark 0.4.0+ exports proxy nodes for unresolved calls and may include
`origin` on non-source nodes. Do not treat `origin=proxy` or `origin=binary`
nodes as source locations during manual review.

## 10. Multi-Language Analysis

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

As of Trailmark 0.4.0, supported parser names include `python`, `javascript`,
`typescript`, `php`, `ruby`, `c`, `cpp`, `c_sharp`, `java`, `go`, `rust`,
`solidity`, `cairo`, `circom`, `haskell`, `erlang`, `masm`, `swift`, `objc`,
`kotlin`, `dart`, `move`, `tact`, `func`, `sway`, `rego`, `proto`, `thrift`,
and `graphql`. Always call `supported_languages()` on the installed build
before relying on this list.

## 11. CLI Patterns

```bash
# Version check before v0.4-only commands
uv run trailmark --version

# Quick summary with auto-detection
uv run trailmark analyze --language auto --summary {targetDir}

# Analyze explicit languages
uv run trailmark analyze --language rust --summary {targetDir}
uv run trailmark analyze --language python,rust --complexity 8 {targetDir}

# Entrypoint inventory
uv run trailmark entrypoints --language auto {targetDir}

# v0.4+: native diff and native diagram
uv run trailmark diff --repo {repoDir} main HEAD --json
uv run trailmark diagram -t {targetDir} -T call-graph -f main --depth 2

# Full JSON output for piping to other tools
uv run trailmark analyze {targetDir} | jq '.nodes | to_entries[] | select(.value.cyclomatic_complexity > 10)'
```

## 12. Annotation Workflow

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
if hasattr(engine, "clear_annotations"):
    engine.clear_annotations("handle_request", kind=AnnotationKind.ASSUMPTION)
    engine.clear_annotations("handle_request")

# v0.4+: nodes with a given annotation
if hasattr(engine, "nodes_with_annotation"):
    finding_nodes = engine.nodes_with_annotation(AnnotationKind.FINDING)
```

**Annotation kinds:** `ASSUMPTION`, `PRECONDITION`, `POSTCONDITION`, `INVARIANT`.
Pre-analysis adds: `BLAST_RADIUS`, `PRIVILEGE_BOUNDARY`, `TAINT_PROPAGATION`.
Audit augmentation adds: `FINDING`, `AUDIT_NOTE` (set by `augment_sarif()` /
`augment_weaudit()`).

**Source convention:** Use `"llm"` for LLM-inferred annotations, `"docstring"`
for annotations extracted from source, `"manual"` for human-added annotations.
