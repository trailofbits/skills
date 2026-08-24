# Trailmark Query Patterns for Security Analysis

Common patterns for using Trailmark in security reviews.

## Version-Gated Queries

Use v0.2-safe APIs unless the installed build is Trailmark 0.4.0 or newer, or
the method exists when probed with `hasattr()`.

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("{targetDir}", language="auto")

if hasattr(engine, "subgraph_edges"):
    edges = engine.subgraph_edges("tainted")  # v0.4+
else:
    # v0.2 fallback: filter exported edges by subgraph membership
    import json
    graph = json.loads(engine.to_json())
    member_ids = {node["id"] for node in engine.subgraph("tainted")}
    edges = [
        e for e in graph.get("edges", [])
        if e["source"] in member_ids and e["target"] in member_ids
    ]
```

## 1. Mapping Attack Surface

Find all entrypoints and trace what they can reach:

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("{targetDir}", language="auto")

# All entrypoints
for ep in engine.attack_surface():
    print(f"{ep['node_id']}: {ep['trust_level']} ({ep['kind']})")
    # Trailmark 0.5.0+ includes node attributes when present, e.g. Solidity
    # visibility/mutability and overridden-by metadata
    for key, value in ep.get("attributes", {}).items():
        print(f"  {key} = {value}")
```

On 0.5.0+, Solidity entrypoints come from parser metadata: interface members
are excluded, and a base implementation shadowed by a derived contract carries
`solidity_overridden_by` naming the overriding method(s). Check that attribute
before attributing reachability to the base implementation.

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

## 6. Transitive Slices

Upward and downward transitive slices (v0.2-safe):

```python
callers_to_sink = engine.ancestors_of("execute_query")
downstream = engine.reachable_from("handle_request")
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
`origin` on non-source nodes. Trailmark 0.5.0+ also exports
`proxy.external:<symbol>` nodes for endpoints declared external in
`.trailmark/links.toml`, and materializes proxies and `type_uses` edges for
single-language parses (0.4 emitted them only for polyglot parses). Do not
treat `origin=proxy` or `origin=binary` nodes as source locations during
manual review.

## 10. Multi-Language Analysis

Ask Trailmark which languages it supports, detect what exists under the
target tree, then choose `auto` or an explicit list:

```python
# trailmark.parse is a 0.3+ module; on 0.2.x import detect_languages from
# trailmark.query.api instead (supported_languages has no 0.2.x equivalent)
from trailmark.parse import detect_languages, supported_languages
from trailmark.query.api import QueryEngine

print(supported_languages())
print(detect_languages("{targetDir}"))

engine = QueryEngine.from_directory("{targetDir}", language="auto")
engine = QueryEngine.from_directory("{targetDir}", language="python,rust")
```

As of Trailmark 0.5.0, supported parser names include `python`, `javascript`,
`typescript`, `php`, `ruby`, `c`, `cpp`, `c_sharp`, `java`, `go`, `rust`,
`solidity`, `cairo`, `circom`, `haskell`, `erlang`, `masm`, `swift`, `objc`,
`kotlin`, `dart`, `move`, `tact`, `func`, `sway`, `rego`, `proto`, `thrift`,
`graphql`, and `sql` (0.5.0+). Treat this list as documentation, not a source
of truth; on 0.3+ builds call `supported_languages()` before relying on it.

## 10a. Cross-Boundary Links (v0.5+)

When the parser cannot see a call across an FFI/RPC/contract boundary,
declare it in `.trailmark/links.toml` at the analysis root (see the SKILL.md
Repository Links section for the format). The declared edges materialize on
every parse, so path and reachability queries cross the boundary directly:

```python
# .trailmark/links.toml declares backend:submit -> contract:Verifier.verify
paths = engine.paths_between("submit", "verify")
```

Configured edges carry a `configured_by` attribute naming the file. When a
declared endpoint is external (`target_external = true`), it appears as a
`proxy.external:<symbol>` node — treat it as a system boundary, not source.

## 11. CLI Patterns

```bash
# Version check before v0.4-only commands (version CLI itself is 0.2.2+)
uv run trailmark --version

# Quick summary with auto-detection
uv run trailmark analyze --language auto --summary {targetDir}

# Analyze explicit languages
uv run trailmark analyze --language rust --summary {targetDir}
uv run trailmark analyze --language python,rust --complexity 8 {targetDir}

# Entrypoint inventory
uv run trailmark entrypoints --language auto {targetDir}

# Structural diff between two refs or directories
uv run trailmark diff --language auto --repo {repoDir} main HEAD --json

# v0.4+: native diagram
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
engine.clear_annotations("handle_request", kind=AnnotationKind.ASSUMPTION)
engine.clear_annotations("handle_request")

# Nodes with a given annotation
finding_nodes = engine.nodes_with_annotation(AnnotationKind.FINDING)
```

**Annotation kinds:** `ASSUMPTION`, `PRECONDITION`, `POSTCONDITION`, `INVARIANT`.
Pre-analysis adds: `BLAST_RADIUS`, `PRIVILEGE_BOUNDARY`, `TAINT_PROPAGATION`.
Audit augmentation adds: `FINDING`, `AUDIT_NOTE` (set by `augment_sarif()` /
`augment_weaudit()`).

**Source convention:** Use `"llm"` for LLM-inferred annotations, `"docstring"`
for annotations extracted from source, `"manual"` for human-added annotations.
