# Query Recipes

Use these recipes after building a graph and running `engine.preanalysis()`.
Feature-gate optional Trailmark 0.4 APIs with `hasattr()`.

## Build And Preanalyze

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("{targetDir}", language="auto")
engine.preanalysis()
```

If auto-detection is wrong, rerun with an explicit language or comma-separated
language list.

## Bind A File/Line Candidate

Prefer Trailmark or `audit-augmentation` matching helpers when available. If
working from exported JSON, match nodes whose location file equals the
candidate file and whose line span overlaps the candidate line range. Pick the
smallest span as primary.

## Reachability

```python
node_id = "{bound_node}"

if hasattr(engine, "entrypoint_paths_to"):
    entry_paths = engine.entrypoint_paths_to(node_id)
else:
    entry_paths = []
    for entry in engine.attack_surface():
        for path in engine.paths_between(entry["name"], node_id):
            entry_paths.append(path)
```

Classify paths as:

- `untrusted_external`
- `semi_trusted_external`
- `trusted_internal`
- `unknown`

If no path exists, distinguish likely dead/internal code from parser,
language, proxy, dynamic dispatch, or missing-entrypoint modeling gaps.

## Taint And Privilege Boundaries

```python
tainted = node_id in set(engine.subgraph("tainted"))
boundary = node_id in set(engine.subgraph("privilege_boundary"))
entry_reachable = node_id in set(engine.subgraph("entrypoint_reachable"))
```

When `connect_subgraphs()` exists, use it to find paths from tainted nodes to
privilege-boundary nodes and check whether the candidate sits on or near those
paths.

## Blast Radius And Neighborhood

```python
callers = engine.callers_of(node_id)
callees = engine.callees_of(node_id)
high_blast = node_id in set(engine.subgraph("high_blast_radius"))

if hasattr(engine, "reachable_from"):
    downstream = engine.reachable_from(node_id)
else:
    downstream = []
```

Flag downstream sinks involving:

- value transfer
- authorization or role decisions
- persistence or state writes
- parsing or deserialization
- cryptographic keys, sessions, or signatures
- external process, network, or file operations

## Evidence Limits

Always record:

- Trailmark version or feature probes
- unsupported languages or parser errors
- unresolved/proxy/dynamic call uncertainty
- unmatched or ambiguous graph binding
- missing entrypoint modeling
- places where manual security judgment is still required
