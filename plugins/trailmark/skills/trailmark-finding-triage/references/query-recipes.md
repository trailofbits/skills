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

entry_paths = engine.entrypoint_paths_to(node_id)
direct_entrypoint = next(
    (ep for ep in engine.attack_surface() if ep["node_id"] == node_id), None
)
```

Classify paths as:

- `untrusted_external`
- `semi_trusted_external`
- `trusted_internal`
- `unknown`

An empty self-path does not make a direct entrypoint unreachable. If no
nontrivial path exists, report direct membership and distinguish internal code
from parser, language, proxy, dynamic-dispatch, or missing-entrypoint gaps. On
0.7, max depth counts edges (default 20); retain that bound in the evidence.

## Taint And Privilege Boundaries

```python
# Trailmark 0.5+ returns node dicts from subgraph(), so compare ids; `set(engine.subgraph(...))`
# raises TypeError (unhashable dict). The helper also accepts plain id lists.
def ids(name):
    return {n["id"] if isinstance(n, dict) else n for n in engine.subgraph(name)}

tainted = node_id in ids("tainted")
boundary = node_id in ids("privilege_boundary")
entry_reachable = node_id in ids("entrypoint_reachable")
```

When `connect_subgraphs()` exists, use it to find paths from tainted nodes to
privilege-boundary nodes and check whether the candidate sits on or near those
paths.

## Blast Radius And Neighborhood

```python
callers = engine.callers_of(node_id)
callees = engine.callees_of(node_id)
high_blast = node_id in ids("high_blast_radius")

downstream = engine.reachable_from(node_id)
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

## Trailmark 0.7 State And Resolution Evidence

For a Solidity storage declaration, bind its `state_variable` node rather than
the enclosing contract, then query `readers_of(node_id)` and `writers_of(node_id)`
when available. Analyze each accessor's direct entrypoint membership and call
paths. For callable seeds, `state_read_by()` and `state_written_by()` expose
the other direction. Storage is limited to direct access in the declaring
contract, and calls-only traversal does not follow these edges.

Record `summary()["source_file_counts"]`, `parse_diagnostics()`,
`call_resolution()`, and `unresolved_calls()` on 0.7. Preserve exporter version
and schema version when consuming JSON. Unknown syntax, absent resolution, or
an uncertain deferred callback edge requires a qualified conclusion rather than
a reachability or exploitability claim.
