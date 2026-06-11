# Neighborhood Patterns

Use multiple bounded graph dimensions. Each dimension creates candidate review
targets, not findings.

| Dimension | Query idea | Variant hypothesis |
|---|---|---|
| Same caller | Other callees of the seed's caller | Caller applies the same bad precondition before several sinks |
| Same callee/sink | Other callers of the vulnerable sink | Missing validation before the same sink elsewhere |
| Same entrypoint path | Nodes on related paths from the same entrypoint | Adjacent unchecked operation in the same user flow |
| Same interface/override | Implementations of the same interface, trait, override, hook, or adapter family | One implementation fixed, sibling remains vulnerable |
| Same file/module cluster | Neighboring functions with similar dependencies | Copy/paste or parallel business logic |
| Same taint/boundary class | Nodes with the same taint and boundary status | Same trust transition, different operation |
| Same type/reference use | Functions touching the same critical type or state object | Missing invariant around the same asset |

## Query Sketches

```python
seed = "{bound_node}"
callers = engine.callers_of(seed)
callees = engine.callees_of(seed)

same_caller_candidates = []
for caller in callers:
    same_caller_candidates.extend(engine.callees_of(caller))

same_sink_candidates = []
for callee in callees:
    if is_sensitive_sink(callee):
        same_sink_candidates.extend(engine.callers_of(callee))

if hasattr(engine, "entrypoint_paths_to"):
    paths = engine.entrypoint_paths_to(seed)

if hasattr(engine, "type_references"):
    type_neighbors = engine.type_references(seed)
```

## Expansion Bounds

Use the smallest useful candidate set:

- cap each dimension at the top 10 candidates unless the user asks for more
- prefer graph distance 1 or 2 before wider expansion
- exclude generated, vendor, test, and mock paths by default
- stop and ask for a narrower root cause when more than 50 candidates survive
  first-pass ranking

## Evidence To Preserve

For each candidate, preserve:

- node ID and source location
- neighborhood dimension
- distance from seed when available
- reachability and trust level
- taint and privilege-boundary status
- shared sink, caller, interface, or type reason
- exclusion or penalty reason
