# Pre-Analysis Passes

Four passes that enrich the code graph before downstream skills (genotoxic,
diagram) consume it. Run via `engine.preanalysis()`.

## Contents

- Blast radius estimation
- Entry point enumeration
- Privilege boundary detection
- Taint propagation
- Subgraph reference
- Annotation reference

---

## 1. Blast Radius Estimation

Counts how many nodes are reachable downstream (descendants) and upstream
(ancestors) from each function. High blast radius means a bug in that
function affects many others.

**Annotation:** `AnnotationKind.BLAST_RADIUS` on every node.

```
"12 downstream, 3 upstream; critical: db_query, auth_check"
```

**Subgraph:** `high_blast_radius` — nodes with >= 10 downstream descendants.

```python
engine.preanalysis()

# All high-blast-radius nodes
high = engine.subgraph("high_blast_radius")
for node in high:
    print(f"{node['id']}: CC={node['cyclomatic_complexity']}")

# Per-node annotation
for ann in engine.annotations_of("handler",
                                  kind=AnnotationKind.BLAST_RADIUS):
    print(ann["description"])
```

---

## 2. Entry Point Enumeration

Collects all entrypoints, groups them by trust level, and computes the
full set of reachable nodes from any entrypoint.

**Subgraphs:**

| Name | Contents |
|------|----------|
| `entrypoints` | All entrypoint nodes |
| `entrypoint_reachable` | Every node reachable from any entrypoint |
| `entrypoints:untrusted_external` | Entrypoints at untrusted level |
| `entrypoints:semi_trusted_external` | Entrypoints at semi-trusted level |
| `entrypoints:trusted_internal` | Entrypoints at trusted level |

```python
engine.preanalysis()

# Nodes NOT reachable from any entrypoint (potential dead code)
all_ids = {n["id"] for n in engine.subgraph("entrypoint_reachable")}
# Compare with full node set from engine.summary()
```

---

## 3. Privilege Boundary Detection

Finds call edges where the source and target are reachable from entrypoints
at different trust levels. These boundaries are where untrusted data crosses
into trusted zones.

**Annotation:** `AnnotationKind.PRIVILEGE_BOUNDARY` on boundary nodes.

```
"trust transition across call: untrusted_external -> trusted_internal"
```

**Subgraph:** `privilege_boundary` — all nodes sitting on a trust boundary.

```python
engine.preanalysis()

boundary = engine.subgraph("privilege_boundary")
for node in boundary:
    anns = engine.annotations_of(
        node["id"], kind=AnnotationKind.PRIVILEGE_BOUNDARY)
    for a in anns:
        print(f"{node['id']}: {a['description']}")
```

---

## 4. Taint Propagation

Propagates taint from every untrusted and semi-trusted entrypoint through
call edges. Trusted entrypoints do not generate taint. Each tainted node
is annotated with the entrypoint(s) that reach it.

**Annotation:** `AnnotationKind.TAINT_PROPAGATION` on tainted nodes.

```
"tainted via: handle_request, parse_input"
```

**Subgraph:** `tainted` — all nodes reachable from any non-trusted entrypoint.

```python
engine.preanalysis()

tainted = engine.subgraph("tainted")
for node in tainted:
    anns = engine.annotations_of(
        node["id"], kind=AnnotationKind.TAINT_PROPAGATION)
    print(f"{node['id']}: {anns[0]['description']}")
```

---

## Subgraph Reference

All subgraphs created by `engine.preanalysis()`:

| Subgraph | Pass | Description |
|----------|------|-------------|
| `high_blast_radius` | Blast radius | Nodes with >= 10 downstream descendants |
| `entrypoints` | Entry point enum | All entrypoint nodes |
| `entrypoint_reachable` | Entry point enum | Union of all entrypoint-reachable nodes |
| `entrypoints:{trust_level}` | Entry point enum | Entrypoints grouped by trust level |
| `privilege_boundary` | Privilege boundary | Nodes on trust-level transitions |
| `tainted` | Taint propagation | All nodes reachable from non-trusted entrypoints |

Query any subgraph:

```python
nodes = engine.subgraph("tainted")
names = engine.subgraph_names()
```

---

## Annotation Reference

Annotations added by pre-analysis (source = `"preanalysis"`):

| Kind | Pass | Description format |
|------|------|--------------------|
| `blast_radius` | Blast radius | `"N downstream, M upstream; critical: ..."` |
| `privilege_boundary` | Privilege boundary | `"trust transition across call: X -> Y"` |
| `taint_propagation` | Taint propagation | `"tainted via: ep1, ep2"` |

Query annotations:

```python
from trailmark.models import AnnotationKind

engine.annotations_of("func", kind=AnnotationKind.BLAST_RADIUS)
engine.annotations_of("func", kind=AnnotationKind.PRIVILEGE_BOUNDARY)
engine.annotations_of("func", kind=AnnotationKind.TAINT_PROPAGATION)
```
