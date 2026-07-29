---
name: trailmark
description: "Builds and queries multi-language source and binary code graphs for security analysis. Includes pre-analysis passes for blast radius, taint propagation, privilege boundaries, entry point enumeration, proxy/unresolved-call tracking, type/reference queries, structural traversal, graph diffs, audit augmentation, declared cross-language/FFI/external links via `.trailmark/links.toml`, and SQL schema graphs. Use when analyzing call paths, mapping attack surface, finding complexity hotspots, enumerating entry points, tracing taint propagation, measuring blast radius, importing SARIF/weAudit/binary findings, linking source graphs across language or RPC boundaries, or building a code graph for audit prioritization. Feature-gate version-specific Trailmark APIs before using them; prefer `trailmark.parse.detect_languages()` or `--language auto` when the target language is unknown or polyglot."
---

# Trailmark

Parses source code into a directed graph of functions, classes, calls, and
semantic metadata for security analysis.

## When to Use

- Mapping call paths from user input to sensitive functions
- Finding complexity hotspots for audit prioritization
- Identifying attack surface and entrypoints
- Understanding call relationships in unfamiliar codebases
- Security review or audit preparation across polyglot projects
- Adding LLM-inferred annotations (assumptions, preconditions) to code units
- Importing external binary-analysis graphs to connect source and binary views
- Querying transitive slices, entrypoint paths, subgraph edges, or type references
- Producing graph evidence for one suspicious function or candidate finding
- Pre-analysis before mutation testing (genotoxic skill) or diagramming

## When NOT to Use

- Single-file scripts where call graph adds no value (read the file directly)
- Architecture diagrams not derived from code (use the `diagramming-code` skill or draw by hand)
- Mutation testing triage (use the genotoxic skill, which calls trailmark internally)
- Runtime behavior analysis (trailmark is static, not dynamic)

## Rationalizations to Reject

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "I'll just read the source files manually" | Manual reading misses call paths, blast radius, and taint data | Install trailmark and use the API |
| "Pre-analysis isn't needed for a quick query" | Blast radius, taint, and privilege data are only available after `preanalysis()` | Always run `engine.preanalysis()` before handing off to other skills |
| "The graph is too large, I'll sample" | Sampling misses cross-module attack paths | Build the full graph; use subgraph queries to focus |
| "Uncertain edges don't matter" | Dynamic dispatch is where type confusion bugs hide | Account for `uncertain` edges in security claims |
| "Single-language analysis is enough" | Polyglot repos have FFI boundaries where bugs cluster | Use the correct `--language` flag per component |
| "Complexity hotspots are the only thing worth checking" | Low-complexity functions on tainted paths are high-value targets | Combine complexity with taint and blast radius data |
| "The docs mention a version-gated method, so I can call it anywhere" | Many environments still have Trailmark 0.2.x installed | Check the installed version or probe feature availability before using v0.4+/v0.5+ features |

---

## Installation

**MANDATORY:** If `uv run trailmark` fails (command not found, import error,
ModuleNotFoundError), install trailmark before doing anything else:

```bash
uv pip install trailmark
```

**DO NOT** fall back to "manual verification", "manual analysis", or reading
source files by hand as a substitute for running trailmark. The tool must be
installed and used programmatically. If installation fails, report the error
to the user instead of silently switching to manual code reading.

## Version Gate

Trailmark 0.4.0 expands the graph model and query surface, and 0.5.0 adds a
SQL parser, repository-link configuration, and richer entrypoint metadata.
Before using a feature listed as **v0.4+** or **v0.5+**, check the installed
version:

```bash
trailmark --version 2>/dev/null || uv run trailmark --version 2>/dev/null
```

Compare the reported version numerically (not lexically). `0.4.0` or newer
means the full v0.4 surface is available. The version command itself was added
in 0.2.2, so a failure means either a pre-0.2.2 install or trailmark missing
entirely — distinguish with `trailmark analyze --help`. When working
programmatically, probe with `hasattr()` and fall back instead of assuming a
v0.4-only method exists:

```python
if hasattr(engine, "subgraph_edges"):
    edges = engine.subgraph_edges("tainted")
else:
    # v0.2 fallback: filter engine.to_json() edges whose endpoints
    # are both in engine.subgraph("tainted")
    edges = []
```

**v0.2-safe baseline:** CLI `analyze`, `diff`, `entrypoints`, `augment`, and
`--language auto`; `QueryEngine.from_directory()`, `callers_of()`,
`callees_of()`, `paths_between()`, `ancestors_of()`, `reachable_from()`,
`entrypoint_paths_to()`, `complexity_hotspots()`, `attack_surface()`,
`summary()`, `to_json()`, `preanalysis()`, `annotate()`, `annotations_of()`,
`nodes_with_annotation()`, `clear_annotations()`, `findings()`, `subgraph()`,
`subgraph_names()`, `diff_against()`, `augment_sarif()`, and
`augment_weaudit()`.

**Added in 0.2.2:** CLI `--version` flag and `version` subcommand.

**Added in 0.3.x:** the `trailmark.parse` module with module-level
`detect_languages()` and `supported_languages()`. `detect_languages()` itself
is v0.2-safe via `from trailmark.query.api import detect_languages` (kept as a
deprecated alias in 0.3+); `supported_languages()` has no 0.2.x equivalent.

**v0.4+ features:** native `diagram` subcommand; expanded parser coverage;
proxy nodes for unresolved calls; node origins; binary graph augmentation via
`augment_binary()`; `connect_subgraphs()`; `subgraph_edges()`;
`generic_parameters()`; and `type_references()`.

**v0.5+ features:** `sql` parser (PostgreSQL-oriented schemas, tables, views,
functions, procedures, dependencies); node kinds `schema`, `table`, `view`,
`procedure`; `.trailmark/links.toml` repository-link configuration (see
Repository Links below), including `proxy.external:<symbol>` nodes for
declared external endpoints; repository links, unresolved-call proxies, and
`type_uses` edges now materialize for single-language directory parses (0.4
emitted them only for polyglot parses); Solidity entrypoints detected from
parser metadata (interfaces excluded; `solidity_visibility`,
`solidity_mutability`, `solidity_override`, `solidity_container_kind`, and
`solidity_overridden_by` node attributes); `attack_surface()` entries carry an
`attributes` key when the node has attributes; TypeScript resolves receivers
assigned with `new ConcreteClass()`; C# file-scoped namespaces.

v0.5.0 adds no new `QueryEngine` methods, so `hasattr(engine, ...)` cannot
detect it. Gate v0.5 features on the reported version, or probe structurally:

```python
from trailmark.models.nodes import NodeKind

has_v05 = "SCHEMA" in NodeKind.__members__  # sql kinds are 0.5+
```

## Quick Start

```bash
# Auto-detect and merge every supported language under the tree
uv run trailmark analyze --language auto --summary {targetDir}

# Explicit languages (single language or comma-separated list)
uv run trailmark analyze --language rust {targetDir}
uv run trailmark analyze --language python,rust {targetDir}

# Complexity hotspots
uv run trailmark analyze --language auto --complexity 10 {targetDir}

# Entrypoint inventory and structural diff (v0.2-safe)
uv run trailmark entrypoints --language auto {targetDir}
uv run trailmark diff --repo {repoDir} main HEAD --json

# Version report (0.2.2+)
uv run trailmark --version

# v0.4+: native diagram command
uv run trailmark diagram -t {targetDir} -T call-graph -f main --depth 2
```

### Programmatic API

```python
# trailmark.parse is a 0.3+ module; on 0.2.x import detect_languages from
# trailmark.query.api instead (supported_languages has no 0.2.x equivalent)
from trailmark.parse import detect_languages, supported_languages
from trailmark.query.api import QueryEngine

# Ask the installed Trailmark build what it supports
supported_languages()
detect_languages("{targetDir}")

# Prefer auto for unknown or polyglot trees; use explicit lists when needed
engine = QueryEngine.from_directory("{targetDir}", language="auto")
engine = QueryEngine.from_directory("{targetDir}", language="python,rust")

engine.callers_of("function_name")
engine.callees_of("function_name")
engine.paths_between("entry_func", "db_query")
engine.complexity_hotspots(threshold=10)
engine.attack_surface()
engine.summary()
engine.to_json()

# Transitive slices and entrypoint path queries (v0.2-safe)
engine.ancestors_of("sensitive_sink")
engine.reachable_from("entry_func")
engine.entrypoint_paths_to("sensitive_sink")

# v0.4+: connect named subgraphs
if hasattr(engine, "connect_subgraphs"):
    engine.connect_subgraphs("tainted", "privilege_boundary")

# Run pre-analysis (blast radius, entrypoints, privilege
# boundaries, taint propagation)
result = engine.preanalysis()

# Query subgraphs created by pre-analysis
engine.subgraph_names()
engine.subgraph("tainted")
engine.subgraph("high_blast_radius")
engine.subgraph("privilege_boundary")
engine.subgraph("entrypoint_reachable")
if hasattr(engine, "subgraph_edges"):
    engine.subgraph_edges("tainted")

# Add LLM-inferred annotations
from trailmark.models import AnnotationKind

engine.annotate("function_name", AnnotationKind.ASSUMPTION,
                "input is URL-encoded", source="llm")

# Query annotations (including pre-analysis results)
engine.annotations_of("function_name")
engine.annotations_of("function_name",
                       kind=AnnotationKind.BLAST_RADIUS)
engine.annotations_of("function_name",
                       kind=AnnotationKind.TAINT_PROPAGATION)
engine.nodes_with_annotation(AnnotationKind.FINDING)
engine.clear_annotations("function_name", kind=AnnotationKind.ASSUMPTION)

# v0.4+: generic/type-reference and binary augmentation APIs
if hasattr(engine, "generic_parameters"):
    engine.generic_parameters("GenericTypeOrFunction")
if hasattr(engine, "type_references"):
    engine.type_references("function_name")
if hasattr(engine, "augment_binary"):
    engine.augment_binary("binary_graph.json")
```

## Pre-Analysis Passes

**Always run `engine.preanalysis()` before handing off to genotoxic or
`diagramming-code` skills.** Pre-analysis enriches the graph with four passes:

1. **Blast radius estimation** — counts downstream and upstream nodes per
   function, identifies critical high-complexity descendants
2. **Entry point enumeration** — maps entrypoints by trust level, computes
   reachable node sets
3. **Privilege boundary detection** — finds call edges where trust levels
   change (untrusted -> trusted)
4. **Taint propagation** — marks all nodes reachable from untrusted
   entrypoints

Results are stored as annotations and named subgraphs on the graph.

For detailed documentation, see
[references/preanalysis-passes.md](references/preanalysis-passes.md).

## Language Selection

Do not hardcode a stale language table in downstream workflows. Ask the
installed Trailmark build what it supports:

```python
from trailmark.parse import detect_languages, supported_languages

supported_languages()
detect_languages("{targetDir}")
```

CLI patterns:

```bash
# Auto-detect and merge
uv run trailmark analyze --language auto {targetDir}

# Explicit list for a known polyglot target
uv run trailmark analyze --language python,rust {targetDir}
```

As of Trailmark 0.5.0, parser names include: `python`, `javascript`,
`typescript`, `php`, `ruby`, `c`, `cpp`, `c_sharp`, `java`, `go`, `rust`,
`solidity`, `cairo`, `circom`, `haskell`, `erlang`, `masm`, `swift`, `objc`,
`kotlin`, `dart`, `move`, `tact`, `func`, `sway`, `rego`, `proto`, `thrift`,
`graphql`, and `sql` (added in 0.5.0; PostgreSQL-oriented, `.sql` files).
Treat this list as documentation, not a source of truth; call
`supported_languages()` on the installed build before relying on a parser.

## Repository Links (v0.5+)

Parsers cannot see cross-language calls (FFI, RPC, IPC, contract invocation)
or edges into external systems. Declare them in `.trailmark/links.toml` at the
analysis root and Trailmark materializes the edges on every parse — this is a
stable public configuration interface:

```toml
[[link]]
source = "backend:submit"
target = "contract:Verifier.verify"
kind = "calls"                 # any EdgeKind; defaults to calls
confidence = "certain"         # certain | inferred | uncertain; defaults to inferred
description = "JSON-RPC eth_call"

[[link]]
source = "backend:notify"
target = "payments-webhook"
target_external = true         # required because target is unresolved
```

Endpoint references may be exact node IDs or unique names/suffixes. Validation
fails closed: ambiguous references, unknown internal endpoints, invalid enum
values, and malformed TOML raise `ValueError` rather than silently weakening
the graph. `source_external = true` / `target_external = true` permit an
unresolved endpoint by creating a `proxy.external:<symbol>` node. Configured
edges carry a `configured_by = .trailmark/links.toml` attribute so they are
distinguishable from parser-derived edges.

Use this when the audit spans an FFI/RPC boundary the rationalization table
warns about: declare the boundary edges first, then path and taint queries
cross them like any other call edge.

## Graph Model

**Node kinds:** `function`, `method`, `class`, `module`, `struct`,
`interface`, `trait`, `enum`, `namespace`, `contract`, `library`,
`template`; **v0.4+** also materializes unresolved references as `proxy`
nodes; **v0.5+** adds `schema`, `table`, `view`, and `procedure` for SQL
graphs.

**Node origins:** **v0.4+** nodes may carry origin `source`, `proxy`,
`binary`, or `synthetic`. v0.2 exports may omit origin.

**Edge kinds:** `calls`, `inherits`, `implements`, `contains`, `imports`;
**v0.4+** adds `resolves_to`, `type_uses`, `specializes`, and
`corresponds_to`.

**Edge confidence:** `certain` (direct call, `self.method()`), `inferred`
(attribute access on non-self object), `uncertain` (dynamic dispatch)

### Per Code Unit
- Parameters with types, return types, exception types
- Cyclomatic complexity and branch metadata
- Docstrings
- Annotations: `assumption`, `precondition`, `postcondition`, `invariant`,
  `blast_radius`, `privilege_boundary`, `taint_propagation`, `finding`,
  `audit_note` (last two set by `augment_sarif` / `augment_weaudit`)

### Per Edge
- Source/target node IDs, edge kind, confidence level

### Project Level
- Dependencies (imported packages)
- Entrypoints with trust levels and asset values
- Named subgraphs (populated by pre-analysis)

## Key Concepts

**Declared contract vs. effective input domain:** Trailmark separates what a
function *declares* it accepts from what can *actually reach* it via call
paths. Mismatches are where vulnerabilities hide:
- **Widening**: Unconstrained data reaches a function that assumes validation
- **Safe by coincidence**: No validation, but only safe callers exist today

**Edge confidence:** Dynamic dispatch produces `uncertain` edges. Account for
confidence when making security claims.

**Proxy nodes (v0.4+):** Unresolved calls are preserved as nodes such as
`proxy.unresolved:<symbol>`. Do not treat these as source code functions; use
them to identify resolution gaps, dynamic dispatch, external APIs, or binary
linkage candidates. **v0.5+** also emits `proxy.external:<symbol>` nodes for
endpoints declared external in `.trailmark/links.toml`.

**Reachability is not taint:** `entrypoint_paths_to()` and the taint subgraph
answer different questions. Path queries report call-graph reachability;
preanalysis taint marks nodes reachable from untrusted entrypoints as a coarse
signal. Trailmark does not perform interprocedural taint analysis — do not
present either as proof that attacker-controlled data reaches a sink.

**Binary augmentation (v0.4+):** `engine.augment_binary()` imports an external
binary-analysis graph JSON file. Trailmark connects it to source nodes when
possible; it does not disassemble binaries itself.

**Subgraphs:** Named collections of node IDs produced by pre-analysis.
Query with `engine.subgraph("name")`. Available after `engine.preanalysis()`.

## Query Patterns

See [references/query-patterns.md](references/query-patterns.md) for common
security analysis patterns.

See [references/preanalysis-passes.md](references/preanalysis-passes.md) for
pre-analysis pass documentation.

Use `trailmark-finding-triage` when the user has one concrete candidate
finding, SARIF result, weAudit annotation, suspicious function, or report
excerpt and needs a handoff-ready reachability and blast-radius evidence packet.

Use `trailmark-variant-neighborhood` after one seed issue is known and the user
needs graph-derived variant candidates for `variant-analysis`, Semgrep, CodeQL,
or manual review.
