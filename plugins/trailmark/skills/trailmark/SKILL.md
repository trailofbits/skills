---
name: trailmark
description: "Builds and queries multi-language source code graphs for security analysis. Includes pre-analysis passes for blast radius, taint propagation, privilege boundaries, and entry point enumeration. Use when analyzing call paths, mapping attack surface, finding complexity hotspots, enumerating entry points, tracing taint propagation, measuring blast radius, or building a code graph for audit prioritization. Supports 16 languages including Solidity, Cairo, Circom, Rust, Go, Python, C/C++, TypeScript."
---

# Trailmark

Parses source code into a directed graph of functions, classes, calls, and
semantic metadata for security analysis. Supports 16 languages.

## When to Use

- Mapping call paths from user input to sensitive functions
- Finding complexity hotspots for audit prioritization
- Identifying attack surface and entrypoints
- Understanding call relationships in unfamiliar codebases
- Security review or audit preparation across polyglot projects
- Adding LLM-inferred annotations (assumptions, preconditions) to code units
- Pre-analysis before mutation testing (genotoxic skill) or diagramming

## When NOT to Use

- Single-file scripts where call graph adds no value (read the file directly)
- Architecture diagrams not derived from code (use the diagram skill or draw by hand)
- Mutation testing triage (use the genotoxic skill, which calls trailmark internally)
- Runtime behavior analysis (trailmark is static, not dynamic)

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

## Quick Start

```bash
# Python (default)
uv run trailmark analyze --summary {targetDir}

# Other languages
uv run trailmark analyze --language rust {targetDir}
uv run trailmark analyze --language javascript {targetDir}
uv run trailmark analyze --language go --summary {targetDir}

# Complexity hotspots
uv run trailmark analyze --complexity 10 {targetDir}
```

### Programmatic API

```python
from trailmark.query.api import QueryEngine

# Specify language (defaults to "python")
engine = QueryEngine.from_directory("{targetDir}", language="rust")

engine.callers_of("function_name")
engine.callees_of("function_name")
engine.paths_between("entry_func", "db_query")
engine.complexity_hotspots(threshold=10)
engine.attack_surface()
engine.summary()
engine.to_json()

# Run pre-analysis (blast radius, entrypoints, privilege
# boundaries, taint propagation)
result = engine.preanalysis()

# Query subgraphs created by pre-analysis
engine.subgraph_names()
engine.subgraph("tainted")
engine.subgraph("high_blast_radius")
engine.subgraph("privilege_boundary")
engine.subgraph("entrypoint_reachable")

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
```

## Pre-Analysis Passes

**Always run `engine.preanalysis()` before handing off to genotoxic or
diagram skills.** Pre-analysis enriches the graph with four passes:

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

## Supported Languages

| Language | `--language` value | Extensions |
| --- | --- | --- |
| Python | `python` | `.py` |
| JavaScript | `javascript` | `.js`, `.jsx` |
| TypeScript | `typescript` | `.ts`, `.tsx` |
| PHP | `php` | `.php` |
| Ruby | `ruby` | `.rb` |
| C | `c` | `.c`, `.h` |
| C++ | `cpp` | `.cpp`, `.hpp`, `.cc`, `.hh`, `.cxx`, `.hxx` |
| C# | `c_sharp` | `.cs` |
| Java | `java` | `.java` |
| Go | `go` | `.go` |
| Rust | `rust` | `.rs` |
| Solidity | `solidity` | `.sol` |
| Cairo | `cairo` | `.cairo` |
| Haskell | `haskell` | `.hs` |
| Circom | `circom` | `.circom` |
| Erlang | `erlang` | `.erl` |

## Graph Model

**Node kinds:** `function`, `method`, `class`, `module`, `struct`,
`interface`, `trait`, `enum`, `namespace`, `contract`, `library`

**Edge kinds:** `calls`, `inherits`, `implements`, `contains`, `imports`

**Edge confidence:** `certain` (direct call, `self.method()`), `inferred`
(attribute access on non-self object), `uncertain` (dynamic dispatch)

### Per Code Unit
- Parameters with types, return types, exception types
- Cyclomatic complexity and branch metadata
- Docstrings
- Annotations: `assumption`, `precondition`, `postcondition`, `invariant`,
  `blast_radius`, `privilege_boundary`, `taint_propagation`

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

**Subgraphs:** Named collections of node IDs produced by pre-analysis.
Query with `engine.subgraph("name")`. Available after `engine.preanalysis()`.

## Query Patterns

See [references/query-patterns.md](references/query-patterns.md) for common
security analysis patterns.

See [references/preanalysis-passes.md](references/preanalysis-passes.md) for
pre-analysis pass documentation.
