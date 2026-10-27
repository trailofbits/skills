# trailmark

**Source code graph analysis for security auditing.** Parses code into queryable graphs of functions, classes, and calls, then uses that structure for native taint analyzer modeling, diagram generation, mutation testing triage, protocol verification, and differential review.

The original graph skills support Trailmark 0.2.x through the 0.5.0 release line. Prefer
`--language auto`, `trailmark.parse.detect_languages()` (0.3+), and
`QueryEngine.preanalysis()` for the core workflow. Before using features added
in v0.4.0 or v0.5.0, check the installed Trailmark version or probe for the
method/CLI command first.

`taint-trace` uses `trailmark>=0.7.1,<0.8` from the package index and checks the
required graph APIs directly. Its launcher needs `uv`; native taint analyzers are
separate dependencies. See the [backend catalog](skills/taint-trace/references/catalog.md)
for language routes and capability requirements.

## Compatibility

Use this guard before relying on version-gated features:

```bash
trailmark --version 2>/dev/null || uv run trailmark --version 2>/dev/null
```

Compare the reported version numerically. If it is `0.4.0` or newer, the
expanded v0.4 feature set is available; `0.5.0` or newer adds the v0.5 set.
If the command is missing or reports an older version, stay on the v0.2-safe
baseline — the `trailmark` skill's Version Gate section has the authoritative
list. (The version CLI itself was added in 0.2.2, so a missing command can
also mean trailmark is not installed at all.)

v0.4.0 adds expanded parser coverage, explicit proxy nodes for unresolved
calls, node origins (`source`, `proxy`, `binary`, `synthetic`), new edge kinds
(`resolves_to`, `type_uses`, `specializes`, `corresponds_to`), subgraph edge
and connection queries, generic/type-reference queries, the native
`trailmark diagram` CLI, and binary graph augmentation via `augment_binary()`.

v0.5.0 adds a PostgreSQL-oriented `sql` parser (with node kinds `schema`,
`table`, `view`, `procedure`), the stable `.trailmark/links.toml`
configuration for declaring cross-language/FFI/RPC/external links
(external endpoints become `proxy.external:<symbol>` nodes), repository
links/proxies/`type_uses` edges for single-language parses, Solidity
entrypoints from parser metadata (visibility/mutability/overridden-by
attributes, interfaces excluded), node attributes in `attack_surface()`
entries, TypeScript constructed-receiver resolution, and C# file-scoped
namespace support. It adds no new `QueryEngine` methods or CLI commands, so
gate v0.5 features on the version number, not `hasattr()`.

## Prerequisites

[Trailmark](https://pypi.org/project/trailmark/) ([source](https://github.com/trailofbits/trailmark)) must be installed:

```bash
uv tool install trailmark
# Python snippets: uv run --with trailmark python -   (a tool env is not importable)
```

## Skills

| Skill | Description |
|-------|-------------|
| `trailmark` | Build and query multi-language source/binary code graphs with pre-analysis passes, version feature gates, proxy nodes, type/reference queries, cross-language link configuration, and structural traversal helpers |
| `slicing-code-context` | Build bounded graph-informed source packets and delegate focused work to constrained subagents |
| `diagramming-code` | Generate Mermaid diagrams from code graphs (call graphs, class hierarchies, complexity heatmaps, data flow); v0.4 native diagram support is feature-gated |
| `crypto-protocol-diagram` | Extract protocol message flow from source code or specs (RFC, ProVerif, Tamarin) into sequence diagrams |
| `genotoxic` | Triage mutation testing results using graph analysis — classify survived mutants as false positives, missing tests, or fuzzing targets |
| `vector-forge` | Mutation-driven test vector generation — find coverage gaps via mutation testing, then generate Wycheproof-style vectors that close them |
| `graph-evolution` | Compare code graphs at two snapshots to surface security-relevant structural changes text diffs miss |
| `trailmark-review-gate` | Apply PASS/WARN/FAIL/UNKNOWN structural gate rules to branch, PR, fix, or release diffs |
| `mermaid-to-proverif` | Convert Mermaid sequence diagrams into ProVerif formal verification models |
| `audit-augmentation` | Project SARIF, weAudit, and v0.4 binary-analysis graph findings onto code graphs as annotations and subgraphs |
| `trailmark-finding-triage` | Triage one finding, SARIF result, weAudit annotation, suspicious function, or report excerpt with reachability, taint, privilege-boundary, and blast-radius evidence; `scripts/evidence_packet.py` builds the evidence for several file/line findings from one graph |
| `trailmark-variant-neighborhood` | Expand one seed issue into graph-derived variant candidates for variant-analysis, Semgrep, CodeQL, or manual review |
| `taint-trace` | Use graph and source evidence to add native source/sink/sanitizer/propagation models and annotations, then run an existing taint analyzer |
| `trailmark-summary` | Quick structural overview (auto-detected languages, entry points, dependencies) for vivisect/galvanize |
| `trailmark-structural` | Full structural analysis with all pre-analysis passes (blast radius, taint, privilege boundaries, complexity) |

## Taint Analysis Workflow

Invoke `/trailmark:taint-trace` for guidance or `/trailmark:taint-trace-run` for
staged inventory, capability fixtures, baseline, modeling, native analysis, and
reporting. Workflow arguments are a JSON object:

```json
{
  "target": ".",
  "languages": ["php"],
  "backends": {"php": "psalm"},
  "focus": ["execute_query"]
}
```

Languages default to `auto`; backend overrides and sink focus are optional.
The skill supplies its `skill_dir` when invoking the workflow; checkout users can
also supply that absolute skill directory explicitly. The workflow otherwise
resolves only known installed plugin caches.

Artifacts live under the target's `.trailmark/taint-trace/runs/`. Reports separate
analyzed, limited, skipped, and failed components and retain native findings,
traces, model provenance, and unresolved graph gaps. Trailmark provides structural
evidence; the native analyzer computes taint flows. Single-function analysis is
explicitly limited, and a fully skipped run cannot report success. The skill does
not execute the target application.

Ordinary checks use deterministic fixtures. Enable native backend tests explicitly:
`TAINT_TRACE_PSALM`, `TAINT_TRACE_JOERN`, `TAINT_TRACE_SEMGREP`, and
`TAINT_TRACE_OPENGREP` select executable paths; `1` selects the executable on PATH
for Semgrep or OpenGrep. Run standalone capability contracts with the commands in
[artifact handling](skills/taint-trace/references/artifacts.md). The built-in Joern
probe covers 12 graphable languages and checks native cross-function traces and
context-specific escaping.

## Directory Structure

```text
trailmark/
├── .claude-plugin/
│   └── plugin.json
├── agents/
│   └── code-slice-worker.md          # Bounded worker, no repository tools.
│                                     # Dispatch as `trailmark:code-slice-worker`
├── README.md
├── workflows/
│   └── taint-trace-run.js            # /trailmark:taint-trace-run
├── tests/
│   └── taint-trace-run.test.mjs       # Staged lifecycle contracts
└── skills/
    ├── trailmark/                    # Core graph querying
    ├── slicing-code-context/         # Bounded source slicing and worker delegation
    ├── diagramming-code/             # Mermaid diagram generation
    │   └── scripts/diagram.py
    ├── crypto-protocol-diagram/      # Protocol flow extraction
    │   └── examples/
    ├── genotoxic/                    # Mutation testing triage
    ├── vector-forge/                 # Mutation-driven test vector generation
    │   └── references/
    ├── graph-evolution/              # Structural diff
    │   └── scripts/graph_diff.py
    ├── trailmark-review-gate/         # Structural review gates
    ├── mermaid-to-proverif/          # Sequence diagram → ProVerif
    │   └── examples/
    ├── audit-augmentation/           # SARIF/weAudit integration
    ├── trailmark-finding-triage/      # Single-finding evidence packets
    ├── trailmark-variant-neighborhood/ # Variant candidate neighborhoods
    ├── taint-trace/                  # Graph-backed native taint models and runner
    │   ├── references/              # Load only the selected backend
    │   └── scripts/                 # Context, capability, native evidence, validation
    ├── trailmark-summary/            # Quick overview for vivisect/galvanize
    └── trailmark-structural/         # Full structural analysis
```

## Related Skills

| Skill | Use For |
|-------|---------|
| `mutation-testing` | Guidance for running mutation frameworks (mewt, muton) — use before genotoxic for triage |
| `differential-review` | Text-level security diff review — complements graph-evolution's structural analysis |
| `audit-context-building` | Deep architectural context before vulnerability hunting |
| `variant-analysis` | Search for related candidates after trailmark-finding-triage identifies a repeatable root cause |
