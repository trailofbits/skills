# trailmark

**Source code graph analysis for security auditing.** Parses code into queryable graphs of functions, classes, and calls, then uses that structure for diagram generation, mutation testing triage, protocol verification, and differential review.

These skills support Trailmark 0.2.x through the 0.4.0 release line. Prefer
`--language auto`, `trailmark.parse.detect_languages()`, and
`QueryEngine.preanalysis()` for the v0.2-safe core workflow. Before using
features added for v0.4.0, check the installed Trailmark version or probe for
the method/CLI command first.

## Compatibility

Use this guard before relying on v0.4-only features:

```bash
trailmark --version 2>/dev/null || uv run trailmark --version 2>/dev/null
```

If the command reports `trailmark 0.4.0` or newer, the expanded v0.4 feature
set is available. If the command is missing or reports an older version, stay
on the v0.2-safe surface: `analyze`, `--language auto`, `detect_languages()`,
`QueryEngine.from_directory()`, `summary()`, `complexity_hotspots()`,
`attack_surface()`, `preanalysis()`, annotations, and SARIF/weAudit
augmentation.

v0.4.0 adds expanded parser coverage, explicit proxy nodes for unresolved calls,
node origins (`source`, `proxy`, `binary`, `synthetic`), new edge kinds
(`resolves_to`, `type_uses`, `specializes`, `corresponds_to`), transitive query
helpers, entrypoint path queries, subgraph edge queries, generic/type-reference
queries, CLI `version`/`entrypoints`/`diff`/`diagram`, and binary graph
augmentation via `augment_binary()`.

## Prerequisites

[Trailmark](https://pypi.org/project/trailmark/) ([source](https://github.com/trailofbits/trailmark)) must be installed:

```bash
uv pip install trailmark
```

## Skills

| Skill | Description |
|-------|-------------|
| `trailmark` | Build and query multi-language source/binary code graphs with pre-analysis passes, v0.4 feature gates, proxy nodes, type/reference queries, and structural traversal helpers |
| `diagramming-code` | Generate Mermaid diagrams from code graphs (call graphs, class hierarchies, complexity heatmaps, data flow); v0.4 native diagram support is feature-gated |
| `crypto-protocol-diagram` | Extract protocol message flow from source code or specs (RFC, ProVerif, Tamarin) into sequence diagrams |
| `genotoxic` | Triage mutation testing results using graph analysis — classify survived mutants as false positives, missing tests, or fuzzing targets |
| `vector-forge` | Mutation-driven test vector generation — find coverage gaps via mutation testing, then generate Wycheproof-style vectors that close them |
| `graph-evolution` | Compare code graphs at two snapshots to surface security-relevant structural changes text diffs miss |
| `mermaid-to-proverif` | Convert Mermaid sequence diagrams into ProVerif formal verification models |
| `audit-augmentation` | Project SARIF, weAudit, and v0.4 binary-analysis graph findings onto code graphs as annotations and subgraphs |
| `trailmark-summary` | Quick structural overview (auto-detected languages, entry points, dependencies) for vivisect/galvanize |
| `trailmark-structural` | Full structural analysis with all pre-analysis passes (blast radius, taint, privilege boundaries, complexity) |

## Directory Structure

```text
trailmark/
├── .claude-plugin/
│   └── plugin.json
├── README.md
└── skills/
    ├── trailmark/                    # Core graph querying
    ├── diagramming-code/             # Mermaid diagram generation
    │   └── scripts/diagram.py
    ├── crypto-protocol-diagram/      # Protocol flow extraction
    │   └── examples/
    ├── genotoxic/                    # Mutation testing triage
    ├── vector-forge/                 # Mutation-driven test vector generation
    │   └── references/
    ├── graph-evolution/              # Structural diff
    │   └── scripts/graph_diff.py
    ├── mermaid-to-proverif/          # Sequence diagram → ProVerif
    │   └── examples/
    ├── audit-augmentation/           # SARIF/weAudit integration
    ├── trailmark-summary/            # Quick overview for vivisect/galvanize
    └── trailmark-structural/         # Full structural analysis
```

## Related Skills

| Skill | Use For |
|-------|---------|
| `mutation-testing` | Guidance for running mutation frameworks (mewt, muton) — use before genotoxic for triage |
| `differential-review` | Text-level security diff review — complements graph-evolution's structural analysis |
| `audit-context-building` | Deep architectural context before vulnerability hunting |
