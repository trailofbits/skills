# trailmark

**Source code graph analysis for security auditing.** Parses code into queryable graphs of functions, classes, and calls, then uses that structure for diagram generation, mutation testing triage, protocol verification, and differential review.

These skills target Trailmark 0.2.x. Prefer `--language auto`,
`trailmark.parse.detect_languages()`, and `QueryEngine.preanalysis()`
instead of older 0.1.x-era manual language detection workflows.

## Prerequisites

[Trailmark](https://pypi.org/project/trailmark/) ([source](https://github.com/trailofbits/trailmark)) must be installed:

```bash
uv pip install trailmark
```

## Skills

| Skill | Description |
|-------|-------------|
| `trailmark` | Build and query multi-language code graphs with pre-analysis passes (blast radius, taint, privilege boundaries, entrypoints) |
| `diagramming-code` | Generate Mermaid diagrams from code graphs (call graphs, class hierarchies, complexity heatmaps, data flow) |
| `crypto-protocol-diagram` | Extract protocol message flow from source code or specs (RFC, ProVerif, Tamarin) into sequence diagrams |
| `genotoxic` | Triage mutation testing results using graph analysis — classify survived mutants as false positives, missing tests, or fuzzing targets |
| `vector-forge` | Mutation-driven test vector generation — find coverage gaps via mutation testing, then generate Wycheproof-style vectors that close them |
| `graph-evolution` | Compare code graphs at two snapshots to surface security-relevant structural changes text diffs miss |
| `mermaid-to-proverif` | Convert Mermaid sequence diagrams into ProVerif formal verification models |
| `audit-augmentation` | Project SARIF and weAudit findings onto code graphs as annotations and subgraphs |
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
