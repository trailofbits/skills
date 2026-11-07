# trailmark

**Source code graph analysis for security auditing.** Parses code into queryable graphs of functions, classes, and calls, then uses that structure for diagram generation, mutation testing triage, protocol verification, and differential review.

Workflow guidance covers Trailmark 0.2.x through 0.7.0, with version gates for
new APIs. Prefer `--language auto`, `trailmark.parse.detect_languages()` (0.3+),
and `QueryEngine.preanalysis()` for the core workflow. The plugin version and
the installed Trailmark version are separate; check the latter before using a
new parser, keyword argument, or output field.

## Compatibility

```bash
trailmark --version || uv run trailmark --version
```

Compare versions numerically. A missing version command can mean Trailmark is
absent or older than 0.2.2; check `trailmark analyze --help` before selecting a
fallback. Use method probes for additive APIs, and version checks for changed
keyword arguments and parser behavior.

| Trailmark | Available features |
|-----------|--------------------|
| 0.2.x–0.3.x | Core queries, preanalysis, findings, structural diffs; public `trailmark.parse` API in 0.3+ |
| 0.4+ | Native diagrams, proxies and node origins, type/reference queries, subgraph connections, binary graph imports |
| 0.5+ | SQL, `.trailmark/links.toml`, external proxies, richer Solidity entrypoint attributes |
| 0.6+ | Rust lexical/local-item resolution and body-bearing functions in brace-delimited `verus!` blocks |
| 0.7+ | Nine more language frontends, Solidity state access, call-resolution and parse diagnostics, source-file coverage, export provenance, richer native diffs, and appendable finding imports |

Trailmark 0.7.0 supports **39 languages**. Its nine new frontends are Aiken
(`aiken`), Bash (`bash`), Julia (`julia`), Lua (`lua`), Perl 5 (`perl`),
PowerShell (`powershell`), R (`r`), VB.NET (`vb`), and Zig (`zig`). Ask the
installed build's `supported_languages()` and `detect_languages()` what is
available. Parser support does not imply complete language semantics, entrypoint
detection, or a mutation framework for that language. See the released
[language notes](https://github.com/trailofbits/trailmark/blob/v0.7.0/docs/languages.md).

**Bundled packet helpers still use Trailmark 0.5.x.** `slicing-code-context`'s
`build_slice_packet.py` and `trailmark-finding-triage`'s `evidence_packet.py`
declare `trailmark>=0.5,<0.6`; slicing also enforces that version at runtime.
Installing a 0.7 CLI does not update their isolated script environments. Use the
version-gated manual API workflow for 0.7-only evidence; do not claim those
helpers contain the new parsers, diagnostics, or storage relationships.

When upgrading to 0.7, rebuild saved graphs and ID-keyed overrides. Generate
both sides of a code-change comparison with the same Trailmark version and
language selection: overloads, nested/anonymous callables, namespaces, and
same-stem files can acquire different IDs. Graph JSON now includes
`trailmark_version`, `schema_version`, source counts, and parse diagnostics;
schema version `1` does not promise identical parser behavior across releases.
Missing roots and zero matching files fail unless explicitly allowed, while a
valid empty source file still counts as inspected. Empty self-paths do not make
direct entrypoints unreachable, and uncertain deferred callback edges describe
possible execution. See the released
[skills compatibility guide](https://github.com/trailofbits/trailmark/blob/v0.7.0/docs/skills-compatibility.md)
for the full consumer contract.

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
| `trailmark-summary` | Quick structural overview (auto-detected languages, entry points, dependencies) for vivisect/galvanize |
| `trailmark-structural` | Full structural analysis with all pre-analysis passes (blast radius, taint, privilege boundaries, complexity) |

## Directory Structure

```text
trailmark/
├── .claude-plugin/
│   └── plugin.json
├── agents/
│   └── code-slice-worker.md          # Bounded worker, no repository tools.
│                                     # Dispatch as `trailmark:code-slice-worker`
├── README.md
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

## Calcifier recipe for `genotoxic`

The [`genotoxic` Python recipe](skills/genotoxic/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/genotoxic/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/genotoxic/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `request` | `str` | `'Analyze the complete working directory.'` |
