---
name: audit-augmentation
description: >
  Augments Trailmark code graphs with external audit findings from SARIF static
  analysis results and weAudit annotation files. Maps findings to graph nodes by
  file and line overlap, creates severity-based subgraphs, and enables
  cross-referencing findings with pre-analysis data (blast radius, taint, etc.).
  Use when projecting SARIF results onto a code graph, overlaying weAudit
  annotations, cross-referencing Semgrep or CodeQL findings with call graph
  data, or visualizing audit findings in the context of code structure.
---

# Audit Augmentation

Projects findings from external tools (SARIF) and human auditors (weAudit)
onto Trailmark code graphs as annotations and subgraphs.

## When to Use

- Importing Semgrep, CodeQL, or other SARIF-producing tool results into a graph
- Importing weAudit audit annotations into a graph
- Cross-referencing static analysis findings with blast radius or taint data
- Querying which functions have high-severity findings
- Visualizing audit coverage alongside code structure

## When NOT to Use

- Running static analysis tools (use semgrep/codeql directly, then import)
- Building the code graph itself (use the `trailmark` skill)
- Generating diagrams (use the `diagramming-code` skill after augmenting)

## Installation

**MANDATORY:** If `uv run trailmark` fails, install trailmark first:

```bash
uv pip install trailmark
```

## Quick Start

### CLI

```bash
# Augment with SARIF
uv run trailmark augment {targetDir} --sarif results.sarif

# Augment with weAudit
uv run trailmark augment {targetDir} --weaudit .vscode/alice.weaudit

# Both at once, output JSON
uv run trailmark augment {targetDir} \
    --sarif results.sarif \
    --weaudit .vscode/alice.weaudit \
    --json
```

### Programmatic API

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("{targetDir}", language="python")

# Run pre-analysis first for cross-referencing
engine.preanalysis()

# Augment with SARIF
result = engine.augment_sarif("results.sarif")
# result: {matched_findings: 12, unmatched_findings: 3, subgraphs_created: [...]}

# Augment with weAudit
result = engine.augment_weaudit(".vscode/alice.weaudit")

# Query findings
engine.findings()                                       # All findings
engine.subgraph("sarif:error")                          # High-severity SARIF
engine.subgraph("weaudit:high")                         # High-severity weAudit
engine.subgraph("sarif:semgrep")                        # By tool name
engine.annotations_of("function_name")                  # Per-node lookup
```

## Workflow

```
Augmentation Progress:
- [ ] Step 1: Build graph and run pre-analysis
- [ ] Step 2: Locate SARIF/weAudit files
- [ ] Step 3: Run augmentation
- [ ] Step 4: Inspect results and subgraphs
- [ ] Step 5: Cross-reference with pre-analysis
```

**Step 1:** Build the graph and run pre-analysis for blast radius and taint
context:

```python
engine = QueryEngine.from_directory("{targetDir}", language="{lang}")
engine.preanalysis()
```

**Step 2:** Locate input files:
- **SARIF**: Usually output by tools like `semgrep --sarif -o results.sarif`
  or `codeql database analyze --format=sarif-latest`
- **weAudit**: Stored in `.vscode/<username>.weaudit` within the workspace

**Step 3:** Run augmentation via `engine.augment_sarif()` or
`engine.augment_weaudit()`. Check `unmatched_findings` in the result — these
are findings whose file/line locations didn't overlap any parsed code unit.

**Step 4:** Query findings and subgraphs. Use `engine.findings()` to list all
annotated nodes. Use `engine.subgraph_names()` to see available subgraphs.

**Step 5:** Cross-reference with pre-analysis data to prioritize:
- Findings on tainted nodes: overlap `sarif:error` with `tainted` subgraph
- Findings on high blast radius nodes: overlap with `high_blast_radius`
- Findings on privilege boundaries: overlap with `privilege_boundary`

## Annotation Format

Findings are stored as standard Trailmark annotations:

- **Kind**: `finding` (tool-generated) or `audit_note` (human notes)
- **Source**: `sarif:<tool_name>` or `weaudit:<author>`
- **Description**: Compact single-line:
  `[SEVERITY] rule-id: message (tool)`

## Subgraphs Created

| Subgraph | Contents |
|----------|----------|
| `sarif:error` | Nodes with SARIF error-level findings |
| `sarif:warning` | Nodes with SARIF warning-level findings |
| `sarif:note` | Nodes with SARIF note-level findings |
| `sarif:<tool>` | Nodes flagged by a specific tool |
| `weaudit:high` | Nodes with high-severity weAudit findings |
| `weaudit:medium` | Nodes with medium-severity weAudit findings |
| `weaudit:low` | Nodes with low-severity weAudit findings |
| `weaudit:findings` | All weAudit findings (entryType=0) |
| `weaudit:notes` | All weAudit notes (entryType=1) |

## How Matching Works

Findings are matched to graph nodes by file path and line range overlap:

1. Finding file path is normalized relative to the graph's `root_path`
2. Nodes whose `location.file_path` matches AND whose line range overlaps are
   selected
3. The tightest match (smallest span) is preferred
4. If a finding's location doesn't overlap any node, it counts as unmatched

SARIF paths may be relative, absolute, or `file://` URIs — all are handled.
weAudit uses 0-indexed lines which are converted to 1-indexed automatically.

## Supporting Documentation

- **[references/formats.md](references/formats.md)** — SARIF 2.1.0 and
  weAudit file format field reference
