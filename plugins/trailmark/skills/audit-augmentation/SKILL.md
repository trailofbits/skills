---
name: audit-augmentation
description: >-
  Imports and projects SARIF (including Semgrep/CodeQL), weAudit, or binary-graph findings onto a Trailmark
  code graph. Use for finding-to-function context, taint, blast-radius, or privilege-boundary
  cross-references, visualizing or overlaying findings; not for a single-finding reachability verdict.
---

# Audit Augmentation

Project audit findings onto one Trailmark graph, then prioritize findings by the
pre-analysis signals on the same nodes. Use `trailmark-finding-triage` after
this step when one finding needs a reachability verdict or PoC.

## Procedure

1. Locate the SARIF, weAudit, or binary graph inputs. The helper resolves the
   target to an absolute path: parsing a relative root directly can leave
   findings unmatched because graph and scanner paths do not normalize alike.

2. Run the bundled command. It builds the graph, runs pre-analysis, imports the
   finding file, and cross-references all results **in one process**. Do not run
   `trailmark augment` separately when you need those cross-references: a new
   process does not retain the first process's graph or pre-analysis.

   ```bash
   uv run --no-project "{baseDir}/scripts/augment_context.py" \
     --target "/absolute/path/to/repository" \
     --sarif results.sarif --out augmented.json --summary-out summary.json
   ```

   Replace `--sarif` with `--weaudit .vscode/alice.weaudit` when appropriate.
   Combine one flag of each kind to import both machine and human findings.
   Binary graph import is Trailmark 0.4+ only and uses `--binary graph.json`.
   The command stops with a clear error on an unsupported version.
   If auto-detection misses the code, pass `--language python,rust` or another
   explicit language set.

3. Use `summary.json` for compact import statistics, including binary-only
   imports, and the SARIF/weAudit intersections
   with `tainted`, `high_blast_radius`, and `privilege_boundary`. Use
   `augmented.json` for the complete subgraph counts and priority-node list.
   `findings_on_tainted` includes SARIF warnings/notes and human findings;
   `error_on_tainted` is only the error subset. `signals_available: false`
   means a signal is unavailable, not that the input is clean. Ranking counts
   actual analysis signals first, then severity; tool/author tags are not votes.
   A missing severity subgraph means no finding matched that class; check
   `subgraph_names()` before querying it.

4. The helper accepts one file of each kind per run. SARIF and weAudit imports
   replace earlier augmentation from their source family: merge same-kind files
   first following [formats.md](references/formats.md). For multiple binary artifacts, use the programmatic API below.
   Report unmatched findings and investigate a high count
   before calling the scan clean. Module and `proxy.unresolved:*` nodes may be
   legitimate line-overlap matches; keep them in the result.

## Safety and reporting

- Do not skip pre-analysis because the input is “only SARIF”; it supplies the
  cross-reference signals this skill exists to report.
- Keep the complete JSON in `--out`; use `--limit 0` only when every priority
  node must be printed into the conversation.
- Read [formats.md](references/formats.md) for SARIF/weAudit field and line
  conventions.

## Rationalizations to Reject

| Shortcut | Why it is wrong |
| --- | --- |
| Only errors matter | Keep warnings, notes and human findings in every cross-reference. |
| The machine report is enough | Import both machine and human sources when both are available. |
| Pre-analysis is optional | It supplies the taint, blast-radius and boundary signals. |
| No matches means clean | Inspect unmatched findings, path roots and unavailable signals. |
| More source tags means higher risk | Rank analysis signals and severity, not author/tool counts. |
| The console list is complete | Check its total/truncation fields; the full list is in `--out`. |

## Programmatic queries

When finding messages, node annotations, or raw graph queries are needed, keep
the engine in the same Python process as its pre-analysis and imports:

Run this in a trusted environment with `uv run --no-project --with 'trailmark>=0.2,<0.6' python -`:

```python
from pathlib import Path
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory(str(Path(target).resolve()), language="auto")
engine.preanalysis()
engine.augment_sarif(sarif_file)       # Include only the available input kinds.
engine.augment_weaudit(weaudit_file)
# For binary input, check hasattr(engine, "augment_binary") first (v0.4+).
# Then call engine.augment_binary(binary_file).
# Multiple binary artifacts can be imported on this same engine.
engine.findings()                    # Nodes with finding or audit_note annotations.
engine.annotations_of(node_id)       # Complete annotations for a node.
engine.subgraph_names()              # Available severity and tool/author groups.
engine.subgraph("sarif:error")        # Query only names returned above.
```

Binary input has `artifact`, `functions`, and `calls` fields; imported
`binary:<artifact>` nodes and inferred `corresponds_to` edges retain source
links. Trailmark imports this graph; it does not disassemble the binary.
For persistent source/external links on Trailmark 0.5+, use the main
`trailmark` skill's Repository Links guidance.
