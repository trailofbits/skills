---
name: graph-evolution
description: >
  Compares Trailmark code graphs at two snapshots — git commits or tags, two source directories,
  or pre-exported graph JSON — to surface security-relevant structural changes that text diffs
  miss: new or changed entrypoints, taint reaching new functions, blast-radius growth, privilege
  boundary changes, and complexity shifts. Use when reviewing what changed between audit
  snapshots, releases, or commits.
---

# Graph Evolution

One helper builds both graphs, runs pre-analysis, computes the native and subgraph diffs, saves
every artifact in full, and writes a report with every deterministic section filled. Your work is
the judgment: read the source of the changed nodes and write the security impact.

## When to use

Comparing two snapshots of the same codebase for structural security changes. Not for a single
snapshot (use `trailmark`), for line-level review of a diff (use `differential-review`, which
complements this skill), or for mutation testing (use `genotoxic`).

## Procedure

1. **Run the helper** with an explicit `--language` (`auto` or a list such as `python,rust`).
   `trailmark diff` defaults to Python and returns a valid but empty diff for anything else.
   Do not read the helper's source first; its `--help` is complete, and the commands below are
   the whole interface.

   ```bash
   # git refs (temporary detached worktrees; cleanup failures are reported)
   uv run --no-project "{baseDir}/scripts/evolve.py" --repo . --before v1.2.0 --after v1.3.0 \
     --language auto --output-dir evolution-review --name v1_2_0_v1_3_0

   # two source directories
   uv run --no-project "{baseDir}/scripts/evolve.py" --before-dir before --after-dir after \
     --language auto --output-dir evolution-review --name before_after

   # graphs exported earlier (needs the matching `trailmark diff --json` output)
   uv run --no-project "{baseDir}/scripts/evolve.py" --before-graph b.json --after-graph a.json \
     --native-diff d.json --language auto --output-dir evolution-review
   ```

   It writes `evidence/before_graph.json`, `evidence/after_graph.json`,
   `evidence/trailmark_diff.json`, `evidence/subgraph_diff.json`, `summary.json`, `findings.md`,
   and `GRAPH_EVOLUTION_<name>.md`. It stops if either graph has no nodes.
   The output directory must be new or empty; never reuse an existing review directory.
   Pre-exported graphs must include complete entrypoint metadata under `entrypoints`
   (node ID to kind/trust_level/asset_value/description), as the helper's exports do.
   A plain `QueryEngine.to_json()` export omits it: add `attack_surface()` metadata or
   rebuild from source. The helper checks every native delta against the graphs and
   refuses missing provenance or contradictions. Report names are sanitized for filenames.

2. **Read `summary.json`**, not the raw graph or diff JSON — those files are complete and can be
   large. The packet includes complete `node_changes` and `edge_changes`, entrypoint changes,
   complexity changes, every subgraph membership change, and candidates. Read all these
   deltas, not just high-priority candidates: removing an authorization call can leave
   memberships unchanged. For large packets use targeted JSON queries with explicit counts;
   never silently cap the review scope. Read the report's Methodology section when editing it.

3. **Rewrite `findings.md` in one pass.** Read the source of the nodes the candidates name, then
   write the whole file once with the Write tool: for each candidate, keep or change the
   severity from the source, replace both `TODO` lines with what an attacker gains or loses and
   what to review, fix, or test. Keep a line for each candidate:
   `**Disposition C0001:** confirmed — <source-based reason>` (or `dismissed` / `needs-review`).
   Keep non-security changes as INFO or explicitly dismiss them; do not silently delete them.
   If there are no findings, write `No security findings: <source-based reason>` plus
   every candidate's disposition. Add findings the pre-classification cannot see —
   especially a new call edge into a function that builds a query, command, or path from its
   arguments. One Write, not one Edit per line.

4. **Assemble and deliver.**

   ```bash
   uv run --no-project "{baseDir}/scripts/evolve.py" --assemble --output-dir evolution-review
   ```

   This validates the review before changing the report and fails while a required `TODO` field remains — including the
   one in Methodology, where you replace it with the limitations specific to this comparison
   (one Edit). Deliver the report and the four evidence paths. Read
   [report-format.md](references/report-format.md) if a section needs more structure and
   [evolution-metrics.md](references/evolution-metrics.md) when a metric needs explaining.

## Severity criteria

| Severity | Structural criteria (confirm in source) |
|---|---|
| CRITICAL | Source-confirmed exploitable impact, such as a removed effective authorization check; never assigned from graph structure alone |
| HIGH | New untrusted entrypoint or newly reachable sensitive-name node; CC increase over 3 on a tainted node; proposals needing source review |
| MEDIUM | New call edges crossing a trust boundary; moderate security-relevant complexity growth |
| LOW | Added code without entrypoint reachability; cosmetic changes |
| INFO | Dead code removal, complexity reductions, other positive changes |

## Rationalizations to reject

| Rationalization | Reality |
|---|---|
| "The text diff already shows what changed." | Reachability, taint, and blast radius are not visible in a line diff; that is what this skill measures. |
| "The diff is empty, so nothing changed." | Only after both graph summaries show healthy node counts. An empty diff with a wrong `--language` is a parsing failure. |
| "A node left `privilege_boundary`, so authentication was removed." | The boundary may have moved. Read the source before concluding. |
| "I can hand-write the tables from the JSON." | The helper already filled every table completely. Write the judgment, not the inventory. |
| "I will fix the TODOs one edit at a time." | Rewrite `findings.md` once and assemble; per-line edits and re-reading the report cost more than the review itself. |
| "The proposed severity is the answer." | It is a structural proposal. Context decides. |

## Integration

Run `differential-review` on the same range for line-level findings; this report supplies the
structural context. Mutation testing (`genotoxic`) can target the functions this report flags.
Use `trailmark-review-gate` when an explicit structural PASS/WARN/FAIL/UNKNOWN gate is needed.
