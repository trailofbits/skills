---
name: codeql
description: >-
  Run a CodeQL security scan, build or reuse a database, create data extensions, and produce
  SARIF results. Use for CodeQL scans, database builds, taint analysis, or SAST analysis.
allowed-tools: Bash Read Write Edit Glob Grep AskUserQuestion TaskCreate TaskList TaskUpdate TaskGet
---

# CodeQL Analysis

Use the scripts first. Keep every generated file in one output directory and never open a raw
SARIF file with `Read`.

For build-only, extension-only, or analysis-only requests, use the corresponding workflow under
`workflows/` and stop when that request is complete. Use the procedure below for a full scan.

## Rules that must not change

1. Run `check_db_quality.py` after every build. A successful build can still extract no useful source.
2. Use an explicit generated `.qls`; never pass query-pack names directly to `codeql database analyze`.
3. Investigate zero findings. Confirm database quality and suite verification in the report.
4. On Apple Silicon, treat exit 137 as an arm64e/arm64 tracing mismatch before considering `--build-mode=none`.
5. For full scans, follow the build, extension, and analysis phases in order. Record any skipped phase as a coverage gap.
6. If multiple databases exist and the user has not selected one, ask. Offer at most four options.

## Output Directory

Resolve this once, before a build or analysis. Keep the database, logs, extensions, raw results,
final results, rulesets, quality verdict, and compact summary under this one directory.

## Procedure

1. Confirm `codeql`, `jq`, and `uv` are available. Resolve the output directory once:

```bash
OUTPUT_DIR=$("{baseDir}/scripts/resolve_output_dir.sh" "${USER_SPECIFIED_DIR:-}")
echo "$OUTPUT_DIR"
```

2. Discover usable databases in the same shell that consumes the result. If this reports more
   than one database and the user did not choose one, ask them to select it (at most four options):

```bash
if ! DB_LIST=$("{baseDir}/scripts/find_databases.sh" "${OUTPUT_DIR:-.}" .); then
  echo "ERROR: CodeQL database discovery failed" >&2
  exit 1
fi
printf '%s\n' "$DB_LIST"
```

   If none exists, build one with `/static-analysis:codeql-build`.
   That workflow handles language detection, build methods, arm64e routing, build fixes, and the quality gate.
   For manual control, read `workflows/build-database.md` before running any build command.

3. Set `DB_NAME` to the selected database (the directory containing `codeql-database.yml`), then
   resolve its actual languages. Do this after a new build too; do not guess from file extensions:

   ```bash
   set -euo pipefail
   DB_NAME="/path/to/selected/database"
   codeql resolve database --format=json -- "$DB_NAME" |
     jq -e '.languages | select(type == "array" and length > 0)'
   ```

   Set `CODEQL_LANG` to the resolved language. If the database holds multiple languages and
   the user has not selected one, ask which to analyze before setting it; do not select the
   first entry silently. A language the user already chose must be present in the resolved list.

4. If extensions are needed, read `workflows/create-data-extensions.md`. Check existing extensions first;
   only model confirmed missing sources, sinks, summaries, or sanitizers.

5. Gather the actual available packs before presenting the plan. Run `codeql resolve qlpacks`
   and identify the official and installed third-party packs for `CODEQL_LANG`, using
   `references/ruleset-catalog.md` when needed. Detect model packs in repository
   `qlpack.yml`/`codeql-pack.yml` files with `dataExtensions`, standalone YAML files with
   `extensions:`, and the installed pack manifests returned by CodeQL. Record their names
   and directories; if an expected pack is missing, include an install-or-ignore choice.

   Ask one combined question showing scan mode, the installed query packs, detected model packs,
   and threat model. Defaults are run-all, every installed pack, detected model packs, and
   remote-only sources. If the user already chose a value, show it as chosen rather than asking again.
   Follow `workflows/run-analysis.md` Steps 2–3 for model-pack discovery and flag mapping.

6. Run analysis and compact result processing in one shell. Supply only options the user selected:

```bash
"{baseDir}/scripts/codeql_pipeline.sh" \
  --database "$DB_NAME" --language "$CODEQL_LANG" --out "$OUTPUT_DIR" \
  --mode run-all
```

   The pipeline writes `raw/results.sarif`, final `results/results.sarif`, `quality.json`,
   `rulesets.txt`, and compact `summary.json`. Use `summary.json` for the report; inspect a narrowed
   record only when needed. For its exact flags, run `codeql_pipeline.sh --help`.

7. Report the output directory, database, language, mode, selected packs/model packs/threat models,
   compact finding counts, and whether the database-quality and suite gates passed. Mark skipped or
   partial phases explicitly.

## References

- Read `workflows/build-database.md` only for a manual build or a failed build rung.
- Read `workflows/create-data-extensions.md` only when evaluating custom sources/sinks.
- Read `workflows/run-analysis.md` only when adapting the analysis plan beyond the pipeline flags.
- Read `references/build-fixes.md`, `quality-assessment.md`, or `macos-arm64e-workaround.md` only for
  their named failure condition.
- Read `references/language-details.md`, `ruleset-catalog.md`, or `threat-models.md` only when choosing
  that corresponding value.

This skill creates SARIF. Use sarif-parsing to investigate an existing SARIF file without running CodeQL.

## Each Bash Call Is a Fresh Shell

Use `codeql_pipeline.sh` for analysis because it keeps the output directory, database, language,
and selected flags together. When following a manual workflow block, define every variable and
source every helper again in that same block; Bash state does not carry to the next tool call.
