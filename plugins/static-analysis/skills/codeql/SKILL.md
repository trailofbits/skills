---
name: codeql
description: >-
  Scans code for security vulnerabilities with CodeQL interprocedural dataflow and taint
  analysis. Use for "run codeql", "codeql scan", "build codeql database", "SAST scan",
  "taint analysis", "dataflow analysis", or "find vulnerabilities in this repo".
  Covers Python, JavaScript/TypeScript, Go, Java/Kotlin, C/C++, C#, Ruby, and Swift.
  Supports run-all and important-only modes and project-specific data extensions.
  Use semgrep for fast pattern matching; sarif-parsing for existing results.
allowed-tools: Bash Read Write Edit Glob Grep AskUserQuestion TaskCreate TaskList TaskUpdate TaskGet
---

# CodeQL Analysis

Use the scripts first. Preserve full raw and final SARIF on disk; read compact reports,
not the whole SARIF. Track long builds with the task tools.

## Each Bash call is a fresh shell

Variables, arrays and sourced functions never carry between tool calls. Substitute actual
quoted paths in every new call. Define all options in the same call that uses them.

## Database Discovery

Confirm codeql, jq, and uv are installed. If CodeQL is missing, stop and offer the
CodeQL bundle or gh extension install github/gh-codeql followed by gh codeql install-stub.
Discover every usable database (a leftover marker alone does not prove a successful build):

```bash
set -euo pipefail
DB_LIST=$("{baseDir}/scripts/find_databases.sh" "/absolute/source-or-requested-output" .)
while IFS= read -r db; do
  [ -n "$db" ] || continue
  printf '%s\n' "$db"
  codeql resolve database --format=json -- "$db" | jq '{languages}'
  grep -A5 '^creationMetadata:' "$db/codeql-database.yml" || true
done <<<"$DB_LIST"
```

### Auto-Detection Logic

- Respect an explicit database/build/workflow choice without asking again.
- No database: build. One database: ask reuse or build new. Several: show paths, languages
  and creation metadata, then ask; offer at most four choices, including build new.
- Build-only, extension-only and analysis-only requests use the corresponding workflow
  under workflows/ and stop at the requested boundary. Full scans run build/reuse →
  extension evaluation → analysis, documenting skipped phases.

## Output Directory

Resolve this once **after** choosing a database. An explicit user output path takes priority;
otherwise reuse the selected database's parent, or auto-increment for a new build.
Substitute the actual requested/reuse path below, or an empty string for a new default:

```bash
"{baseDir}/scripts/resolve_output_dir.sh" "/absolute/output"
```

Record the returned absolute path. Pass that literal path to every later step, including
the build workflow's out. Never allocate a second default. Keep build logs, database,
extensions and analysis artifacts together; an explicitly reused database can remain in
its existing location when the user selected a separate output directory.

## Procedure

1. Build if needed after discovery and output selection:

   ```text
   /static-analysis:codeql-build {"target":"/absolute/source","out":"/absolute/output","lang":"python"}
   ```

   Substitute actual paths and language. For manual control or failed rungs read
   workflows/build-database.md. The workflow handles the build ladder and quality gate.
   On Apple Silicon investigate exit 137 as arm64e/arm64 tracing mismatch before
   --build-mode=none; read references/macos-arm64e-workaround.md.

2. Resolve actual database languages, including after a new build:

   ```bash
   set -euo pipefail
   codeql resolve database --format=json -- "/absolute/selected/database" |
     jq -e '.languages | select(type == "array" and length > 0)'
   ```

   Ask which language if several remain and none was selected; verify a selected language.
   Run the quality checker after each build. Explain missing coverage before asking for an
   informed override of built-below-threshold. The pipeline accepts --max-error-ratio PERCENT
   --quality-reason "approved reason"; zero source/project files still fail.

3. Evaluate extensions with workflows/create-data-extensions.md. Inspect existing models
   first, then model confirmed missing sources, sinks, summaries or sanitizers; explain omissions.

4. Run codeql resolve qlpacks. Check official, Trail of Bits and Community packs for the
   resolved language. Discover model packs from installed manifests and repository
   qlpack.yml/codeql-pack.yml files with dataExtensions, plus standalone extension YAML.
   Read workflows/run-analysis.md Steps 2–3 for discovery and flag mapping, and
   references/ruleset-catalog.md when choosing packs. Offer install-or-ignore for missing packs.
   Ask one combined plan question: mode, query/model packs and threat models. Defaults:
   run-all, every installed compatible query pack, detected compatible model packs, remote
   sources. Already chosen values need no new question.

5. Translate the **entire accepted plan, including accepted defaults**, into this one shell
   call. Replace every sample value. Empty arrays mean explicitly excluded/not available,
   not forgotten defaults. Do not execute the sample pack names unchanged.

   ```bash
   # Accepted analysis plan: replace all sample paths/names with the confirmed values.
   set -euo pipefail
   DB_NAME="/absolute/selected/database"
   OUTPUT_DIR="/absolute/output"
   CODEQL_LANG="python"
   MODE="run-all"
   THIRD_PARTY_PACKS=(vendor/python-queries community/python-queries)
   MODEL_PACKS=(acme/python-models)
   ADDITIONAL_PACKS=("/absolute/model-directory")
   THREAT_MODELS=(remote)
   args=(--database "$DB_NAME" --language "$CODEQL_LANG" --out "$OUTPUT_DIR" --mode "$MODE")
   if ((${#THIRD_PARTY_PACKS[@]})); then args+=(--third-party-packs "${THIRD_PARTY_PACKS[*]}"); fi
   for value in "${MODEL_PACKS[@]+"${MODEL_PACKS[@]}"}"; do args+=(--model-pack "$value"); done
   for value in "${ADDITIONAL_PACKS[@]+"${ADDITIONAL_PACKS[@]}"}"; do args+=(--additional-pack "$value"); done
   for value in "${THREAT_MODELS[@]+"${THREAT_MODELS[@]}"}"; do args+=(--threat-model "$value"); done
   "{baseDir}/scripts/codeql_pipeline.sh" "${args[@]}"
   ```

   Include any approved quality override, --threads, --timeout, and --rerun in args in that
   same call. See {baseDir}/scripts/codeql_pipeline.sh --help for flags. The pipeline verifies
   the explicit .qls and preserves full raw/final SARIF. Earlier output is archived under
   .attempts/; a failed retry never presents old output as its success. Do not remove a run
   lock until its owning process is confirmed stopped.

6. Read run-status.json first. Only status: complete means completed analysis. On failure,
   inspect the recorded attempt and diagnostics, not archived output as current findings.
   On success read quality.json, rulesets.txt, summary.json and report.json. Compare executed
   selections in rulesets.txt with the accepted plan and explain exclusions. report.json
   includes severity-ranked locations/security severity and omission counts. For omitted
   evidence use a targeted query or redirect process_results.py summary FILE --details
   --top-rules 0 to disk; do not dump all evidence into context.

## Rationalizations to Reject

- “The build passed, so extraction worked.” Check source/file counts and extraction errors.
- “security-extended/default packs suffice.” Check third-party packs; run-all includes both
  security-and-quality and security-experimental. Never pass bare pack names to analyze.
- “Standard frameworks need no models.” Inspect project-specific wrappers and extensions.
- “Build failure justifies build-mode=none.” Exhaust the build ladder and macOS workarounds.
- “No findings proves security.” Verify extraction, models and a nonempty explicit suite.
- “Scan means pick the first database.” Ask unless the user specified the choice.
- “A new shell remembers options.” Rebuild arrays and source helpers in each call.
- “Planned packs were used.” Check recorded executed selections, not just the plan.

## Success Criteria

One output directory; appropriate database/language; quality and suite gates passed;
extensions evaluated; selected packs used or exclusions explained; build logs preserved;
full raw/results.sarif and final results/results.sarif preserved; compact evidence reported;
zero findings investigated; failed/skipped/partial phases identified explicitly.

## References

- [workflows/build-database.md](workflows/build-database.md),
  [workflows/create-data-extensions.md](workflows/create-data-extensions.md),
  [workflows/run-analysis.md](workflows/run-analysis.md): corresponding phase/manual path.
- [references/build-fixes.md](references/build-fixes.md),
  [references/quality-assessment.md](references/quality-assessment.md),
  [references/macos-arm64e-workaround.md](references/macos-arm64e-workaround.md): corresponding failure.
- [references/language-details.md](references/language-details.md),
  [references/ruleset-catalog.md](references/ruleset-catalog.md),
  [references/threat-models.md](references/threat-models.md),
  [references/performance-tuning.md](references/performance-tuning.md): corresponding decision.

This skill creates SARIF. Use sarif-parsing for existing results and semgrep for fast
single-file matching or a compiled target without a viable build.
