# Reports and their data

`coverage-report.sh --out coverage/` leaves these files. Nothing is summarised away: the console
shows totals and the least-covered functions, the files hold everything.

| File | Producer | Contents |
|---|---|---|
| `coverage.json` | `llvm-cov export` | `data[0].files[]` (per-file `summary` with lines/functions/regions/branches counts, `segments`, `branches`, `expansions`), `data[0].functions[]` (name, execution `count`, `regions`, `branches`, `filenames`), `data[0].totals` |
| `coverage.lcov` | `llvm-cov export -format=lcov` | `SF:`/`FN:`/`FNDA:`/`DA:`/`BRDA:` records for `genhtml` and other lcov consumers |
| `report.txt` | `llvm-cov report` | the per-file table with percentages |
| `html/index.html` | `llvm-cov show -format=html` | browsable source with counts |
| `merged.profdata`, `profiles/*.profraw` | `llvm-profdata merge` | reusable profiles; keep them to diff campaigns |
| `crashes.txt` | `execute-rt --isolate` | one `path<TAB>signal N name` or `path<TAB>exit N` line per crashing input |
| `summary.txt` | the script | the console summary |

`llvm-cov export -summary-only` drops the `functions`, `segments`, and `branches` records; the
script always writes the full export so every question can be answered afterwards.

## Region and segment records

- Function `regions` entries are `[line_start, col_start, line_end, col_end, count, file_id, expanded_file_id, kind]`.
- File `segments` entries are `[line, col, count, has_count, is_region_entry, is_gap_region]`; a
  region entry with `has_count` and `count == 0` is code that never ran, which is what
  `coverage-query.py uncovered-lines` prints.
- File `branches` entries are `[line_start, col_start, line_end, col_end, true_count, false_count, file_id, expanded_file_id, kind]`.
- `-ignore-filename-regex` filters `files[]` and `totals` but not `functions[]`; the query tool
  applies the same filter so both agree.

## Differential coverage between two campaigns

Measure each campaign into its own directory, then compare the two exports:

```bash
bash {baseDir}/scripts/coverage-report.sh --binary ./fuzz_exec --corpus corpus-before/ --out cov-before/ --ignore 'harness.cc|execute-rt.cc' --no-html
bash {baseDir}/scripts/coverage-report.sh --binary ./fuzz_exec --corpus corpus-after/  --out cov-after/  --ignore 'harness.cc|execute-rt.cc' --no-html
uv run --no-project {baseDir}/scripts/coverage-query.py --json cov-before/coverage.json functions --only-uncovered > before.txt
uv run --no-project {baseDir}/scripts/coverage-query.py --json cov-after/coverage.json  functions --only-uncovered > after.txt
diff before.txt after.txt
```

For a line-level diff, `llvm-cov show ./fuzz_exec -instr-profile=cov-after/merged.profdata -show-line-counts-or-regions <file>`
against the same command with `cov-before/merged.profdata`. `llvm-cov` accepts one
`-instr-profile`; merge profiles first if you want a union (`llvm-profdata merge a.profdata b.profdata -o union.profdata`).

## lcov HTML

```bash
genhtml --output-directory coverage/lcov-html coverage/coverage.lcov
```

gives a per-source-file report from the lcov export (useful with LLVM older than 18, which has no
directory view).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `no .profraw written` | binary built without `-fprofile-instr-generate -fcoverage-mapping`, or `LLVM_PROFILE_FILE` unwritable | rebuild; check the `--out` directory is writable |
| `coverage.json` counts every function as 0 | the harness returned before calling the target (input contract not met) | inspect the harness's early returns; fix the corpus format |
| script exits 4 during replay | a corpus input crashed the in-process replay | rerun with `--isolate`; the crash list is in `crashes.txt` |
| `llvm-profdata` / `llvm-cov` not found | tools not on PATH | install LLVM (`apt install llvm`, `brew install llvm`) or set `LLVM_PROFDATA`/`LLVM_COV`; on macOS the script tries `xcrun` |
| `Failed to load coverage: ... malformed` | profile from a different build of the binary | rerun the replay after every rebuild |
| Numbers look inflated | harness/runtime files included | add them to `--ignore` |
| `-O3` build | optimisation removed code | rebuild with `-O0` or `-O2` |
