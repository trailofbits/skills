---
name: coverage-analysis
type: technique
description: "Measures and interprets what a fuzzing campaign actually reaches, using llvm-cov, lcov, or a fuzzer's own coverage output. Covers baselining a new campaign, reading coverage reports, and turning uncovered regions into harness, seed, or dictionary work. Use when a fuzzer plateaus, when judging whether a harness is effective, after changing a harness, or when asking why some code is never reached."
---

# Coverage Analysis

Coverage tells you which code a corpus exercises. Use it to judge a harness, to find what blocks
the fuzzer (magic values, checksums, unreachable branches), and to track the effect of harness,
seed, or dictionary changes. Measure it from the **saved corpus** with a dedicated coverage build,
never from the fuzzer's live statistics: that is reproducible and comparable across fuzzers.

Skip it when the campaign is still finding crashes, when the fuzzer's own counters answer the
question, or when the codebase is so large that a full report is impractical.

## Procedure (LLVM, C/C++)

The bundled scripts do the mechanical work. Run them; do not retype them or read their output
files into the conversation.

1. **Build a coverage binary.** Compile the target and its libFuzzer-style harness with
   `-fprofile-instr-generate -fcoverage-mapping`, define `NO_MAIN` (or otherwise drop the
   program's `main`), and link `{baseDir}/scripts/execute-rt.cc` instead of a fuzzing engine.
   Use `-O0 -g` (or `-O2`; never `-O3`, which deletes code). Do not add `-fsanitize=fuzzer`.

   ```bash
   clang++ -DNO_MAIN -O0 -g -fprofile-instr-generate -fcoverage-mapping \
     target.cc harness.cc {baseDir}/scripts/execute-rt.cc -o fuzz_exec
   ```

   For C targets compile the C files with `clang -c` and link with `clang++`. For a CMake or
   autotools project, set `CFLAGS`/`CXXFLAGS` to the two coverage flags and link the harness,
   the static library, and `execute-rt.cc` yourself; see
   [references/toolchains.md](references/toolchains.md) for the CMake, libpng-style, GCC/gcovr,
   and Rust routes.

2. **Replay the corpus and write every report** in one step:

   ```bash
   bash {baseDir}/scripts/coverage-report.sh --binary ./fuzz_exec --corpus corpus/ \
     --out coverage/ --ignore 'harness.cc|execute-rt.cc'
   ```

   It writes `coverage/coverage.json` (full `llvm-cov export`: per-file, per-function, region and
   branch data), `coverage.lcov`, `report.txt`, `html/`, the merged `.profdata`, and
   `summary.txt`, and prints only the totals and the least-covered functions. Add `--isolate`
   when the corpus may contain crashing inputs: each input then runs in its own process, the
   crashing inputs are listed in `coverage/crashes.txt`, the safe inputs are still measured, and
   the crashing inputs' coverage is **not** recorded and cannot be recovered from the run. Say so
   in the write-up rather than reporting it as covered. If an in-process replay dies, the script
   stops with exit 4 and tells you to rerun with `--isolate`.

3. **Locate what is not reached** without reading the JSON or HTML:

   ```bash
   uv run --no-project {baseDir}/scripts/coverage-query.py --json coverage/coverage.json functions --only-uncovered
   uv run --no-project {baseDir}/scripts/coverage-query.py --json coverage/coverage.json uncovered-lines --file main.cc --context 2
   uv run --no-project {baseDir}/scripts/coverage-query.py --json coverage/coverage.json branches --file main.cc --only-untaken
   ```

   `functions` lists every function, not only a top-N; `uncovered-lines` prints each never-executed
   region start as `file:line` with the source text so you can cite it; `branches` shows
   true/false counts where the compiler recorded them.

4. **Interpret.** Read the cited source lines, then classify each gap:

   | What you see at the gap | Meaning | Next action |
   |---|---|---|
   | Comparison against a constant (`memcmp`, `== 0x...`, checksum) | Magic-value or checksum blocker | Add the constant to a dictionary (`"\x7F\x45\x4C\x46"`) and a seed that carries it |
   | A branch the harness never selects | Harness gap | Route the input to that path (mode byte, second entrypoint) |
   | Code no harness path can call | Dead for this harness | Say so; do not count it as a fuzzing failure |
   | Coverage lower than the last run | Regression | Compare against the stored `coverage.json` of the previous campaign |

   Verify a proposed seed by replaying it alone (put it in its own directory and rerun step 2) and
   confirming the gate's line count is now non-zero. A block that the current corpus reaches is
   not a blocker.

5. **Deliver.** Totals, the uncovered functions, each blocker as `file:line` with its proposed
   dictionary entry or seed, and the crash accounting from `crashes.txt`. Keep `coverage/` on
   disk; the HTML is for humans, `coverage.json` and `coverage.lcov` are for tools and later
   comparison.

## Rules

- Coverage builds use a dedicated binary; fuzzer instrumentation and profile instrumentation do
  not mix.
- Exclude harness and runtime files with `--ignore`; otherwise they inflate the numbers.
- Never compare coverage produced by different tools or instrumentation (fuzzer counters vs
  llvm-cov, LLVM vs gcov). Store `coverage.json` with a timestamp to track trends.
- A crashing input's coverage is lost with the process; isolation preserves the rest, nothing
  restores the lost part. Fix or quarantine the crash, then re-measure.
- Do not hand-write the runtime, the merge/export commands, or an HTML generator; use the
  scripts, and read [references/reports.md](references/reports.md) for what each artifact holds
  and how to diff two campaigns.

## References

- [references/toolchains.md](references/toolchains.md) — CMake integration, autotools projects,
  GCC/gcovr, cargo-fuzz, AFL++/honggfuzz corpora, large-codebase filtering.
- [references/reports.md](references/reports.md) — the `llvm-cov export` JSON layout the query
  tool reads, lcov/genhtml, differential coverage between campaigns, troubleshooting.
