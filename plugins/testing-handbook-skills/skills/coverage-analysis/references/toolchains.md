# Toolchain routes

`scripts/execute-rt.cc` and `scripts/coverage-report.sh` cover the LLVM route on any C/C++ build.
This page holds the per-build-system and per-fuzzer details, and the GCC and Rust routes.

## Build systems

### Plain compiler invocation

```bash
clang++ -DNO_MAIN -O0 -g -fprofile-instr-generate -fcoverage-mapping \
  main.cc harness.cc {baseDir}/scripts/execute-rt.cc -o fuzz_exec
```

C targets: compile the C sources with `clang -c` using the same two coverage flags, then link
the objects with `clang++ -fprofile-instr-generate ... {baseDir}/scripts/execute-rt.cc`.

### CMake

Add a coverage executable next to the fuzzing one; only the flags and the runtime differ:

```cmake
add_executable(fuzz main.cc harness.cc)
target_compile_definitions(fuzz PRIVATE NO_MAIN=1)
target_compile_options(fuzz PRIVATE -g -O2 -fsanitize=fuzzer)
target_link_libraries(fuzz -fsanitize=fuzzer)

add_executable(fuzz_exec main.cc harness.cc ${COVERAGE_SKILL_DIR}/scripts/execute-rt.cc)
target_compile_definitions(fuzz_exec PRIVATE NO_MAIN)
target_compile_options(fuzz_exec PRIVATE -O0 -g -fprofile-instr-generate -fcoverage-mapping)
target_link_libraries(fuzz_exec -fprofile-instr-generate)
```

```bash
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCOVERAGE_SKILL_DIR=<skill dir> .
cmake --build . --target fuzz_exec
```

### Autotools / Makefile libraries (the libpng pattern)

```bash
export CC=clang CXX=clang++ CFLAGS="-fprofile-instr-generate -fcoverage-mapping" CXXFLAGS="$CFLAGS"
./configure --enable-shared=no --disable-tools && make
$CXX $CFLAGS harness.cc .libs/libtarget.a {baseDir}/scripts/execute-rt.cc -lz -o fuzz_exec
```

Then `coverage-report.sh --binary ./fuzz_exec --corpus corpus/ --out coverage/ --ignore 'harness.cc|execute-rt.cc'`.

## Fuzzer-specific notes

| Fuzzer | Corpus location | Coverage build |
|---|---|---|
| libFuzzer | the directory passed to the fuzzer (it writes new inputs back to the first one) | this route; never combine `-fsanitize=fuzzer` with profile instrumentation |
| AFL++ | `output/default/queue/` (crashes under `output/default/crashes/`) | this route; the same `LLVMFuzzerTestOneInput` works, replay `queue/` and, with `--isolate`, `crashes/` |
| honggfuzz | the workspace directory; crash files alongside | this route with the plain compiler, not `hfuzz-clang` |
| cargo-fuzz | `fuzz/corpus/<target>/` | `rustup toolchain install nightly --component llvm-tools-preview` then `cargo +nightly fuzz coverage <target>`; the `.profdata` lands under `fuzz/coverage/<target>/`. Report with `llvm-cov` from the nightly toolchain against `target/<triple>/coverage/<triple>/release/<target>`; `coverage-query.py` reads its `export` JSON unchanged |

## GCC route (gcov + gcovr)

```bash
g++ -DNO_MAIN -O0 -g -ftest-coverage -fprofile-arcs main.cc harness.cc {baseDir}/scripts/execute-rt.cc -o fuzz_exec_gcov
./fuzz_exec_gcov corpus/            # writes .gcda next to the objects
uv tool install gcovr               # or: uv run --with gcovr gcovr ...
gcovr --exclude 'harness.cc|execute-rt.cc' --txt -o coverage/report.txt
gcovr --exclude 'harness.cc|execute-rt.cc' --html-details -o coverage/html/index.html
gcovr --exclude 'harness.cc|execute-rt.cc' --json -o coverage/gcovr.json
```

With clang you can produce gcov data too (`--gcov-executable "llvm-cov gcov"` for gcovr). Do not
mix gcov and profile instrumentation in one binary. `--isolate` works identically here because it
only forks; `.gcda` files are written by each child at exit.

## Large codebases

- Report only what matters: `--ignore` takes any regex; pass several alternatives.
- Query instead of browsing: `coverage-query.py functions --file 'src/parser/'` or
  `uncovered-lines --file 'lexer.c'` keep the output to the files you asked about.
- Per-directory HTML: `llvm-cov show ... -format=html -output-dir html/ -show-directory-coverage`
  (LLVM 18+); `coverage-report.sh` already writes the standard HTML tree.

## Untested here

The scripts were exercised on macOS (Apple clang 17, `xcrun llvm-cov`) and are plain POSIX C++
and bash. The GCC/gcovr and cargo-fuzz commands above are transcribed from the Testing Handbook
and the tools' documentation; run them once on your platform before relying on them in CI.
