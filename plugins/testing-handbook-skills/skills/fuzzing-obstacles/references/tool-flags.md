# Fuzzing build flags by tool

Which tools define the fuzzing flag, and the commands to build with it. Checked against
upstream sources: AFL++ `src/afl-cc.c` (`add_defs_common` inserts
`-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1`), honggfuzz `hfuzz_cc/hfuzz-cc.c` (no such
define), OSS-Fuzz `infra/base-images/base-clang/Dockerfile` (base `CFLAGS` include the
define), the LLVM libFuzzer documentation ("Fuzzer-friendly build mode" proposes the macro as a
convention; `-fsanitize=fuzzer` does not define it), and `clang -fsanitize=fuzzer -dM -E`.

| Tool | Flag defined automatically? | Build |
|------|-----------------------------|-------|
| libFuzzer (clang `-fsanitize=fuzzer`) | No | `clang++ -g -fsanitize=fuzzer,address -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION harness.cc target.cc -o fuzzer` |
| libFuzzer instrumentation only | No | `clang -fsanitize=fuzzer-no-link -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -c target.c` |
| AFL++ (`afl-cc`, `afl-clang-fast`, `afl-clang-lto`) | Yes | `afl-clang-fast++ -g -fsanitize=address target.cc harness.cc -o fuzzer` |
| honggfuzz (`hfuzz-clang`) | No | `hfuzz-clang++ -g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION target.cc harness.cc -o fuzzer` |
| LibAFL (C/C++ targets) | No | `clang++ -g -fsanitize=address -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION target.cc -c -o target.o` |
| OSS-Fuzz | Yes (in the base `CFLAGS`/`CXXFLAGS`) | `$CXX $CXXFLAGS target.cc $LIB_FUZZING_ENGINE -o $OUT/fuzzer` |
| cargo-fuzz | Yes (`--cfg fuzzing`) | `cargo fuzz build <target>`; `cargo fuzz run <target>` |
| Rust outside cargo-fuzz | No | `RUSTFLAGS="--cfg fuzzing" cargo build` |
| Coverage build that replays the corpus | Never | Add the same `-D` or `--cfg` so the replay follows the fuzzing build's paths |

`cfg!(fuzzing)` is a runtime-visible constant usable in ordinary expressions; `#[cfg(fuzzing)]`
removes items at compile time. The fuzzing cfg is not set by plain `cargo build`.

AFL++ tip: persistent-mode harnesses benefit most from obstacle patching, and
`AFL_LLVM_LAF_ALL` adds input-to-state transformations for comparisons that remain.

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Coverage does not improve after patching | Flag not defined in this build, or wrong obstacle | Check the build's flags (`-dM -E \| grep FUZZING`); profile to find the real bottleneck |
| Many crashes in newly reachable code | Downstream code relies on the skipped check | Add defensive defaults or partial validation |
| Code compiles differently across files | Flag missing from some build configurations or dependencies | Define it in every translation unit of the fuzzing build |
| Cannot reproduce production bugs | Fuzzing build diverges too much | Minimize patches; keep state-critical validation |

## Measuring patch effectiveness

Compare line, region and function coverage (`llvm-cov`, or `cargo fuzz coverage`) before and
after the patch on the same corpus, and check whether the corpus grows more diverse.

## Real-world examples

- **OpenSSL** uses `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` to relax some checks while fuzzing,
  for example in [crypto/cmp/cmp_vfy.c](https://github.com/openssl/openssl/blob/afb19f07aecc84998eeea56c4d65f5e0499abb5a/crypto/cmp/cmp_vfy.c#L665-L678).
  Its fuzzing setup: [openssl/fuzz](https://github.com/openssl/openssl/tree/master/fuzz).
- **ogg crate (Rust)** skips checksum verification under
  [`cfg!(fuzzing)`](https://github.com/RustAudio/ogg/blob/5ee8316e6e907c24f6d7ec4b3a0ed6a6ce854cc1/src/reading.rs#L298-L300).

References: [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html),
[Rust conditional compilation](https://doc.rust-lang.org/reference/conditional-compilation.html).
