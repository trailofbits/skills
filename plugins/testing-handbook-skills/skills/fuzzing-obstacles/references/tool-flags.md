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
| LibAFL (C/C++ targets) | Build-system dependent | For a libFuzzer-compatible integration: `clang++ -g -fsanitize=fuzzer-no-link,address -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -c target.cc -o target.o`, then link with that integration's runtime. Other LibAFL executors need their own coverage instrumentation and link flags; AddressSanitizer alone is not coverage instrumentation |
| OSS-Fuzz | Yes (in the base `CFLAGS`/`CXXFLAGS`) | `$CXX $CXXFLAGS target.cc $LIB_FUZZING_ENGINE -o $OUT/fuzzer` |
| cargo-fuzz | Yes (`--cfg fuzzing`) | `cargo fuzz build <target>`; `cargo fuzz run <target>` |
| cargo-afl | Yes unless `AFL_NO_CFG_FUZZING` disables it | `cargo afl build`; inspect the environment and generated flags |
| Plain Rust/Cargo | No | `RUSTFLAGS="--cfg fuzzing" cargo build` |
| Coverage build that replays the corpus | Build-system dependent | Inspect inherited flags; add the same `-D` or `--cfg` if absent so replay follows the fuzzing build's paths |

`cfg!(fuzzing)` is a runtime-visible constant usable in ordinary expressions; `#[cfg(fuzzing)]`
removes items at compile time. The fuzzing cfg is not set by plain `cargo build`.

For Cargo projects using the `unexpected_cfgs` lint, declare the custom name in
`Cargo.toml` (this declaration does not enable it):

```toml
[lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(fuzzing)'] }
```

For direct rustc invocations, use `--check-cfg 'cfg(fuzzing)'`. Verify both the
ordinary and fuzzing builds, especially projects with `-D warnings`.

AFL++ tip: persistent-mode harnesses benefit most from obstacle patching, and
`AFL_LLVM_LAF_ALL` splits difficult comparisons into smaller comparisons. CmpLog
provides input-to-state solving; these are different mechanisms.

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Coverage does not improve after patching | Flag not defined in this build, or wrong obstacle | Inspect preprocessing macros with the same compiler and flags as the build, then profile |
| Many crashes in newly reachable code | Downstream code relies on the skipped check | Add defensive defaults or partial validation |
| Code compiles differently across files | Flag missing from some build configurations or dependencies | Define it in every translation unit of the fuzzing build |
| Cannot reproduce production bugs | Fuzzing build diverges too much | Minimize patches; keep state-critical validation |

For a direct Clang build, inspect macros with an executable command such as
`clang -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -dM -E -x c /dev/null`.
Use the actual build's flags rather than adding the define only to this check.
When triaging a crash, repair unkeyed checksums before production replay. A keyed
MAC or signature requires a separate attacker-capability analysis, not a blanket
false-positive label.

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

Additional references: [AFL++ instrumentation options](https://aflplus.plus/docs/fuzzing_in_depth/),
[cargo-afl build flags](https://github.com/rust-fuzz/afl.rs/blob/master/cargo-afl/src/main.rs),
[Rust check-cfg](https://doc.rust-lang.org/rustc/check-cfg.html).
