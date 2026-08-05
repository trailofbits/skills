---
name: constant-time-analysis
description: Detects timing side-channel vulnerabilities in cryptographic code. Use when implementing or reviewing crypto code, encountering division on secrets, secret-dependent branches, or constant-time programming questions in C, C++, Go, Rust, Swift, Java, Kotlin, C#, PHP, JavaScript, TypeScript, Python, or Ruby.
allowed-tools: Bash Read Grep Glob
effort: medium
---

# Constant-Time Analysis

Compile the code, inspect the emitted assembly or bytecode for variable-time instructions, then decide which of the flagged operations actually touch secrets. The compilation step is mechanical; the triage step is the work.

## When to Use

- Implementing or reviewing a signature, encryption, KEM, or key derivation routine
- Code applies `/` or `%` to a value derived from a key, plaintext, nonce, or token
- The user mentions "constant-time", "timing attack", "side-channel", or "KyberSlash"
- Reviewing functions named `sign`, `verify`, `encrypt`, `decrypt`, `derive_key`

## When NOT to Use

- **Measuring** timing variance on a running binary — use the `constant-time-testing` skill from the `testing-handbook-skills` plugin, which covers dudect and statistical approaches and may not be installed. This skill inspects compiler output statically and never executes the code under test.
- Non-cryptographic code, or crypto code where every input is public
- High-level API usage where a vetted library owns the constant-time guarantees
- Cache and other microarchitectural side channels — the assembly view cannot see them

## Language Routing

Read the guide for the target language before interpreting any findings; each one lists that language's dangerous instructions and the idiomatic constant-time replacements.

| Guide | Languages |
| ----- | --------- |
| [references/compiled.md](references/compiled.md) | C, C++, Go, Rust |
| [references/swift.md](references/swift.md) | Swift |
| [references/vm-compiled.md](references/vm-compiled.md) | Java, C# |
| [references/kotlin.md](references/kotlin.md) | Kotlin |
| [references/php.md](references/php.md) | PHP |
| [references/javascript.md](references/javascript.md) | JavaScript, TypeScript |
| [references/python.md](references/python.md) | Python |
| [references/ruby.md](references/ruby.md) | Ruby |

## Running the Analyzer

The analyzer takes one file and detects the language from its extension. **Always pass `--warnings`:**

```bash
uv run {baseDir}/ct_analyzer/analyzer.py --warnings <source_file>
```

Without it the analyzer reports only error-severity findings, which means division, modulo and weak RNG. Four detector families are warning severity and stay silent: secret-dependent branches, early-exit comparison (`memcmp`, `strcmp`, `.equals`, `==`), table lookups indexed by a secret, and variable-time encoding. Early-exit comparison of an authentication tag is the most common timing bug in real code — Lucky Thirteen was exactly that — so a default run is quiet about the finding you are most likely to have.

| Flag | Effect |
| ---- | ------ |
| `--warnings` | Add the four warning-severity families above. Pass it every time |
| `--func <regex>` | Restrict output to function names matching the regex |
| `--json` | Machine-readable output |
| `--github` | GitHub Actions annotations |
| `--arch <target>` | Target architecture (`x86_64`, `arm64`, `riscv64`, ...) — native languages only |
| `--opt-level <level>` | Optimization level (`O0` through `O3`, `Os`, `Oz`) — native languages only |
| `--compiler <name>` | Override compiler choice (`gcc`, `clang`, `go`, `rustc`, `swiftc`) |

Narrow a large file to the routines that handle secrets with a regex, for example `--func 'sign|verify'`.

**Run natively compiled code (C, C++, Go, Rust, Swift) at more than one `--arch` and `--opt-level`.** Division timing and branch lowering are architecture- and optimization-dependent: x86_64 `IDIV` and arm64 `SDIV` differ, and a `cmov` at `-O2` can become a branch at `-O0`. A single clean run proves one configuration safe, not the code.

**How `--arch` crosses depends on the toolchain.** clang crosses with `--target` and needs no second compiler, but any source that includes libc headers also needs that target's C library headers — `libc6-dev-riscv64-cross` and friends — or it fails with `bits/libc-header-start.h file not found`. Go cross-builds through `GOARCH`, though `go tool objdump` has no riscv64 disassembler. A GNU cross toolchain is a *separate binary*, so gcc needs it named explicitly — `--compiler x86_64-linux-gnu-gcc`, `--compiler riscv64-linux-gnu-gcc` — and nothing is substituted for you, so the report always names the binary that ran. rustc needs the target's standard library (`rustup target add`), and Swift on Linux targets only the host. Compare against the toolchain that builds your product, not whichever cross build a distribution packages.

**Re-run the whole sweep on the fix, across compilers, targets and every level including `Os` and `Oz`.** Any fix that works by handing the compiler a constant divisor to strength-reduce is a fix only where the compiler chooses to cooperate, and that choice varies more than it looks. Replacing `key_coef / (2 * gamma2)` with a `#define`d divisor still emits a real divide here:

| Toolchain | Levels that emit a division |
| --------- | --------------------------- |
| gcc riscv64 | `O0` through `Oz` — every level |
| gcc arm64, gcc x86_64 | `Os`, `Oz` |
| clang arm64 | `O0`, `Oz` |

Strength reduction is an optimizer courtesy, not a language guarantee. Prefer an explicit multiply-shift, and verify it against the original expression over the full input range rather than on sampled values — an off-by-a-power-of-two reciprocal matches for millions of inputs before it diverges.

Java, Kotlin, and C# compile to JVM/CIL bytecode. The analyzer reads that bytecode, so `--arch` and `--opt-level` do not apply and the JIT may still introduce variable-time native code the analyzer cannot see.

### Per-language coverage limits

Coverage is not uniform, and the gaps change what a clean report means:

| Language | What the report does not cover |
| -------- | ------------------------------ |
| Go | Only symbols from the analyzed file. `go build` links the runtime in, and its divisions — all on public data — would otherwise dominate the findings |
| JavaScript, TypeScript | Bytecode findings are restricted to functions the file declares by name, because V8 dumps node's internals the same way it dumps yours. Anonymous callbacks fall to the source scan. For TypeScript, bytecode findings name the function but carry no line, since V8's positions index the transpiled output |
| Python, Ruby, PHP | Bytecode reflects the interpreter that ran, not a JIT'd or alternative runtime |
| Rust | Analyzed as a library unless the file declares `fn main`; private functions with no caller may be optimized away before analysis |
| Swift | Targets the host platform on Linux; iOS and macOS triples need an Apple toolchain |

Since findings and silence both depend on the configuration, say which compiler, architecture, and optimization level produced a result when reporting it.

To sweep a directory, loop in the shell — the analyzer is a deterministic script, one invocation per file:

```bash
for f in src/crypto/*.c; do uv run {baseDir}/ct_analyzer/analyzer.py --warnings --json "$f"; done
```

### Prerequisites

| Language | Requirement |
| -------- | ----------- |
| C, C++, Go, Rust | `gcc`/`clang`, `go`, `rustc` in PATH |
| Swift | Xcode or Swift toolchain (`swiftc`) |
| Java / Kotlin | JDK (`javac`, `javap`); Kotlin also needs `kotlinc` |
| C# | .NET SDK plus `ilspycmd` (`dotnet tool install -g ilspycmd`) |
| PHP | PHP with the VLD extension or OPcache |
| JavaScript / TypeScript | Node.js |
| Python | Python 3.x |
| Ruby | Ruby with `--dump=insns` support |

On a "toolchain not found" error, see [references/vm-compiled.md](references/vm-compiled.md) for JVM and .NET installation, macOS keg-only PATH configuration, and troubleshooting.

## Interpreting Results

**PASSED** — no *error*-severity finding for the configuration you ran. Warnings do not affect it, so `Result: PASSED` alongside `Warnings: 6` is normal and is not a clean result. Read the warning list before concluding anything.

**FAILED** — dangerous instructions found, reported per function:

```text
[ERROR] SDIV
  Function: decompose_vulnerable
  Reason: SDIV has early termination optimization; execution time depends on operand values
```

## Triaging Findings

**The analyzer has no data flow analysis. It flags every dangerous instruction regardless of whether a secret reaches it, so a FAILED report is a worklist, not a verdict.** Reporting the raw output as a set of vulnerabilities is the primary failure mode of this skill.

For each flagged instruction, read the source and answer one question: **does an operand depend on secret data?** Trace from the instruction's function back to the caller's inputs, then classify:

```c
// FALSE POSITIVE: operands are a buffer length, already public from the ciphertext size
int num_blocks = data_len / 16;

// TRUE POSITIVE: dividend is a private-key coefficient; IDIV/SDIV leaks its magnitude
int32_t q = secret_coef / GAMMA2;
```

| Question | If yes |
| -------- | ------ |
| Is the operand a compile-time constant? | Likely false positive |
| Is the operand a public parameter — length, count, index bound? | Likely false positive |
| Is the operand derived from a key, plaintext, nonce, or token? | **True positive** |
| Can an attacker influence the operand's value? | **True positive** |

State the verdict and the data flow that justifies it for every flagged item. A finding you cannot trace to a secret is not a finding; say so explicitly rather than dropping it silently.

`{baseDir}/ct_analyzer/tests/triage_samples/` holds a known-answer case per language: each fixture pairs a true positive with a false positive that the analyzer reports identically, and `expectations.json` records which is which and why. `triage_c.c` is the shortest example — the analyzer flags the division in both `ct_high_bits` and `ct_block_count`, and correct triage confirms the first and clears the second.

**Weak-RNG and encoding findings ask a different question.** For `Math.random`, `mt_rand`, `random.randint`, `System.Random` and `base64_encode`, no operand is secret, so "does an operand depend on a secret?" does not resolve them. Ask instead what the result is used for: seeding a nonce or key is a true positive, jittering a retry delay is not. These are reported by a regex scan over the source rather than from bytecode, so they are attributed to `<source>` with a line number instead of to the enclosing function — except in PHP, where they carry the function.

**Comparison and lookup findings have their own question, and their own fix.** For an early-exit comparison, ask whether either side is secret: comparing an authentication tag, MAC, or password hash is a true positive, comparing a public protocol header is not. For a table lookup, ask whether the *index* is secret — the array's contents do not matter, only what selects the element. Both are exploitable as written, so a confirmed one needs the language's constant-time primitive rather than a rewrite of the loop:

| Language | Constant-time comparison |
| -------- | ------------------------ |
| C, C++ | `CRYPTO_memcmp` (OpenSSL) or `sodium_memcmp` |
| Go | `crypto/subtle.ConstantTimeCompare` |
| Rust | the `subtle` crate's `ConstantTimeEq` |
| Java, Kotlin | `MessageDigest.isEqual` |
| C# | `CryptographicOperations.FixedTimeEquals` |
| PHP | `hash_equals` |
| Python | `hmac.compare_digest` |
| Ruby | `OpenSSL.secure_compare` |
| JavaScript, TypeScript | `crypto.timingSafeEqual` |

A secret-indexed lookup has no drop-in replacement: it needs a bit-sliced or arithmetic formulation that touches every element, which is why AES S-box tables are the classic case. Encoding a secret through a table — `base64_encode`, `bin2hex`, `chr`/`ord` — is the same problem in a library, and `paragonie/constant_time_encoding` is the reference fix for PHP.

## Limitations

1. **Static only** — reads assembly and bytecode, never runtime behavior. Cache timing and other microarchitectural channels are invisible.
2. **No data flow analysis** — see triage above.
3. **Configuration-specific** — a different compiler, optimization level, architecture, or runtime version can emit different instructions from identical source.

## Real-World Impact

- **KyberSlash (2023)** — division instructions in ML-KEM implementations allowed key recovery
- **Lucky Thirteen (2013)** — timing differences in CBC padding validation enabled plaintext recovery
- **RSA timing attacks** — early implementations leaked private key bits through division timing

## References

- [Cryptocoding Guidelines](https://github.com/veorq/cryptocoding) — defensive coding for crypto
- [KyberSlash](https://kyberslash.cr.yp.to/) — division timing in post-quantum crypto
- [BearSSL Constant-Time](https://www.bearssl.org/constanttime.html) — practical constant-time techniques
