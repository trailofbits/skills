# Prompt: Go constant-time analyzer benchmarking

Paste this whole file into a fresh Claude Code session whose working
directory is the root of this `skills` repository (the one containing
`plugins/constant-time-analysis/`).  Branch off `main` before starting.

---

## Goal

Apply the same evaluation rigor we already applied to the C/C++ version of
this analyzer (BoringSSL, OpenSSL, libsodium, mbedTLS) to **Go** crypto
code.  The four artefacts to produce are direct analogues of the C ones:

  - `benchmark/GO_MECHANICAL_EVAL.md`  - curated mechanical triage
  - `benchmark/GO_V2_DESIGN.md`        - filter improvement loop
  - `benchmark/GO_V3_DWARF.md`         - source attribution from Go DWARF
  - `benchmark/results/wild_<repo>_v3.json` for each production target

Read these as templates before starting:

  * `plugins/constant-time-analysis/benchmark/MECHANICAL_EVAL.md`
  * `plugins/constant-time-analysis/benchmark/V2_DESIGN.md`
  * `plugins/constant-time-analysis/benchmark/V3_DWARF.md`
  * `plugins/constant-time-analysis/benchmark/WILD_EVAL.md`

The CT-AFI metric, the filter framework (`ct_analyzer/filters.py`), and
the harnesses (`benchmark/scripts/run_benchmark.py`,
`benchmark/scripts/run_wild.py`) all already exist.  You are extending,
not re-creating.

## Phase 0: Confirm what's already there

The analyzer's `GoCompiler` class is in `ct_analyzer/analyzer.py`; it
builds a binary with `go build` and disassembles via `go tool objdump`.
The single curated Go file
(`ct_analyzer/tests/test_samples/decompose_vulnerable.go`) exists but
isn't integrated into the benchmark corpus.

Run:

```bash
PYTHONPATH=. python3 ct_analyzer/analyzer.py --warnings ct_analyzer/tests/test_samples/decompose_vulnerable.go
```

to confirm the Go path produces output.  If the Go binary path picks up
runtime symbols polluting the report, narrow the disassembly to package
code (see "Pitfalls" below).

## Phase 1: curated Go corpus + first numbers

Build a 12-15 item Go corpus under
`plugins/constant-time-analysis/benchmark/corpus_go/` with the same
three categories as the C one:

  1. **clean** (intentionally CT, expect 0 findings):
     - `crypto/subtle.ConstantTimeCompare` and friends
       (`ConstantTimeSelect`, `ConstantTimeByteEq`, `ConstantTimeEq`,
       `ConstantTimeLessOrEq`)
     - ChaCha20 quarter-round (ARX, no branches on secrets)
     - HKDF / HMAC update loops over public-length input
     - `crypto/cipher` mode wrappers operating on pre-validated lengths
     - `golang.org/x/crypto/curve25519` field arithmetic (when extracted
       to a standalone `.go`)

  2. **vulnerable** (planted CT bugs, must detect):
     - **KyberSlash analogue**: `q := secretCoef / GAMMA2`
     - **Lucky13 analogue**: padding-loop bound is secret-derived
     - **Naive RSA modexp**: branch on `if exp & 1 == 1` per bit of secret exponent
     - **Naive MAC compare**: `if bytes.Equal(computedMac, receivedMac)`
       (this is documented as constant-time in Go since 1.4 but lots of
       legacy code uses `==` on byte slices, which IS variable-time and
       compiles to a memequal call with early exit; both patterns
       deserve detection)
     - **Naive `==` on byte slices**: `if computedMAC == expectedMAC`
       where the slices are convertible to arrays (Go won't compile
       `[]byte == []byte`, but `[16]byte == [16]byte` does compile and
       is variable-time)

  3. **limitation_no_signal**:
     - AES T-table style (cache-timing) - tool can't see this; document it

Each `.go` file must `go build` standalone.  Use a bare `package main`
with a `main()` that calls every function so they don't get DCE'd.

Write `benchmark/corpus_go/manifest.json` with the same schema as the C
corpus: per-file `label` + `ground_truth_violations` list with `line`
+ `kind`.

## Phase 2: baseline metric + curated benchmark

Extend `benchmark/scripts/run_benchmark.py` to support
`--corpus-dir benchmark/corpus_go --manifest benchmark/corpus_go/manifest.json`
(it should already work; the harness is corpus-agnostic).

```bash
PYTHONPATH=. python3 benchmark/scripts/run_benchmark.py \
  --warnings --opt O0 --opt O2 --opt O3 --filter all --smart-fusion \
  --corpus-dir benchmark/corpus_go \
  --manifest benchmark/corpus_go/manifest.json \
  --label go_baseline --out benchmark/results/go_00_baseline.json
```

Note: Go's optimisation levels are `-N -l` (disable opts) at "O0" and
default at higher levels.  The analyzer's `GoCompiler` already maps
this; verify by looking at the produced asm.  If "O2" and "O3" produce
identical disassembly, that's expected - report against O0 and the
default opt.

## Phase 3: improvement loop with held-out validation

Same arc as the C version (read `V2_DESIGN.md`).  The filter framework
in `ct_analyzer/filters.py` already exists; you are adding Go-specific
patterns to the existing `CT_FUNCTION_PATTERNS` list, not creating a
new module.

For Go specifically, the allowlist patterns to add:

  - `crypto/subtle.*` family (full module path appears in Go disassembly)
  - `crypto/internal/edwards25519.*` (CT-coded by design)
  - `crypto/internal/nistec.*` (uses `*Field` types with CT operations)
  - `golang.org/x/crypto/curve25519.*`
  - `crypto/cipher.*` (the public-protocol layer)
  - `runtime.memequal` (Go's implementation IS constant-time per the
    runtime contract - DON'T flag, but also DON'T blanket-allowlist
    callers; the `==` semantic on `[N]byte` arrays compiles to it and
    is the CT path; the early-exit version is `bytes.Equal` which IS
    NOT constant-time despite popular belief - confirm against the
    Go source before allowlisting)
  - `crypto/elliptic.*Marshal*` / `*Unmarshal*` (DER-style codecs)

**Iterate carefully** with the curated regression check after every
filter change.  Two regression traps from the C version that apply
directly to Go:

  - Over-broad `*_validate_*` patterns suppressing real CT functions
    (Lucky13 case)
  - Extending `non-secret` to errors in a way that suppresses legitimate
    documented variable-time helpers reachable from secret-handling
    callers (mbedtls_mpi_mod_int case).  The Go analogue is
    `math/big.Int.Mod` and `math/big.Int.ModInverse` - documented
    variable-time, called from secret-handling crypto paths in legacy
    code; the v1 RSA implementation in Go's crypto/rsa used these
    before the consttime path was introduced.

Track the trajectory in `benchmark/results/go_trajectory.jsonl`.

Target curated F1 0.85+ before moving on.

## Phase 4: wild benchmark on production code

Pick **three** Go production codebases.  Recommended:

  - `golang/go` standard library `crypto/*` (especially `crypto/rsa`,
    `crypto/ecdsa`, `crypto/internal/edwards25519`, `crypto/aes`,
    `crypto/sha256`).  Build with `go build std` to produce
    archive files with DWARF.
  - `golang.org/x/crypto` (the extended crypto packages: `chacha20poly1305`,
    `nacl/box`, `curve25519`, `bn256`, `salsa20`)
  - `cloudflare/circl` (Cloudflare's research crypto library, includes
    post-quantum candidates - excellent for testing because it has both
    intentionally-CT code AND research code with known timing leaks)

Optionally substitute `filippo.io/edwards25519` (small, focused, very
clean) or `tink/go` (Google's Tink in Go, used in production).

For each:

```bash
mkdir -p benchmark/wild_go && cd benchmark/wild_go
git clone --depth=1 <repo-url>
cd <repo>
go build -gcflags="all=-N -l -dwarflocationlists=true" ./...
```

Note: Go's standard build already includes DWARF.  The
`-dwarflocationlists=true` flag improves attribution accuracy.

The disassembly path is different from C: Go produces single binaries
or archives, not per-`.c` `.o` files.  You have two options:

  **Option A** (simpler): build to a binary, disassemble the whole thing
  with `go tool objdump -s '<package-path>' <binary>` and treat each
  package's symbols as a logical "object".  Filter symbols by package
  prefix to get per-package totals.

  **Option B** (fancier): build with `go build -work` to retain the
  intermediate `.a` archives in `$WORK/.../`, then `objdump -d` those.
  More invasive; only use if Option A misses too many symbols.

Either way, **add a build-validity precondition** matching the C
version's: refuse to print headlines when `n_objects == 0` or
`n_instructions < 1000`.  Go's silent-failure mode is a missing
GOPATH or a broken module cache; equivalent to the C silent-submodule
failure.

## Phase 5: mechanical triage

Same approach as the C wild eval (`WILD_EVAL.md`):

  1. Triage **all** errors finding-by-finding.  Read the source.
     Classify each as TP / FP-public / FP-doc / FP-loop.
  2. Sample **30 warnings** with a fresh seed (use `seed=44` to match
     the C v3 numbering convention).  Triage each.

Look for:
  - Function naming: Go uses `package.Func` and `package.(*Type).Method`
    in symbols.  The package path tells you what stratum (e.g.
    `crypto/subtle` = intentional CT, `encoding/asn1` = public protocol,
    `math/big` = variable-time-by-design).
  - Test files: skip anything in `_test.go`, `*/internal/test/*`,
    `*/example/*`, `*/cmd/*`.
  - Generated files: Go has many `*_amd64.s` hand-written assembly
    files.  These don't go through the parser easily; the analyzer's
    Go path uses `go tool objdump` which handles them.

## Phase 6: write up + commit

Three writeups, mirroring the C ones:

  - `benchmark/GO_MECHANICAL_EVAL.md` (curated triage at the best v3 config)
  - `benchmark/GO_V2_DESIGN.md` (the filter improvement trajectory)
  - `benchmark/GO_V3_DWARF.md` (source attribution + final numbers)

Each commit message should report curated F1, wild totals, error TP/FP,
and triage-time savings vs unfiltered baseline.  Push to a feature
branch, do not open a PR unless asked.

## Pitfalls specific to Go (read before starting)

1. **`bytes.Equal` IS variable-time despite popular belief.**  The Go
   stdlib documentation suggests it but does NOT promise constant time.
   The implementation in `runtime/slice.go` calls `memequal_varlen`
   which has an early exit.  If your wild eval doesn't flag any
   `bytes.Equal` calls on secret-named arguments, you have a recall
   problem.  The CT-correct API is `crypto/subtle.ConstantTimeCompare`.
   Source-level `memcmp-source` filter must include `bytes.Equal` and
   `bytes.Compare` along with the C ones.

2. **`runtime.memequal` (used by `==` on byte arrays) IS constant-time.**
   That contract is in `runtime/asm_amd64.s` for amd64.  But this
   creates an asymmetry: `[16]byte == [16]byte` is CT, but `bytes.Equal(a,b)`
   on the same data is not.  Most Go programmers don't know this.  The
   filter should NOT allowlist `runtime.memequal` callers blindly,
   because in production the slice version is more common.

3. **Go's symbol names embed the full package path.**  Symbols look like
   `crypto/sha256.(*digest).Write` or `crypto/internal/edwards25519.fieldElement.Multiply`.
   The allowlist regexes need to handle the slash and parens.  Also
   `(*Type)` for methods on pointer receivers.

4. **Go optimisation is much simpler than LLVM.**  There's no
   `O2` / `O3` distinction; the compiler has one optimisation pipeline,
   gated only by `-N` (disable inlining) and `-l` (disable inlining
   helper).  The smart-fusion model still applies: errors any-O,
   warnings only at default opt.

5. **Goroutine / runtime symbols flood the disassembly.**  When you
   disassemble a Go binary, you get not just the package code but the
   entire Go runtime, gc, scheduler, channel ops, etc.  The harness
   must filter symbols by package prefix; otherwise wild totals
   include the runtime's `runtime.gcStart` etc which have variable-time
   ops by design.  Add a `--symbol-prefix crypto/,golang.org/x/crypto/`
   flag or equivalent.

6. **DWARF is on by default.**  `go tool objdump -l` exists and gives
   `file:line` per instruction.  Use it.  The C wild eval was caught
   off guard by missing `-l`; for Go, the equivalent is making sure
   the Go disassembler path actually consumes the DWARF.

7. **Go's `crypto/subtle` is the universal CT vocabulary.**  The
   allowlist for Go is much smaller than C precisely because the
   stdlib funnels everything through `crypto/subtle`.  If you find
   yourself needing to allowlist 70 patterns like the C version, you've
   probably misunderstood something - more likely you only need 10-15
   patterns (subtle + a handful of internal/* paths).

8. **Method receivers vs free functions.**  In disassembly,
   `crypto/cipher.streamWriter.Write` and
   `crypto/cipher.(*streamWriter).Write` are different symbols.  The
   regex must accept both.

## What success looks like

Curated F1 within 0.05 of the C number (so 0.80 - 0.90).  Wild totals
showing >50% reduction from unfiltered baseline after applying the
filter set.  At least one TP found in the wild that survives expert
triage - candidates I'd specifically check:

  - Pre-Go-1.20 `crypto/rsa` decryption code paths if you build against
    an older release tag (Go's RSA had documented timing leaks in
    `decryptPKCS1v15` that were addressed but the historical pattern
    is instructive).
  - `bytes.Equal` calls in `crypto/tls` MAC verification paths (most
    have been migrated to `subtle.ConstantTimeCompare` but not all).
  - `math/big.Int.Exp` and `.ModInverse` callers - these are documented
    variable-time and the analyzer should flag every reachable use.

If the wild evaluation finds zero TPs, that is itself a finding -
report it with the same framing the C eval used: "the population is
CT-clean and the tool agrees by way of a 100% noise-bound."

Mechanical triage of all errors plus a 30-warning held-out sample is
non-negotiable.  Report back with the four artefact paths, the headline
numbers, and any regressions the curated benchmark caught during the
loop.
