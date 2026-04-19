# Compiler Hardening

Security-focused compiler and linker configuration for C++ projects. Based on the [OpenSSF Compiler Options Hardening Guide](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html) and Trail of Bits recommendations.

## Essential Compiler Flags

### Warnings

| Flag | Purpose | GCC | Clang |
|------|---------|-----|-------|
| `-Wall` | Core warnings | Yes | Yes |
| `-Wextra` | Additional warnings | Yes | Yes |
| `-Wpedantic` | Strict ISO compliance | Yes | Yes |
| `-Werror` | Treat warnings as errors | Yes | Yes |
| `-Wconversion` | Implicit narrowing conversions | Yes | Yes |
| `-Wsign-conversion` | Signed/unsigned conversion | Yes | Yes |
| `-Wformat=2` | Format string issues | Yes | Yes |
| `-Wunsafe-buffer-usage` | Raw pointer arithmetic | No | Yes |

### Stack Protection

| Flag | Purpose | GCC | Clang |
|------|---------|-----|-------|
| `-fstack-protector-strong` | Stack buffer overflow detection | Yes | Yes |
| `-fstack-clash-protection` | Prevent stack clash attacks | Yes | Yes |

### Fortification

```
-D_FORTIFY_SOURCE=3
```

Adds runtime bounds checks to `memcpy`, `strcpy`, `sprintf`, and other libc functions. Level 3 (GCC 12+, Clang 16+) provides the most coverage.

**Warning:** This flag is silently ignored if optimization is disabled (`-O0`). Always verify it's active:

```bash
# Check that _FORTIFY_SOURCE is defined in preprocessor output
echo '#include <stdio.h>' | gcc -E -dM -D_FORTIFY_SOURCE=3 -O2 - | grep FORTIFY
```

Trail of Bits found [20+ projects on GitHub](https://blog.trailofbits.com/2023/04/20/typos-that-omit-security-features-and-how-to-test-for-them/) where `_FORTIFY_SOURCE` was misspelled (e.g., `-FORTIFY_SOURCE=2` instead of `-D_FORTIFY_SOURCE=2`).

### Auto-Initialization

```
-ftrivial-auto-var-init=zero
```

Zero-initializes all local variables that would otherwise be uninitialized. Eliminates information leaks from stack variables at minimal performance cost.

### Position-Independent Code

```
-fPIE -pie              # for executables
-fPIC -shared           # for shared libraries
```

Required for ASLR to work effectively.

### Linker Hardening

| Flag | Purpose |
|------|---------|
| `-Wl,-z,relro` | Read-only relocations (partial RELRO) |
| `-Wl,-z,now` | Immediate binding (full RELRO, protects GOT) |
| `-Wl,-z,noexecstack` | Non-executable stack |

### Control Flow Integrity

```
-fcf-protection=full    # GCC/Clang on x86 (Intel CET)
```

## Hardened libc++ (Clang/libc++)

libc++ provides hardening modes that add bounds-checking to standard containers with minimal overhead.

### Modes

| Mode | Flag | What It Checks | Overhead |
|------|------|---------------|----------|
| Fast | `_LIBCPP_HARDENING_MODE_FAST` | Bounds on `[]`, `front()`, `back()` | ~0.3% |
| Extensive | `_LIBCPP_HARDENING_MODE_EXTENSIVE` | Fast + iterator validity, internal invariants | Higher |
| Debug | `_LIBCPP_HARDENING_MODE_DEBUG` | All checks including O(n) validations | Significant |

### How to Enable

```
-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST
```

### Recommendation

- **All builds**: Enable `_FAST` mode — Google measured 0.3% overhead across their fleet
- **Security-critical code**: Enable `_EXTENSIVE` mode
- **Development/testing**: Enable `_DEBUG` mode

### Google's Results

Deployed across Chrome (2022) and entire server fleet:
- ~0.3% average performance overhead
- 1000+ previously undetected bugs found
- 30% reduction in production segfault rate

## Sanitizers

Runtime instrumentation for detecting bugs that static analysis misses.

### AddressSanitizer (ASan)

Detects: heap/stack buffer overflow, use-after-free, double-free, memory leaks.

```
-fsanitize=address -fno-omit-frame-pointer
```

Overhead: ~2x slowdown, ~3x memory. Use in CI, not production.

### UndefinedBehaviorSanitizer (UBSan)

Detects: signed integer overflow, null pointer dereference, division by zero, misaligned access, out-of-bounds array access.

```
-fsanitize=undefined -fno-sanitize-recover=all
```

Overhead: minimal (~5-10%). Safe for most CI runs.

### ThreadSanitizer (TSan)

Detects: data races, lock-order inversions, deadlocks.

```
-fsanitize=thread
```

Overhead: ~5-15x slowdown. Use for concurrent code testing.

### MemorySanitizer (MSan)

Detects: reads of uninitialized memory.

```
-fsanitize=memory -fno-omit-frame-pointer
```

Overhead: ~3x slowdown. Clang-only. Requires all linked code to be instrumented.

### Combining Sanitizers

| Combination | Compatible? |
|-------------|-------------|
| ASan + UBSan | Yes — recommended default |
| ASan + TSan | **No** — mutually exclusive |
| ASan + MSan | **No** — mutually exclusive |
| TSan + UBSan | Yes |
| MSan + UBSan | Yes |

### CI Integration

Recommended CI matrix:

```
1. Build with ASan + UBSan → run all tests
2. Build with TSan → run concurrency tests
3. (Optional) Build with MSan → run all tests (Clang only)
```

### Production: GWP-ASan

For production environments where full ASan is too expensive, use GWP-ASan — a sampling-based allocator that detects heap bugs with near-zero overhead.

- Enabled by default in Chrome, Android, Apple platforms
- Catches use-after-free and buffer overflow in production
- See [Trail of Bits guide to GWP-ASan](https://blog.trailofbits.com/2025/12/16/use-gwp-asan-to-detect-exploits-in-production-environments/)

## Verifying Hardening

Don't trust that flags are applied — verify the binary:

### checksec

```bash
checksec --file=./my_binary
```

Checks: RELRO, stack canary, NX, PIE, FORTIFY.

### readelf

```bash
# Check for RELRO
readelf -l ./my_binary | grep GNU_RELRO

# Check for stack canary symbols
readelf -s ./my_binary | grep __stack_chk

# Check for FORTIFY
readelf -s ./my_binary | grep _chk
```

### Compiler Explorer

For quick verification during development, compile on [Compiler Explorer](https://godbolt.org/) and inspect the generated assembly for canary checks and fortified function calls.

## Complete Hardened Compilation Example

```bash
# GCC
g++ -std=c++23 \
    -Wall -Wextra -Wpedantic -Werror -Wconversion \
    -D_FORTIFY_SOURCE=3 -O2 \
    -fstack-protector-strong -fstack-clash-protection \
    -ftrivial-auto-var-init=zero \
    -fcf-protection=full \
    -fPIE -pie \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
    main.cpp -o my_binary

# Clang (with hardened libc++)
clang++ -std=c++23 -stdlib=libc++ \
    -Wall -Wextra -Wpedantic -Werror -Wconversion \
    -Wunsafe-buffer-usage \
    -D_FORTIFY_SOURCE=3 -O2 \
    -D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST \
    -fstack-protector-strong -fstack-clash-protection \
    -ftrivial-auto-var-init=zero \
    -fcf-protection=full \
    -fPIE -pie \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
    main.cpp -o my_binary
```

## References

- [OpenSSF Compiler Options Hardening Guide](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html)
- [libc++ Hardening Modes](https://libcxx.llvm.org/Hardening.html)
- [Trail of Bits: Typos That Omit Security Features](https://blog.trailofbits.com/2023/04/20/typos-that-omit-security-features-and-how-to-test-for-them/)
- [Trail of Bits: Use GWP-ASan in Production](https://blog.trailofbits.com/2025/12/16/use-gwp-asan-to-detect-exploits-in-production-environments/)
- [Google: Retrofitting Spatial Safety](https://security.googleblog.com/2024/11/retrofitting-spatial-safety-to-hundreds.html)
