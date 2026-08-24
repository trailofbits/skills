# modern-cpp

Modern C++ best practices plugin for Claude Code, guiding AI-assisted development toward C++20/23/26 idioms with a security emphasis from Trail of Bits.

## When to Use

- Writing new C++ code (functions, classes, libraries)
- Modernizing legacy C++ patterns (pre-C++20)
- Working on security-critical C++ code
- Reviewing C++ code for modern idiom adoption
- Choosing between legacy and modern approaches to a problem

## What It Covers

### Language Features (Tiered by Usability)

| Tier | Standard | What |
|------|----------|------|
| Use Today | C++20 | Concepts, ranges, `std::span`, `std::format`, coroutines, `<=>` |
| Use Today | C++23 | `std::expected`, `std::print`, deducing `this`, `std::flat_map` |
| Deploy Now | Any | Compiler hardening flags, sanitizers, hardened libc++ |
| Plan For | C++26 | Reflection (eliminates serialization boilerplate and code generators) |
| Watch | C++26 | Contracts, `std::execution` (promising but needs compiler maturity) |

### Security

- Compiler hardening flags (GCC + Clang, per OpenSSF guidelines)
- Hardened libc++ modes (bounds-checking with ~0.3% overhead)
- Sanitizer setup (ASan, UBSan, TSan, MSan)
- Safe idioms organized by vulnerability class (memory, type, integer, concurrency)

### Anti-Patterns

30+ legacy-to-modern pattern replacements with rationale, covering memory management, type safety, error handling, concurrency, and metaprogramming.

## Installation

```
/plugin marketplace add trailofbits/skills
/plugin install modern-cpp
```
