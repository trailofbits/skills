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

## Calcifier recipe for `modern-cpp`

The [`modern-cpp` Python recipe](skills/modern-cpp/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/modern-cpp/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/modern-cpp/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

| Input | Type | Default |
| --- | --- | --- |
| `task` | `str` | Required |
| `project_directory` | `str` | `'.'` |
| `mode` | `Literal['advise', 'review', 'edit']` | `'review'` |
| `targets` | `tuple[str, ...]` | `()` |
