# DWARF Expert

Interact with and analyze DWARF debug information: parse and search DIEs with
`dwarfdump`/`llvm-dwarfdump` and `readelf`, verify debug info integrity with
`llvm-dwarfdump --verify`, answer questions about the DWARF standard, and write
code that parses DWARF data.

**Author:** Evan Hellman

## What It Does

The skill is a single `SKILL.md` covering:

- Authoritative sources for standard questions: dwarfstd.org, LLVM's
  `lib/DebugInfo/DWARF/`, and libdwarf, looked up on demand rather than answered
  from memory
- An `llvm-dwarfdump` flag reference for dumping, searching (`--find`, `--name`,
  `--lookup`), and displaying DIE trees
- A search-escalation strategy: accelerator-table lookup, exhaustive name search,
  grep pipelines over full dumps, then a `pyelftools` script when pipelines turn
  brittle
- Verification workflows: `--verify` (with `--error-display` and `--verify-json`)
  and `--statistics` for comparing debug-info quality across builds
- Library recommendations for C/C++, Python, Rust, Go, and .NET, plus
  DWARF-specific pitfalls (optional attributes, `DW_AT_abstract_origin` /
  `DW_AT_specification` indirection, type chains)

## Testing

`tests/test_skill_contract.py` extracts every `llvm-dwarfdump` flag the skill
documents and checks it against the real tool's `--help`, and validates the
frontmatter contract (`name`, `description`, `effort`, space-delimited
`allowed-tools`). It fails if the extraction comes back empty or no LLVM
dwarfdump is on PATH — a checker that inspects zero items must not pass.

Requires an LLVM dwarfdump that supports `--error-display` and `--verify-json`
(upstream LLVM 19+; the test checks for the flags themselves rather than a
version string, since Apple's LLVM numbering differs from upstream). macOS:
current Xcode Command Line Tools qualify; Debian/Ubuntu: `apt install llvm-19`
or newer. Run with:

```sh
cd plugins/dwarf-expert/tests
uv run --no-project --with pytest python3 -m pytest -q --import-mode=importlib .
```

## Installation

```
/plugin install trailofbits/skills/plugins/dwarf-expert
```
