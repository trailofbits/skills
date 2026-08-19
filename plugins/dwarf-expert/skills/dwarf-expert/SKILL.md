---
name: dwarf-expert
description: Analyzes DWARF debug information in compiled binaries. Use when inspecting .debug_* sections, DIE trees, or DW_TAG_/DW_AT_ entries with dwarfdump/llvm-dwarfdump or readelf, verifying debug info with llvm-dwarfdump --verify, answering DWARF standard questions, or writing code that parses DWARF (libdwarf, pyelftools, gimli).
effort: medium
allowed-tools: Read Write Edit Bash Grep Glob WebSearch WebFetch
---
# DWARF Expert

Expertise for DWARF debug info: parsing and searching it, verifying its
integrity, answering questions about the standard, and writing code that
consumes it. Out of scope: runtime debugging (use gdb/lldb), reverse
engineering beyond the DWARF sections (use Ghidra/IDA), and compiler-specific
DWARF generation bugs.

# Authoritative Sources

When precision matters, look standard details up instead of answering from memory:

1. **dwarfstd.org** — the official specification. Web-search specific sections,
   e.g. "DWARF5 DW_TAG_subprogram attributes site:dwarfstd.org".
2. **LLVM** — `llvm/lib/DebugInfo/DWARF/` is a reliable reference implementation:
   `DWARFDie.cpp` (DIE and attribute access), `DWARFUnit.cpp` (compilation units),
   `DWARFDebugLine.cpp` (line tables), `DWARFVerifier.cpp` (validation).
3. **libdwarf** — the reference C implementation at github.com/davea42/libdwarf-code.

# Parsing and Searching with dwarfdump

Prefer `dwarfdump` over `readelf` for DWARF-specific work. Two implementations
exist — libdwarf's `dwarfdump` and LLVM's `llvm-dwarfdump` — with different
options, and a bare `dwarfdump` command may be either: check `dwarfdump --version`
first. The options below are LLVM's.

On macOS, linked Mach-O executables do not carry DWARF: it stays in the `.o`
files until `dsymutil` collects it into a `.dSYM` bundle. Point `dwarfdump` at
the dSYM (or the object files), not the executable. `pyelftools` is ELF-only —
for Mach-O scripted work, stay with the LLVM tools.

- `--all`: dump every DWARF section; `--debug-info`, `--debug-line`, etc. dump one
- `--show-children [--recurse-depth=<n>]`: include child DIEs when printing
  selected entries — parameters, locals, and struct members are children of
  function and type DIEs
- `--show-parents [--parent-recurse-depth=<n>]`: include parent DIEs
- `--show-form`: print attribute form types, for when encoding details matter
- `--find=<name>`: exact-name lookup via the accelerator tables — fast but not
  exhaustive; fall back to `--name` when it misses
- `--name=<pattern> [--ignore-case] [--regex]`: exhaustive DIE-name search
- `--lookup=<address>`: find the DIE covering an address
- `--verbose`: print low-level encoding detail

## Searching DIEs

Escalate through these strategies as the query grows more complex:

1. **Name or address match**: `--find`, then `--name`; `--lookup` for addresses.
2. **Attribute or type queries** (e.g. all parameters of type `float *`): dump and
   filter. `grep -B` pulls in the header line carrying each DIE's offset:
   `llvm-dwarfdump file | grep -B 5 "float \*" | grep DW_TAG_formal_parameter`,
   then print each DIE at its offset with `--debug-info=<offset> --show-children`
   (`--lookup` takes a program address, not a DIE offset).
3. **Multi-attribute or structural queries**: when grep pipelines turn brittle,
   write a Python script using `pyelftools` instead.

# Verifying DWARF Integrity

- `llvm-dwarfdump --verify <binary>`: structural checks (unit chains, DIE
  relationships, address ranges). `--error-display=<quiet|summary|details|full>`
  controls detail; `--verify-json=<path>` writes a machine-readable error
  summary; `--quiet` for exit-code-only checks.
- `llvm-dwarfdump --statistics <binary>`: debug-info quality metrics as JSON —
  compare across compiler versions or optimization levels to catch regressions.

Verify after producing DWARF (compilers, binary rewriters), when a debugger
misbehaves on a binary, and when developing DWARF tooling against known-good
files.

When a current-generation compiler emitted an old DWARF version, the build
explicitly passed `-gdwarf-N` — modern gcc and clang default to v4/v5, so check
the build system rather than assuming a toolchain default. GCC embeds its flags
in `DW_AT_producer`, so the pin is often readable right there; clang's producer
string carries no flags. Old versions remain common in the wild and read the
same way apart from surface forms: in v2 output, member offsets appear as
location expressions (`DW_OP_plus_uconst`) and linkage names as
`DW_AT_MIPS_linkage_name`.

# readelf

For general ELF structure, or when `dwarfdump` is unavailable:

- `--debug-dump=<section>`: dump a DWARF section (`info`, `line`, ...)
- `--dwarf-depth=<n>` / `--dwarf-start=<n>`: limit DIE depth / start offset

# Writing Code That Parses DWARF

Prefer an existing library over parsing by hand:

| Library | Language | Notes |
|---------|----------|-------|
| `libdwarf` | C/C++ | github.com/davea42/libdwarf-code — low-level; used to implement `dwarfdump` |
| `pyelftools` | Python | github.com/eliben/pyelftools — also parses ELF in general |
| `gimli` | Rust | github.com/gimli-rs/gimli — pair with `object` to load container files |
| `debug/dwarf` | Go | standard library |
| `LibObjectFile` | .NET | github.com/xoofx/LibObjectFile — also handles ELF/PE object files |

Default to Python with `pyelftools` for one-off scripts unless the task dictates
otherwise.

DWARF-specific pitfalls to handle — and to check for when reviewing DWARF code:

- Attributes are optional: a DIE may omit `DW_AT_name`, `DW_AT_type`, ranges, etc.
- Attribute indirection: a DIE's attributes may live on the DIE referenced by its
  `DW_AT_abstract_origin` (inlined instances) or `DW_AT_specification`
  (out-of-line definitions) — resolve the chain before concluding data is absent.
- Type chains: qualifiers and modifiers (`DW_TAG_const_type`,
  `DW_TAG_pointer_type`, ...) wrap the underlying type; walk `DW_AT_type` links to
  reach the base type.
