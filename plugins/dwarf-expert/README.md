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

## Calcifier recipe for `dwarf-expert`

The [`dwarf-expert` Python recipe](skills/dwarf-expert/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/dwarf-expert/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/dwarf-expert/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `request` | `str` | Required |
| `mode` | `Literal['inspect', 'verify', 'standard', 'code', 'review']` | `'inspect'` |
| `directory` | `str` | `'.'` |
| `binary_inputs` | `tuple[str, ...]` | `()` |
| `source_inputs` | `tuple[str, ...]` | `()` |
| `reference_inputs` | `tuple[str, ...]` | `()` |
| `section` | `Literal['all', 'info', 'line']` | `'info'` |
| `symbol` | `str` | `''` |
| `program_address` | `str` | `''` |
| `verify_binaries` | `bool` | `False` |
| `statistics` | `bool` | `False` |
| `standard_query` | `str` | `''` |
| `source_urls` | `tuple[str, ...]` | `()` |
| `edit_project` | `bool` | `False` |

The recipe declares `Bash`, `WebSearch`, `WebFetch`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
