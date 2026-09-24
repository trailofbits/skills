---
name: fuzzing-dictionary
type: technique
description: "Create and validate fuzzing dictionaries for parsers, protocols, binaries, and file formats. Use when a fuzzer needs magic bytes, keywords, or fixed tokens to pass input validation."
---

# Fuzzing Dictionary

Use a dictionary when a target compares input against known tokens. Do not add a
dictionary to a pure algorithm with no format or keyword expectations.

## Dictionary syntax

```conf
# Comments and empty lines are ignored.
kw1="blah"
kw2="\"ac\\dc\""
kw3="\xF7\xF8"
"foo\x0Abar"
```

Each entry is a quoted string or `name="value"`. Escape quotes and backslashes;
use `\xAB` for non-printable bytes, including `\x0A` for a newline. Source-language
escapes such as `\n` are not dictionary escapes.

## Workflow

1. Identify the input format and choose the closest source:

   | Source | Command |
   | --- | --- |
   | Header or source literals | `{baseDir}/scripts/make-dict.sh header SOURCE > dictionary.dict` |
   | Binary strings | `{baseDir}/scripts/make-dict.sh binary BINARY > dictionary.dict` |
   | CLI flags from a man page | `{baseDir}/scripts/make-dict.sh man COMMAND > dictionary.dict` |

   Use the output as a seed. Add format-specific magic bytes, delimiters, and
   boundary values that the source does not expose. Keep the final dictionary
   focused: 50–200 entries.

2. Validate before using it:

   ```bash
   uv run --no-project {baseDir}/scripts/validate-dict.py dictionary.dict --min-entries 50 --max-entries 200
   ```

3. Deliver the `.dict` file and state its entry count. Wire it into the fuzzer
   once: libFuzzer/cargo-fuzz use `-dict=FILE`; AFL++ uses `-x FILE`.

## Important limits

- Entries longer than libFuzzer's `-max_len` are ignored. Keep entries below
  that limit or increase `-max_len` deliberately.
- `afl-clang-lto` can extract comparison tokens itself with
  `AFL_LLVM_DICT2FILE=auto.dict`; review and merge that output rather than
  assuming it covers format magic bytes.
- Do not add duplicate entries, full sentences, or thousands of generic words.

## More detail when needed

- Read [examples-and-tools.md](references/examples-and-tools.md) for example
  dictionaries, per-fuzzer commands, the go-fuzz workaround, and troubleshooting.
- Read [examples-and-tools.md](references/examples-and-tools.md) when a manual
  extraction command is needed instead of the bundled script.
