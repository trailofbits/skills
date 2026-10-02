---
name: fuzzing-dictionary
type: technique
description: "Creates and validates fuzzing dictionaries for libFuzzer, AFL++, and cargo-fuzz. Use for parsers, protocols, binaries, file formats, or coverage plateaus caused by missing magic bytes and keywords."
---

# Fuzzing Dictionary

## When to Apply

Use a dictionary when a target compares input against known tokens. Do not add a
dictionary to a pure algorithm with no format or keyword expectations.

## Quick Reference

```conf
# Comments and empty lines are ignored.
kw1="blah"
kw2="\"ac\\dc\""
kw3="\xF7\xF8"
"foo\x0Abar"
```

Each entry is a quoted string, `name="value"`, or `name@level="value"`. Escape quotes and backslashes;
use `\xAB` for non-printable bytes, including `\x0A` for a newline. Source-language
escapes such as `\n` are not dictionary escapes.

## Workflow

1. Identify the input format and choose the closest source:

   | Source | Command |
   | --- | --- |
   | C/C++ header or source literals | `{baseDir}/scripts/make-dict.sh header SOURCE > dictionary.dict` |
   | Binary strings | `{baseDir}/scripts/make-dict.sh binary BINARY > dictionary.dict` |
   | CLI flags from a man page | `{baseDir}/scripts/make-dict.sh man COMMAND > dictionary.dict` |

   First check the curated dictionaries in [AFL++](https://github.com/AFLplusplus/AFLplusplus/tree/stable/dictionaries)
   and the matching [OSS-Fuzz project](https://github.com/google/oss-fuzz/tree/master/projects).
   Use extracted output as a seed, not a complete format description. Add relevant
   magic bytes, delimiters, and boundary values. A small dictionary is valid;
   do not pad it to meet an arbitrary minimum. Start focused and measure coverage.
   Extraction exit 2 means partial output: retain the good entries, inspect every
   `# PARTIAL` source-line diagnostic, and resolve it before delivery. Exit 1 means
   no usable entries or an input error. Never hide either status with `|| true`.

2. Validate before using it:

   ```bash
   uv run --no-project {baseDir}/scripts/validate-dict.py dictionary.dict --backend libfuzzer
   ```

3. Deliver the `.dict` file and state its entry count and selected backend.
   Run the fuzzer with that file and compare coverage against a no-dictionary run.

## Tool-Specific Guidance

- libFuzzer/cargo-fuzz use `-dict=FILE`; AFL++ uses `-x FILE`.
- The helpers default to libFuzzer's 64-byte token limit. For AFL++'s 128-byte
  limit, pass `--backend afl++` to both extraction and validation. Length is
  measured after decoding escapes. `-max_len` controls inputs, not this limit.
  Do not silently truncate an overlong token: review useful shorter tokens or
  place the full value in the seed corpus.
- AFL++ LLVM instrumentation supports `AFL_LLVM_DICT2FILE=/absolute/auto.dict`;
  review and merge that output rather than
  assuming it covers format magic bytes.
- Do not add duplicate entries, full sentences, or thousands of generic words.

## More detail when needed

- Read [examples-and-tools.md](references/examples-and-tools.md) for examples,
  per-fuzzer commands, extraction limitations, the go-fuzz workaround, or troubleshooting.

## Related Skills

- **libfuzzer**, **aflpp**, and **cargo-fuzz** cover the corresponding fuzzer setup.
- **coverage-analysis** measures whether a dictionary improves reachability.
- **harness-writing** helps the target consume the supplied tokens correctly.
