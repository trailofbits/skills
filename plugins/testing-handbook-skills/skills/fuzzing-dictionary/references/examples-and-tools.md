# Fuzzing dictionary examples and tool details

## Useful seeds

```conf
# HTTP
"GET"
"POST"
"Content-Type"
"HTTP/1.1"

# PNG
png_magic="\x89PNG\x0D\x0A\x1A\x0A"
ihdr="IHDR"
idat="IDAT"
iend="IEND"
```

For configuration formats, useful seeds include delimiters (`:`, `=`, `{`, `}`),
booleans, section names, and boundary numbers. Prefer target-specific literals
over a large generic word list.

## Fuzzer commands

```bash
# libFuzzer
./fuzz -dict=./dictionary.dict corpus/

# AFL++
afl-fuzz -x ./dictionary.dict -i input/ -o output/ -- ./target @@

# cargo-fuzz
cargo fuzz run fuzz_target -- -dict=./dictionary.dict
```

go-fuzz has no built-in dictionary flag. Convert reviewed entries into seed
files in its corpus instead of passing an unsupported option.

## Manual extraction

These commands collect candidate strings. Convert source-language escapes to
dictionary byte escapes before using them: for example, C `\r\n` becomes
`\x0D\x0A`. Quote and escape binary strings too. The bundled header helper does
this conversion for ordinary C-style literals, preserving original source bytes
even when the file is not UTF-8. It skips comments and character constants. It
does not preprocess macros or join adjacent literals; treat those as candidates,
not a compiler-equivalent interpretation. Raw/prefixed strings, malformed escapes,
and overlong tokens produce source-line diagnostics and a partial (nonzero) status,
while good literals remain available. Review partial results before delivery.

```bash
grep -Eo '"([^"\\]|\\.)*"' header.h | sort -u
strings ./binary | sort -u
man curl | col -b | grep -Eo -- '(^|[[:space:],])--?[A-Za-z0-9][A-Za-z0-9_-]*' | awk '{$1=$1; sub(/^,/, ""); print}' | sort -u
```

If a dictionary does not improve reachability, compare coverage with and
without it, then replace irrelevant tokens. Check parser errors for invalid
escapes and the selected backend's decoded token limit: 64 bytes for libFuzzer,
128 for AFL++. These are not the fuzzer's input `-max_len`. A single useful entry
is valid; empty dictionaries are not. Explicit `--min-entries` / `--max-entries`
are optional project policy, not a parser requirement.

Prefer curated target-specific seeds from AFL++ or OSS-Fuzz before extracting
everything from a binary. For go-fuzz, create one corpus file per decoded entry;
do not copy the dictionary's quotes or escape spellings into corpus files.

The portable dictionary escapes are `\\`, `\"`, and `\xHH`; C escapes such as
`\n` are rejected by [libFuzzer's dictionary reader](https://llvm.org/docs/LibFuzzer.html#dictionaries).
