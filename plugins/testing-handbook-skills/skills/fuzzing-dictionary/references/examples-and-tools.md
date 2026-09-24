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
this conversion for ordinary C-style literals; it does not preprocess macros,
join adjacent literals, or interpret language-specific string prefixes. Review
those cases in the target source.

```bash
grep -Eo '"([^"\\]|\\.)*"' header.h | sort -u
strings ./binary | sort -u
man curl | grep -Eo -- '--?[A-Za-z0-9][A-Za-z0-9_-]*' | sort -u
```

If a dictionary does not improve reachability, compare coverage with and
without it, then replace irrelevant tokens. Check parser errors for invalid
escapes and keep entries below `-max_len`.

The portable dictionary escapes are `\\`, `\"`, and `\xHH`; C escapes such as
`\n` are rejected by [libFuzzer's dictionary reader](https://llvm.org/docs/LibFuzzer.html#dictionaries).
