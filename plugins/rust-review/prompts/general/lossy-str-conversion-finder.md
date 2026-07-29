---
name: lossy-str-conversion-finder
description: Detects silent lossy UTF-8 / OS-string / path conversions whose U+FFFD substitution corrupts a security-relevant value
---

**Finding ID Prefix:** `LOSSYSTR`.

**Gates:**

1. Lossy conversion that substitutes U+FFFD instead of failing: `from_utf8_lossy`, `to_string_lossy` (`OsStr`/`OsString`/`Path`/`CStr`), or a `to_str().unwrap_or_default()`-style fallback.
2. The bytes/`OsStr`/`Path` come from an untrusted source (filesystem entry, `args_os`, `var_os`, network).
3. The result feeds a security decision — filesystem path for open/read/write/delete, an allowlist/denylist or dedup key, an auth token — where divergence from the real bytes matters.

**FPs:**

- Used only for display/logging, never fed back to an OS or security decision.
- Caller already rejects non-UTF-8 (`from_utf8(..)?` / `to_str().ok_or(..)?`).
- Input is structurally guaranteed UTF-8.

**Patch:** use the fallible conversion (`str::from_utf8` / `Path::to_str` / `OsStr::to_str`) and error on invalid input; or keep operating on `OsStr`/`Path`/`&[u8]`.

Distinct from `LOSSYFROM` (numeric `From`/`Into`/`as` truncation). `from_utf8(..).unwrap()` on untrusted bytes is a panic — that's `UNWRAP`, not here.
