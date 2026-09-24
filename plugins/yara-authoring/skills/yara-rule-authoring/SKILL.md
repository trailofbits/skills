---
name: yara-rule-authoring
description: "Writes or reviews YARA-X detection rules for malware, threat hunting, IOCs, Chrome extensions, Android DEX, and legacy-rule migration. Use for .yar or .yara files, YARA-X validation, false-positive reduction, and rule performance."
---

# YARA-X Rule Authoring

Write narrow rules that survive goodware testing. This skill targets YARA-X;
use `yr`, not legacy YARA syntax as the authority.

## Authoring procedure

1. Start with multiple representative samples. Identify family-specific strings
   or structural signals; do not use generic APIs, paths, or one-sample traits.
   For packed samples, unpack first or deliberately target the packer itself.
   If strings provide no distinctive evidence, consider section structure,
   import hashes, entropy, or metadata; acknowledge when YARA cannot distinguish
   the target. Use modules for complex structure and byte reads for simple magic.
2. Add a descriptive name and metadata: `description` starts with `Detects`,
   then `author`, `reference`, and `date`. Use the naming convention in
   [style-guide.md](references/style-guide.md).
3. Put cheap checks first: `filesize`, magic bytes, strings, then modules or
   loops. Use `all of` when common indicators need corroboration.
4. Use 4+ byte strings with good atoms. Regexes need a literal anchor and
   bounded quantifiers such as `.{0,30}`, never `.*` or `.+`.
   Add `nocase` or `wide` only when sample evidence requires them.
5. Run the bundled review before manual inspection of an existing rule, and
   after changes during authoring:

   ```bash
   bash "{baseDir}/scripts/review.sh" rule.yar > review.json
   ```

   The JSON retains every check's complete output and exit status. Fix `E###`
   errors first; quote coded findings as `CODE file:line message` where the
   tool supplies a location. Also explain judgments the tools cannot make:
   whether the strings identify this family and whether generic strings alone
   can trigger the condition. Run `yr scan` against known-malicious samples
   and a goodware corpus before deployment; state when either corpus is unavailable.

The helper accepts a file or directory and requires Bash, `jq`, `uv`, and
the YARA-X `yr` CLI. It checks directories recursively without modifying rules.
The existing `yara_lint.py` and `atom_analyzer.py` commands remain available
separately; see [Scripts](../../README.md#scripts).

## Rationalizations to Reject

| Reject or change | Required replacement |
| --- | --- |
| Generic APIs, common paths, or strings under four bytes | A family-specific marker or structural signal |
| `any of` common strings | `all of` grouped evidence plus a unique marker |
| Unbounded regex | A literal-anchored, bounded regex or hex pattern |
| Module condition before a cheap check | `filesize` or magic-byte prefilter first |
| `uint32(0) == 0xCAFEBABE` for bytes `CA FE BA BE` | `uint32be(0) == 0xCAFEBABE` or `uint32(0) == 0xBEBAFECA` |

`uintNN()` is little-endian. ZIP/OOXML bytes `50 4B 03 04` require
`uint32(0) == 0x04034B50`. Verify every magic-byte predicate on a known sample.

## Migrating from Legacy YARA

Use `yr check --relaxed-re-syntax rules/` only to diagnose migration problems.
Fix them and rerun normal `yr check`: escape literal regex braces, correct
invalid escapes, remove duplicate modifiers, use 3+ characters with `base64`,
and replace negative indexing. See [style-guide.md](references/style-guide.md)
for compatibility error codes and [rule-development.md](workflows/rule-development.md)
for the validation procedure.

## Checklist

- Name and required metadata are present.
- Strings identify the target family, not a broad category.
- Regexes and loops are bounded.
- Cheap condition checks come first and magic bytes match a known sample.
- `yr check`, `yr fmt --check`, lint, and atom analysis pass.
- Known bad samples match and goodware does not.
- Peer review is complete before deployment.

Read [strings.md](references/strings.md) for difficult string selection,
[performance.md](references/performance.md) for tuning, and
[testing.md](references/testing.md) for corpus testing. Read
[crx-module.md](references/crx-module.md) or [dex-module.md](references/dex-module.md)
only when those modules apply; their version requirements and APIs differ.
Use [rule-development.md](workflows/rule-development.md) for the full process.
The [examples directory](examples/) contains attributed Windows, macOS,
JavaScript, npm, and Chrome extension rules.
