---
name: yara-rule-authoring
description: >
  Guides authoring of high-quality YARA-X detection rules for malware identification.
  Use when writing, reviewing, or optimizing YARA rules. Covers naming conventions,
  string selection, performance optimization, migration from legacy YARA, and false
  positive reduction. Triggers on: YARA, YARA-X, malware detection, threat hunting,
  IOC, signature, crx module, dex module.
---

# YARA-X Rule Authoring

Write detection rules that catch malware without drowning in false positives.

**This skill targets YARA-X**, the Rust-based successor to legacy YARA — 5-10x faster regex, better errors, built-in formatter, stricter validation, new modules (crx, dex), 99% rule compatibility. It powers VirusTotal's production systems. Install with `brew install yara-x` or `cargo install yara-x`; the CLI is `yr`. See [Migrating from Legacy YARA](#migrating-from-legacy-yara) for existing rules.

## Core Principles

1. **Strings must generate good atoms** — YARA extracts 4-byte subsequences for fast matching. Strings with repeated bytes, common sequences, or under 4 bytes force slow bytecode verification on too many files.

2. **Target specific families, not categories** — "Detects ransomware" catches everything and nothing. "Detects LockBit 3.0 configuration extraction routine" catches what you want.

3. **Test against goodware before deployment** — A rule that fires on Windows system files is useless. Validate against VirusTotal's goodware corpus or your own clean file set.

4. **Short-circuit with cheap checks first** — `filesize` (instant), then magic bytes (nearly instant), then strings (cheap), then modules (expensive).

5. **Metadata is documentation** — Future you (and your team) need to know what this catches, why, and where the sample came from.

## When to Use

- Writing new YARA-X rules for malware detection
- Reviewing existing rules for quality or performance issues
- Optimizing slow-running rulesets
- Converting IOCs or threat intel into detection signatures
- Debugging false positive issues
- Preparing rules for production deployment
- Migrating legacy YARA rules to YARA-X
- Analyzing Chrome extensions (crx module) or Android apps (dex module)

## When NOT to Use

- Static analysis requiring disassembly → use Ghidra/IDA skills
- Dynamic malware analysis → use sandbox analysis skills
- Network-based detection → use Suricata/Snort skills
- Memory forensics with Volatility → use memory forensics skills
- Simple hash-based detection → just use hash lists

## Platform Considerations

YARA works on any file type. Adapt patterns to your target:

| Platform | Magic Bytes | Bad Strings | Good Strings |
|----------|-------------|-------------|--------------|
| **Windows PE** | `uint16(0) == 0x5A4D` | API names, Windows paths | Mutex names, PDB paths |
| **macOS Mach-O** | `uint32(0) == 0xFEEDFACE` (32-bit), `0xFEEDFACF` (64-bit), `uint32be(0) == 0xCAFEBABE` (universal) | Common Obj-C methods | Keylogger strings, persistence paths |
| **JavaScript/Node** | (none needed) | `require`, `fetch`, `axios` | Obfuscator signatures, eval+decode chains |
| **npm/pip packages** | (none needed) | `postinstall`, `dependencies` | Suspicious package names, exfil URLs |
| **Office docs** | `uint32(0) == 0x04034B50` | VBA keywords | Macro auto-exec, encoded payloads |
| **VS Code extensions** | (none needed) | `vscode.workspace` | Uncommon activationEvents, hidden file access |
| **Chrome extensions** | Use `crx` module | Common Chrome APIs | Permission abuse, manifest anomalies |
| **Android apps** | Use `dex` module | Standard DEX structure | Obfuscated classes, suspicious permissions |

> **`uintNN()` reads little-endian.** Write the constant as the bytes *reversed*, or use `uintNNbe()` and write them in file order. A ZIP/OOXML file starts with bytes `50 4B 03 04`, so it is `uint32(0) == 0x04034B50` — `uint32(0) == 0x504B0304` compiles cleanly and never matches anything. The same trap catches Mach-O universal binaries: on disk they are `CA FE BA BE`, so `uint32(0) == 0xCAFEBABE` is a dead branch; write `uint32be(0) == 0xCAFEBABE` or `uint32(0) == 0xBEBAFECA`. Verify with `yr scan` against one known-good sample before trusting any magic-byte check.

### macOS Malware Detection

No dedicated Mach-O module exists yet — use magic bytes plus string patterns. Good indicators:

- Keylogger artifacts: `CGEventTapCreate`, `kCGEventKeyDown`
- SSH tunnel strings: `ssh -D`, `tunnel`, `socks`
- Persistence paths: `~/Library/LaunchAgents`, `/Library/LaunchDaemons`
- Credential theft: `security find-generic-password`, `keychain`

```yara
// Pattern from Airbnb BinaryAlert
rule SUSP_Mac_ProtonRAT
{
    strings:
        $lib1 = "SRWebSocket" ascii          // Library indicators
        $lib2 = "SocketRocket" ascii
        $behav1 = "SSH tunnel not launched" ascii   // Behavioral indicators
        $behav2 = "Keylogger" ascii
    condition:
        (uint32(0) == 0xFEEDFACF or uint32be(0) == 0xCAFEBABE) and
        any of ($lib*) and any of ($behav*)
}
```

### JavaScript Detection

| Target | Approach |
|---|---|
| npm package | `package.json` patterns, postinstall/preinstall hooks, exfil combination: fetch + env access + credential paths |
| Chrome extension | `crx` module |
| Other extension | Manifest patterns, background script behaviors |
| Standalone JS | Obfuscation markers (eval+atob, fromCharCode chains), unique function/variable names, packed payloads |
| Minified/webpack bundle | Unique strings that survive bundling (URLs, magic values); **avoid function names** — they get mangled |

**Good JS strings:** Ethereum function selectors — `{ a9 05 9c bb }` (`transfer(address,uint256)`), `{ 70 a0 82 31 }` (`balanceOf(address)`); zero-width characters for steganography — `{ E2 80 8B E2 80 8C }`; obfuscator signatures — `_0x`, `var _0x`; specific C2 domains and webhook URLs.

**Bad JS strings:** `require`, `fetch`, `axios` (too common); `Buffer`, `crypto` (legitimate uses everywhere); `process.env` alone (need specific env var names).

## String Selection

**Value ranking:** mutex names are gold, C2 paths silver, error messages bronze. Stack strings are almost always unique. If you need more than 6 strings, you're over-fitting.

Reject a candidate string when any of these holds:

| Test | Why it fails | Do instead |
|---|---|---|
| Under 4 bytes | No atom | Find a longer string |
| Repeated bytes (`0000`, `9090`) | Weak atom | Add surrounding context |
| API name (`VirtualAlloc`, `CreateRemoteThread`) | Every packer and installer calls it | Hex pattern of the call site plus a unique marker |
| Appears in Windows system files | Guaranteed FPs | Find something family-specific |
| Common path (`C:\Windows\`, `cmd.exe`) | Ubiquitous | Find malware-specific paths |
| Appears in other malware families | Not identifying *this* family | Combine with a family-specific marker |

Everything left — unique to this family — is what the rule should rest on.

### Choosing a String Type

| Need | Use |
|---|---|
| Exact ASCII/Unicode text | `$s = "MutexName" ascii wide` |
| Specific byte sequence | `$h = { 4D 5A 90 00 }` |
| Byte sequence with variation | Hex wildcards: `{ 4D 5A ?? ?? 50 45 }` |
| Pattern with structure (URLs, paths) | Bounded regex: `/https:\/\/[a-z]{5,20}\.onion/` |
| Unknown encoding (XOR, base64) | Modifier: `$s = "config" xor(0x00-0xFF)` |

**Modifier discipline:** never use `nocase` or `wide` speculatively — only with confirmed evidence that case or encoding varies across samples. `nocase` doubles atom generation; `wide` doubles string matching. "If you don't have a clear reason for using those modifiers, don't do it" — Kaspersky Applied YARA.

## Condition Design

Order for short-circuit: `filesize <`, magic bytes, strings, modules. If the condition runs past 5 lines, split into multiple rules.

### all of vs any of

| Situation | Use |
|---|---|
| Strings are individually unique to the malware | `any of them` — each alone is suspicious |
| Strings are common but the combination is suspicious | `all of them` — require the full pattern |
| Strings have different confidence levels | Group: `all of ($core_*) and any of ($variant_*)` |
| Seeing false positives | Tighten: `any` → `all`, add more required strings |

**Lesson from production:** rules using `any of ($network_*)` where the strings included `fetch`, `axios`, and `http` matched virtually all web applications. Switching to require a credential path AND a network call AND an exfil destination eliminated the FPs.

### Grouping by Confidence

Different indicator types carry different weight — a C2 domain might be definitive while library imports need corroboration. Grouping by prefix lets you express graduated requirements:

```yara
strings:
    $a1 = "SRWebSocket" ascii            // Category A: library indicators
    $a2 = "SocketRocket" ascii
    $b1 = "SSH tunnel" ascii             // Category B: behavioral
    $b2 = "keylogger" ascii nocase
    $c1 = /https:\/\/[a-z0-9]{8,16}\.onion/   // Category C: C2

condition:
    filesize < 10MB and
    any of ($a*) and any of ($b*)        // Evidence from BOTH categories
```

### Modules vs Byte Checks

| Need | Use |
|---|---|
| imphash, rich header, authenticode | PE module — too complex to replicate |
| Magic bytes or simple offsets | `uint16`/`uint32` — faster, no module overhead |
| Section names/sizes | PE module, but put the magic-byte filter FIRST |
| Chrome extension permissions | `crx` module — string parsing is fragile |
| LNK target paths | `lnk` module — the format is complex |

"Avoid the magic module — use explicit hex checks instead" — Neo23x0. Generalize it: if `uint32()` can do the job, don't load a module.

### Performance

- **Regex must be anchored to a 4+ byte literal.** Without one it evaluates at *every* file offset — catastrophic. Write `/mshta\.exe http:\/\/.../`, not `/http:\/\/.../`. If you can't anchor, use a hex pattern with wildcards.
- **Bound every regex quantifier** — `.{0,30}`, never `.*`. Unbounded regex is both a performance disaster and a memory explosion.
- **Bound loops with filesize** — `filesize < 100KB and for all i in (1..#a) : ...`. Unbounded `#a` can reach thousands in large files.
- **Prefer hex over regex** where the bytes are fixed.

## Before Writing: Is the Sample Packed?

| Signal | What to do |
|---|---|
| Entropy > 7.0 | Likely packed — find the unpacked layer first |
| Few or no readable strings | Likely packed — use entropy, PE structure, or packer signatures |
| UPX/MPRESS/custom packer detected | Target the unpacked payload OR detect the packer itself |
| Readable strings available | Proceed with string-based detection |

**Don't write rules against packed layers.** The packing changes; the payload doesn't.

### When Strings Fail, Pivot to Structure

If extraction returns only API names and generic paths:

| Available signal | Use |
|---|---|
| High entropy sections | `math.entropy()` on specific sections |
| Unusual import pattern | `pe.imphash()` for import-hash clustering |
| PE structure anomalies | Section names, sizes, characteristics |
| Metadata present | Version info, timestamps, resources |
| Nothing unique | This sample may not be detectable with YARA alone |

"One can try to use other file properties, such as metadata, entropy, import hashes or other data which stays constant." — Kaspersky Applied YARA Training

## Debugging False Positives

1. **Which string matched?** — `yr scan -s rule.yar false_positive.exe`
2. **In a legitimate library?** — add a `not $fp_vendor_string` exclusion
3. **A common development pattern?** — replace the string with something more specific
4. **Multiple generic strings matching together?** — tighten to require all, plus a unique marker
5. **Malware using a common technique?** — target its specific implementation details, not the technique

### When to Abandon the Approach

- **Extraction returns only API names and paths** → [pivot to structure](#when-strings-fail-pivot-to-structure)
- **Can't find 3 unique strings** → probably packed; target the unpacked version or detect the packer
- **Rule matches goodware** → 1-2 matches: investigate and tighten; 3-5: find different indicators; 6+: start over
- **Performance is terrible after optimization** → architecture problem; split into focused rules or add strict pre-filters
- **The description is hard to write** → the rule is too vague. If you can't explain what it catches, it catches too much

## Rationalizations to Reject

When you catch yourself thinking these, stop and reconsider.

| Rationalization | Expert Response |
|-----------------|-----------------|
| "This generic string is unique enough" / "This hex pattern is unique" | Unique in one sample ≠ unique across the ecosystem. Test against goodware; your intuition is wrong. |
| "yarGen gave me these strings" | yarGen suggests, you validate. Check each one manually — expect to discard 80%. |
| "It works on my 10 samples" | 10 samples ≠ production. Use a goodware corpus. |
| "One rule to catch all variants" | Causes FP floods. Target specific families. |
| "I'll make it more specific if we get FPs" / "I'll add more conditions later" | Write tight rules upfront. A weak rule deployed is damage done, and FPs burn trust. |
| "This is just for hunting" | Hunting rules become detection rules. Same quality bar. |
| "The API name makes it malicious" | Legitimate software uses the same APIs. Need behavioral context. |
| "`any of them` is fine for these common strings" | Common strings + `any` = FP flood. Use `any of` only for individually unique strings. |
| "This regex is specific enough" | `/fetch.*token/` matches all auth code. Add an exfil destination requirement. |
| "I'll use `.*` for flexibility" | Unbounded regex = performance disaster plus memory explosion. Use `.{0,30}`. |
| "The JavaScript looks clean" | Attackers poison legitimate code with injects. Check for eval+decode chains. |
| "Performance doesn't matter" | One slow rule slows the entire ruleset. Optimize atoms. |
| "I'll use `--relaxed-re-syntax` everywhere" | Masks real bugs. Fix the regex instead of hiding the problem. |
| "PEiD rules still work" | Obsolete. 32-bit packers aren't relevant. |

## Toolkit

| Tool | Purpose |
|------|---------|
| **yr CLI** | `yr check` (validate), `yr fmt` (format), `yr scan -s` (scan, show strings), `yr dump -m pe` (inspect structure) |
| **yarGen** | Extract candidate strings: `yarGen.py -m samples/ --excludegood` |
| **FLOSS** | Extract obfuscated/stack strings: `floss sample.exe` — when yarGen comes up empty |
| **signature-base** | Study quality examples |
| **YARA-CI** | Goodware corpus testing before deployment |

Master these five. Don't get distracted by tool catalogs.

**Development cycle:**

```bash
yr check rule.yar                                   # syntax, with precise line numbers
yr fmt -w rule.yar                                  # standardize formatting
yr dump -m pe sample.exe --output-format yaml       # inspect structure, no dummy rule needed
time yr scan -s rule.yar corpus/                    # scan with timing
```

Reach for `yr dump` when investigating which module fields are available, debugging why a module condition isn't matching, or exploring a new module (crx, lnk, dotnet) before writing against it. YARA-X error messages carry precise source locations — if `yr check` says line 15, the problem is on line 15.

**Version-gated features:** `private $helper = "pattern"` matches but stays out of output (v1.3.0+); `// suppress: slow_pattern` silences a specific warning inline (v1.4.0+); `filesize < 10_000_000` numeric underscores (v1.5.0+). `$_unused` also suppresses unused-string warnings.

## Chrome Extension Analysis (crx module)

Requires YARA-X v1.5.0+, or v1.11.0+ for `permhash()`.

**Key APIs:** `crx.is_crx`, `crx.permissions`, `crx.permhash()`
**Red flags:** `nativeMessaging` + `downloads`, `debugger` permission, content scripts on `<all_urls>`

```yara
import "crx"

rule SUSP_CRX_HighRiskPerms {
    condition:
        crx.is_crx and
        for any perm in crx.permissions : (perm == "debugger")
}
```

See [crx-module.md](references/crx-module.md) for the full API, permission risk assessment, and example rules.

## Android DEX Analysis (dex module)

Requires YARA-X v1.11.0+. **Not compatible with legacy YARA's dex module** — the API is completely different.

**Key APIs:** `dex.is_dex`, `dex.contains_class()`, `dex.contains_method()`, `dex.contains_string()`
**Red flags:** single-letter class names (obfuscation), `DexClassLoader` reflection, encrypted assets

```yara
import "dex"

rule SUSP_DEX_DynamicLoading {
    condition:
        dex.is_dex and
        dex.contains_class("Ldalvik/system/DexClassLoader;")
}
```

See [dex-module.md](references/dex-module.md) for the full API, obfuscation detection, and example rules.

## Migrating from Legacy YARA

99% rule compatibility, but stricter validation:

```bash
yr check --relaxed-re-syntax rules/   # identify issues
# fix each one, then verify without relaxed mode:
yr check rules/
```

| Issue | Legacy | YARA-X Fix |
|-------|--------|------------|
| Literal `{` in regex | `/{/` | `/\{/` |
| Invalid escapes | `\R` silently literal | `\\R` or `R` |
| Base64 strings | Any length | 3+ chars required |
| Negative indexing | `@a[-1]` | `@a[#a - 1]` |
| Duplicate modifiers | Allowed | Remove duplicates |

`--relaxed-re-syntax` is a diagnostic, not a destination. Fix the regex.

## Naming and Metadata

```
{CATEGORY}_{PLATFORM}_{FAMILY}_{VARIANT}_{DATE}      e.g. MAL_Win_Emotet_Loader_Jan25
```

**Categories:** `MAL_` (malware), `HKTL_` (hacking tool), `WEBSHELL_`, `EXPL_`, `SUSP_` (suspicious), `GEN_` (generic). **Platforms:** `Win_`, `Lnx_`, `Mac_`, `Android_`, `CRX_`.

Every rule needs `description` (starting with "Detects"), `author`, `reference`, and `date`:

```yara
meta:
    description = "Detects Example malware via unique mutex and C2 path"
    author = "Your Name <email@example.com>"
    reference = "https://example.com/analysis"
    date = "2025-01-29"
```

See [style-guide.md](references/style-guide.md) for full conventions.

## Workflow

1. **Gather samples** — multiple; single-sample rules are brittle
2. **Extract candidates** — `yarGen -m samples/ --excludegood`
3. **Validate quality** — apply the [string selection](#string-selection) tests; expect to discard 80% of yarGen output
4. **Write the rule** — proper metadata, cheap checks first
5. **Lint and test** — `yr check`, `yr fmt`, the linter script
6. **Goodware validation** — VirusTotal corpus or local clean files
7. **Deploy** — full metadata, then monitor for FPs

Quality signals along the way: a rule matching under 50% of known variants is too narrow; one matching goodware is too broad.

**Reviewing a rule someone else wrote** — run both scripts before reading the rule by eye, and quote the codes they emit:

```bash
uv run {baseDir}/scripts/yara_lint.py suspect.yar      # style, metadata, YARA-X compatibility
uv run {baseDir}/scripts/atom_analyzer.py suspect.yar  # atom quality per string
```

They catch the mechanical faults — short strings, FP-prone substrings, unbounded quantifiers, expensive terms ahead of cheap ones — so your attention goes to the judgement calls they cannot make: whether the strings identify *this* family, and whether the condition can fire on generic strings alone. Report findings by code (`E002`, `W009`) so the author can look each one up in [style-guide.md](references/style-guide.md).

See [testing.md](references/testing.md) for the validation workflow and [rule-development.md](workflows/rule-development.md) for the full step-by-step guide.

## Common Mistakes

| Mistake | Bad | Good |
|---------|-----|------|
| API names as indicators | `"VirtualAlloc"` | Hex pattern of call site + unique mutex |
| Unbounded regex | `/https?:\/\/.*/` | `/https?:\/\/[a-z0-9]{8,12}\.onion/` |
| Missing file type filter | `pe.imports(...)` first | `uint16(0) == 0x5A4D and filesize < 10MB` first |
| Short strings | `"abc"` (3 bytes) | `"abcdef"` (4+ bytes) |
| Unescaped braces (YARA-X) | `/config{key}/` | `/config\{key\}/` |
| Wrong-endian magic bytes | `uint32(0) == 0xCAFEBABE` | `uint32be(0) == 0xCAFEBABE` |

## Quality Checklist

Before deploying any rule:

- [ ] Name follows `{CATEGORY}_{PLATFORM}_{FAMILY}_{VARIANT}_{DATE}`
- [ ] Description starts with "Detects" and explains what/how
- [ ] All required metadata present (author, reference, date)
- [ ] Strings are unique — not API names, common paths, or format strings
- [ ] All strings 4+ bytes with good atom potential
- [ ] Base64 modifier only on strings with 3+ characters
- [ ] Regex bounded, anchored to a literal, with `{` escaped
- [ ] Condition starts with cheap checks (filesize, magic bytes)
- [ ] Magic-byte constants verified against a known-good sample
- [ ] Rule matches all target samples
- [ ] Rule produces zero matches on the goodware corpus
- [ ] `yr check` and `yr fmt --check` pass
- [ ] Linter passes with no errors
- [ ] Peer review completed

## Scripts

```bash
uv run {baseDir}/scripts/yara_lint.py rule.yar      # validate style/metadata
uv run {baseDir}/scripts/atom_analyzer.py rule.yar  # check string quality
```

See [README.md](../../README.md#scripts) for detailed script documentation.

## Further Reading

| Topic | Document |
|-------|----------|
| Naming and metadata conventions | [style-guide.md](references/style-guide.md) |
| Performance and atom optimization | [performance.md](references/performance.md) |
| String types and judgment | [strings.md](references/strings.md) |
| Testing and validation | [testing.md](references/testing.md) |
| Chrome extension module (crx) | [crx-module.md](references/crx-module.md) |
| Android DEX module (dex) | [dex-module.md](references/dex-module.md) |
| Complete rule development process | [rule-development.md](workflows/rule-development.md) |

The `examples/` directory holds real, attributed rules worth reading before writing your own:

| Example | Demonstrates | Source |
|---------|--------------|--------|
| [MAL_Win_Remcos_Jan25.yar](examples/MAL_Win_Remcos_Jan25.yar) | PE malware: graduated string counts, multiple rules per family | Elastic Security |
| [MAL_Mac_ProtonRAT_Jan25.yar](examples/MAL_Mac_ProtonRAT_Jan25.yar) | macOS: Mach-O magic bytes, multi-category grouping | Airbnb BinaryAlert |
| [MAL_NPM_SupplyChain_Jan25.yar](examples/MAL_NPM_SupplyChain_Jan25.yar) | npm supply chain: real attack patterns, ERC-20 selectors | Stairwell Research |
| [SUSP_JS_Obfuscation_Jan25.yar](examples/SUSP_JS_Obfuscation_Jan25.yar) | JavaScript: obfuscator detection, density-based matching | imp0rtp3, Nils Kuhnert |
| [SUSP_CRX_SuspiciousPermissions.yar](examples/SUSP_CRX_SuspiciousPermissions.yar) | Chrome extensions: crx module, permissions | Educational |

**Rule repositories to learn from:** [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) (17,000+ production rules), [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) (endpoint-tested), [imp0rtp3/js-yara-rules](https://github.com/imp0rtp3/js-yara-rules) (JavaScript), [InQuest/awesome-yara](https://github.com/InQuest/awesome-yara) (curated index).

**Guides:** [YARA Style Guide](https://github.com/Neo23x0/YARA-Style-Guide) and [YARA Performance Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines) (Neo23x0), [YARA-X documentation](https://virustotal.github.io/yara-x/).

**macOS specifics:** Apple's own production rules ship at `/System/Library/CoreServices/XProtect.bundle/`; [objective-see](https://objective-see.org/) publishes macOS malware research and samples.
