---
name: yara-rule-authoring
description: >
  Guides authoring of high-quality YARA detection rules for malware identification.
  Use when writing, reviewing, or optimizing YARA rules. Covers naming conventions,
  string selection, performance optimization, and false positive reduction.
  Triggers on: YARA, malware detection, threat hunting, IOC, signature.
---

# YARA Rule Authoring

Write detection rules that catch malware without drowning in false positives.

## Core Principles

1. **Strings must generate good atoms** — YARA extracts 4-byte subsequences for fast matching. Strings with repeated bytes, common sequences, or under 4 bytes force slow bytecode verification on too many files.

2. **Target specific families, not categories** — "Detects ransomware" catches everything and nothing. "Detects LockBit 3.0 configuration extraction routine" catches what you want.

3. **Test against goodware before deployment** — A rule that fires on Windows system files is useless. Validate against VirusTotal's goodware corpus or your own clean file set.

4. **Short-circuit with cheap checks first** — Put `filesize < 10MB and uint16(0) == 0x5A4D` before expensive string searches or module calls.

5. **Metadata is documentation** — Future you (and your team) need to know what this catches, why, and where the sample came from.

## When to Use

- Writing new YARA rules for malware detection
- Reviewing existing rules for quality or performance issues
- Optimizing slow-running rulesets
- Converting IOCs or threat intel into detection signatures
- Debugging false positive issues
- Preparing rules for production deployment

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
| **JavaScript/Node** | (none needed) | `require`, `fetch`, `axios` | Obfuscator signatures, eval+decode chains |
| **npm/pip packages** | (none needed) | `postinstall`, `dependencies` | Suspicious package names, exfil URLs |
| **Office docs** | `uint32(0) == 0x504B0304` | VBA keywords | Macro auto-exec, encoded payloads |
| **VS Code extensions** | (none needed) | `vscode.workspace` | Uncommon activationEvents, hidden file access |

The examples in this skill default to PE files. For JavaScript/supply chain detection:
- No magic bytes check needed (text files)
- Replace API names with obfuscation signatures
- Replace mutex names with exfiltration channel patterns

## Essential Toolkit

An expert uses 5 tools. Everything else is noise.

| Tool | Purpose | When to Use |
|------|---------|-------------|
| **yarGen** | Extract candidate strings from samples | First step for any new rule |
| **yara CLI** | Test rules locally | Every rule iteration |
| **signature-base** | Study quality examples | Learning patterns, borrowing techniques |
| **YARA-CI** | Goodware corpus testing | Before any production deployment |
| **Binarly** | Validate string uniqueness | Before finalizing string selection |

```bash
# yarGen: extract unique strings
python yarGen.py -m /path/to/samples --excludegood

# With opcode extraction for PE files
python yarGen.py --opcodes -m /path/to/samples

# Suppress individual rules when super-rule covers them
python yarGen.py --nosimple -m /path/to/samples

# yara CLI: test against samples
yara -s rule.yar sample.exe

# Local goodware check
yara -r rule.yar /path/to/clean/files/
```

**That's it.** Don't get distracted by tool catalogs. Master these five.

## Rationalizations to Reject

When you catch yourself thinking these, stop and reconsider.

| Rationalization | Expert Response |
|-----------------|-----------------|
| "This generic string is unique enough" | Test against goodware first. Your intuition is wrong. |
| "yarGen gave me these strings" | yarGen suggests, you validate. Check each one manually. |
| "It works on my 10 samples" | 10 samples ≠ production. Use VirusTotal goodware corpus. |
| "One rule to catch all variants" | Causes FP floods. Target specific families. |
| "I'll make it more specific if we get FPs" | Write tight rules upfront. FPs burn trust. |
| "This hex pattern is unique" | Unique in one sample ≠ unique across malware ecosystem. |
| "Performance doesn't matter" | One slow rule slows entire ruleset. Optimize atoms. |
| "PEiD rules still work" | Obsolete. 32-bit packers aren't relevant. |
| "I'll add more conditions later" | Weak rules deployed = damage done. |
| "This is just for hunting" | Hunting rules become detection rules. Same quality bar. |
| "The API name makes it malicious" | Legitimate software uses same APIs. Need behavioral context. |
| "any of them is fine for these common strings" | Common strings + any = FP flood. Use `any of` only for individually unique strings. |
| "This regex is specific enough" | `/fetch.*token/` matches all auth code. Add exfil destination requirement. |
| "The JavaScript looks clean" | Attackers poison legitimate code with injects. Check for eval+decode chains. |
| "I'll use .* for flexibility" | Unbounded regex = performance disaster + memory explosion. Use `.{0,30}`. |

## Decision Trees

### Is This String Good Enough?

```
Is this string good enough?
├─ Less than 4 bytes?
│  └─ NO — find longer string
├─ Contains repeated bytes (0000, 9090)?
│  └─ NO — add surrounding context
├─ Is an API name (VirtualAlloc, CreateRemoteThread)?
│  └─ NO — use hex pattern of call site instead
├─ Appears in Windows system files?
│  └─ NO — too generic, find something unique
├─ Is it a common path (C:\Windows\, cmd.exe)?
│  └─ NO — find malware-specific paths
├─ Unique to this malware family?
│  └─ YES — use it
└─ Appears in other malware too?
   └─ MAYBE — combine with family-specific marker
```

### When to Use "all of" vs "any of"

```
Should I require all strings or allow any?
├─ Strings are individually unique to malware?
│  └─ any of them (each alone is suspicious)
├─ Strings are common but combination is suspicious?
│  └─ all of them (require the full pattern)
├─ Strings have different confidence levels?
│  └─ Group: all of ($core_*) and any of ($variant_*)
└─ Seeing many false positives?
   └─ Tighten: switch any → all, add more required strings
```

**Lesson from production:** Rules using `any of ($network_*)` where strings included "fetch", "axios", "http" matched virtually all web applications. Switching to require credential path AND network call AND exfil destination eliminated FPs.

### When to Abandon a Rule Approach

Stop and pivot when:

- **yarGen returns only API names and paths** → Sample too generic for string-based detection. Consider behavioral patterns or PE structure anomalies instead.

- **Can't find 3 unique strings** → Probably packed. Target the unpacked version or detect the packer.

- **Rule matches goodware files** → Strings aren't unique enough. 1-5 matches = investigate and tighten; 6+ matches = start over with different indicators.

- **Performance is terrible even after optimization** → Architecture problem. Split into multiple focused rules or add strict pre-filters.

- **Description is hard to write** → The rule is too vague. If you can't explain what it catches, it catches too much.

### Debugging False Positives

```
FP Investigation Flow:
│
├─ 1. Which string matched?
│     Run: yara -s rule.yar false_positive.exe
│
├─ 2. Is it in a legitimate library?
│     └─ Add: not $fp_vendor_string exclusion
│
├─ 3. Is it a common development pattern?
│     └─ Find more specific indicator, replace the string
│
├─ 4. Are multiple generic strings matching together?
│     └─ Tighten to require all + add unique marker
│
└─ 5. Is the malware using common techniques?
      └─ Target malware-specific implementation details, not the technique
```

### Hex vs Text vs Regex

```
What string type should I use?
│
├─ Exact ASCII/Unicode text?
│  └─ TEXT: $s = "MutexName" ascii wide
│
├─ Specific byte sequence?
│  └─ HEX: $h = { 4D 5A 90 00 }
│
├─ Byte sequence with variation?
│  └─ HEX with wildcards: { 4D 5A ?? ?? 50 45 }
│
├─ Pattern with structure (URLs, paths)?
│  └─ BOUNDED REGEX: /https:\/\/[a-z]{5,20}\.onion/
│
└─ Unknown encoding (XOR, base64)?
   └─ TEXT with modifier: $s = "config" xor(0x00-0xFF)
```

## Expert Heuristics

Quick rules of thumb from experienced YARA authors:

**String selection:**
- If description is hard to write, the rule is probably too vague
- If you need >6 strings, you're probably over-fitting
- Stack strings are almost always unique — prioritize finding them
- Mutex names are gold; C2 paths are silver; error messages are bronze

**Condition design:**
- If condition is >5 lines, simplify or split into multiple rules
- Always start with `filesize < X` — it's instant
- `uint16(0) == 0x5A4D` before any PE module calls

**Quality signals:**
- yarGen output needs 80% filtering — most suggestions are junk
- If a string appears in both malware and goodware, it's not a good string
- Rules matching <50% of variants are too narrow; matching goodware are too broad

**Count thresholds:**
- Use `#s > N` when a pattern is common but N+ occurrences is suspicious
- Example: `#hex_var > 5` for obfuscator signatures (1-2 might be coincidence)
- Example: `#unicode_vs > 5` for hidden Unicode (legitimate i18n uses fewer)
- Thresholds reduce FPs from patterns that appear legitimately in small numbers

**Performance:**
- `nocase` doubles atom generation — use sparingly
- Unbounded regex (`.*`) is always wrong
- Hex patterns with leading wildcards have no good atoms

**Regex discipline:**
- Use controlled ranges: `.{0,30}` not `.*` or `.+`
- Anchor regex to a string atom when possible — unanchored regex runs against every byte
- `nocase` on regex doubles memory — use only when case actually varies in samples

## Quick Reference

### Naming Convention

```
{CATEGORY}_{PLATFORM}_{FAMILY}_{VARIANT}_{DATE}
```

**Category prefixes:**
- `MAL_` — Confirmed malware
- `HKTL_` — Hacking tool (Cobalt Strike, Mimikatz)
- `WEBSHELL_` — Web shells
- `EXPL_` — Exploits
- `VULN_` — Vulnerable software patterns
- `SUSP_` — Suspicious (lower confidence)
- `PUA_` — Potentially unwanted applications
- `GEN_` — Generic/broad detection

**Platform indicators:** `Win_`, `Lnx_`, `Mac_`, `Android_`

**Examples:**
```
MAL_Win_Emotet_Loader_Jan25
HKTL_Win_CobaltStrike_Beacon_Jan25
WEBSHELL_PHP_Generic_Eval_Jan25
SUSP_PE_Packed_UPX_Anomaly_Jan25
```

### Required Metadata

```yara
rule MAL_Win_Example_Jan25
{
    meta:
        description = "Detects Example malware loader via unique mutex and C2 path"
        author = "Your Name <email@example.com>"  // OR "@twitter_handle"
        reference = "https://example.com/analysis"
        date = "2025-01-29"
        hash = "abc123..."  // Sample SHA256

    strings:
        // ...

    condition:
        // ...
}
```

**Description requirements:**
- Start with "Detects..."
- 60-400 characters
- Explain WHAT it catches and HOW (the distinguishing feature)

### String Selection

**Good strings (unique, stable):**
- Mutex names: `"Global\\MyMalwareMutex"`
- Stack strings (decrypted at runtime)
- PDB paths: `"C:\\Users\\dev\\malware.pdb"`
- C2 paths: `"/api/beacon/check"`
- Unique error messages: `"Failed to inject payload into explorer"`
- Configuration markers
- Custom protocol headers

**Bad strings (FP-prone):**
- API names: `"VirtualAlloc"`, `"CreateRemoteThread"`
- Common executables: `"cmd.exe"`, `"powershell.exe"`
- Format specifiers: `"%s"`, `"%d"`
- Generic paths: `"C:\\Windows\\"`
- Common library strings

### Condition Patterns

**Basic structure (ordered for short-circuit):**
```yara
condition:
    // 1. File size first (instant)
    filesize < 5MB and

    // 2. Magic bytes (nearly instant)
    uint16(0) == 0x5A4D and

    // 3. String matches (cheap)
    2 of ($config_*) and

    // 4. Module checks (expensive)
    pe.imports("kernel32.dll", "VirtualAlloc")
```

**Common patterns:**
```yara
// All strings required
all of them

// At least N strings
3 of ($s*)

// Any from a set
any of ($mutex_*, $c2_*)

// Positional check
$header at 0

// Range check
$marker in (0..1024)

// String count
#s1 > 5
```

## Workflow

### 1. Gather Samples

Collect multiple samples of the target malware family. Single-sample rules are brittle.

### 2. Extract Candidate Strings

Use yarGen to identify unique strings:

```bash
python yarGen.py -m /path/to/samples --excludegood
```

**Then evaluate each string** using the decision tree above. yarGen suggestions need heavy filtering.

### 3. Validate String Quality

Check each string mentally:
- Does it have 4+ consecutive unique bytes?
- Is it an API name or common path? (reject)
- Would this appear in legitimate software? (test it)

Use the atom analyzer for detailed feedback:
```bash
uv run {baseDir}/scripts/atom_analyzer.py draft_rule.yar
```

### 4. Write Initial Rule

Follow the template:

```yara
rule MAL_Family_Variant_Date
{
    meta:
        description = "Detects X via Y"
        author = "Name"
        reference = "URL"
        date = "YYYY-MM-DD"
        hash = "sample_sha256"

    strings:
        $unique1 = "specific_string"
        $unique2 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 }

    condition:
        filesize < 2MB and
        uint16(0) == 0x5A4D and
        all of them
}
```

### 5. Lint and Test

```bash
# Lint for style issues
uv run {baseDir}/scripts/yara_lint.py rule.yar

# Test against malware samples (should match all)
yara -r rule.yar /path/to/malware/samples/

# Test against goodware (should match NONE)
yara -r rule.yar /path/to/clean/files/
```

### 6. Goodware Validation

**VirusTotal (recommended):** Upload rule to VT Retrohunt against goodware corpus.

Any match = investigate using the FP debugging decision tree.

### 7. Document and Deploy

Add to rule repository with full metadata. Version control. Monitor for FPs in production.

## Common Mistakes

### Using API names as indicators

```yara
// BAD: Every program uses these
strings:
    $api1 = "VirtualAlloc"
    $api2 = "CreateRemoteThread"

// GOOD: Combine with unique context
strings:
    $inject_pattern = { 48 8B ?? 48 89 ?? FF 15 }  // Specific injection sequence
    $custom_mutex = "Global\\MyMalware"
```

### Unbounded regex

```yara
// BAD: Matches way too much
$url = /https?:\/\/.*/

// GOOD: Bounded and specific
$c2 = /https?:\/\/[a-z0-9]{8,12}\.onion\/api/
```

### Missing file type filter

```yara
// BAD: Runs PE checks on all files
condition:
    pe.imports("kernel32.dll", "VirtualAlloc")

// GOOD: Filter first
condition:
    uint16(0) == 0x5A4D and
    filesize < 10MB and
    pe.imports("kernel32.dll", "VirtualAlloc")
```

### Short strings

```yara
// BAD: 3 bytes = terrible atoms
$s1 = "abc"

// GOOD: 4+ bytes minimum
$s1 = "abcdef"
```

## Performance Optimization

See [performance.md](references/performance.md) for atom theory details.

**Quick wins:**
1. Put `filesize` and magic byte checks first
2. Avoid `nocase` unless necessary
3. Use bounded regex: `{1,100}` not `*` or `+`
4. Prefer hex strings over regex for byte patterns

**Red flags:**
- Strings under 4 bytes
- Unbounded regex: `.*`, `.+`
- Heavy module use without file-type filtering
- `nocase` on long strings

## Reference Documents

| Topic | Document |
|-------|----------|
| Naming and metadata conventions | [style-guide.md](references/style-guide.md) |
| Performance and atom optimization | [performance.md](references/performance.md) |
| String types and judgment | [strings.md](references/strings.md) |
| Testing and validation | [testing.md](references/testing.md) |

## Scripts

### Rule Linter

Validates style, metadata, and common anti-patterns:

```bash
uv run {baseDir}/scripts/yara_lint.py rule.yar
uv run {baseDir}/scripts/yara_lint.py --json rules/
```

### Atom Analyzer

Evaluates string quality for efficient scanning:

```bash
uv run {baseDir}/scripts/atom_analyzer.py rule.yar
```

## Quality Checklist

Before deploying any rule:

- [ ] Name follows `{CATEGORY}_{PLATFORM}_{FAMILY}_{VARIANT}_{DATE}` format
- [ ] Description starts with "Detects" and explains what/how
- [ ] All required metadata present (author, reference, date)
- [ ] Strings are unique (not API names, common paths, or format strings)
- [ ] All strings have 4+ bytes with good atom potential
- [ ] Condition starts with cheap checks (filesize, magic bytes)
- [ ] Rule matches all target samples
- [ ] Rule produces zero matches on goodware corpus
- [ ] Linter passes with no errors
- [ ] Peer review completed

## Resources

- [Official YARA Documentation](https://yara.readthedocs.io/)
- [Neo23x0 YARA Style Guide](https://github.com/Neo23x0/YARA-Style-Guide)
- [Neo23x0 Performance Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines)
- [signature-base Rule Collection](https://github.com/Neo23x0/signature-base)
- [YARA-CI GitHub Integration](https://yara-ci.cloud.virustotal.com/)
- [yarGen String Extraction](https://github.com/Neo23x0/yarGen)
