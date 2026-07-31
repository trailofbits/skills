# YARA Naming and Metadata

Consistent naming for maintainable rule sets.

## Naming Convention

```
{CATEGORY}_{PLATFORM}_{FAMILY}_{VARIANT}_{DATE}
```

| Component | Description | Examples |
|-----------|-------------|----------|
| CATEGORY | Threat classification | MAL, HKTL, WEBSHELL, EXPL, SUSP |
| PLATFORM | Target OS/environment | Win, Lnx, Mac, Android, Multi |
| FAMILY | Malware family name | Emotet, CobaltStrike, LockBit |
| VARIANT | Specific variant/component | Loader, Beacon, Config |
| DATE | Creation date (MonthYear format) | Jan25, May23 |

### Category Prefixes

| Prefix | Meaning | Use When |
|--------|---------|----------|
| `MAL_` | Confirmed malware | Verified malicious code |
| `HKTL_` | Hacking tool | Dual-use tools (Mimikatz, Cobalt Strike) |
| `WEBSHELL_` | Web shell | PHP/ASP/JSP backdoors |
| `EXPL_` | Exploit | Exploit code or shellcode |
| `VULN_` | Vulnerable | Vulnerable software patterns |
| `SUSP_` | Suspicious | Lower confidence, may FP |
| `PUA_` | Potentially unwanted | Adware, bundleware |
| `GEN_` | Generic | Broad detection category |

### Additional Classifiers

Append when relevant:

| Classifier | Meaning |
|------------|---------|
| `APT_` | APT-associated |
| `CRIME_` | Cybercrime operation |
| `RANSOM_` | Ransomware |
| `RAT_` | Remote access trojan |
| `MINER_` | Cryptominer |
| `STEALER_` | Information stealer |
| `LOADER_` | Loader/dropper |
| `C2_` | Command and control |

### Platform Indicators

| Indicator | Platform |
|-----------|----------|
| `Win_` | Windows |
| `Lnx_` | Linux |
| `Mac_` | macOS |
| `Android_` | Android |
| `iOS_` | iOS |
| `Multi_` | Cross-platform |
| `PE_` | PE file format |
| `ELF_` | ELF file format |
| `PS_` | PowerShell |
| `DOC_` | Office documents |
| `PDF_` | PDF files |
| `JAR_` | Java archives |

### Examples

```yara
// Good names (all include date suffix)
MAL_Win_Emotet_Loader_Jan25
HKTL_Win_CobaltStrike_Beacon_Jan25
WEBSHELL_PHP_Generic_Eval_Jan25
APT_Win_Lazarus_AppleJeus_Config_Jan25
RANSOM_Win_LockBit3_Decryptor_Jan25
SUSP_PE_Packed_UPX_Anomaly_Jan25

// Bad names
malware_detector              // Too vague
rule1                         // Meaningless
detect_bad_stuff              // Unprofessional
EMOTET_RULE                   // Missing category/platform/date
CobaltStrike_Beacon           // Missing category/date
```

## Metadata Requirements

### Required Fields

Every rule MUST have:

```yara
meta:
    description = "Detects X malware via Y unique feature"
    author = "Your Name <email@example.com>"  // OR "@twitter_handle"
    reference = "https://analysis-report-url.com"
    date = "2025-01-29"
```

### Description Guidelines

- **Start with "Detects"** — Consistent, scannable format
- **Length: 60-400 characters** — Brief but informative
- **Explain WHAT and HOW** — What it catches and the distinguishing feature

```yara
// Good descriptions
description = "Detects Emotet loader via unique XOR decryption routine and mutex pattern"
description = "Detects CobaltStrike beacon by watermark bytes in PE overlay"
description = "Detects generic PHP webshell using eval with base64_decode pattern"

// Bad descriptions
description = "Malware"                    // Too short
description = "This rule detects..."       // Redundant
description = "Catches bad stuff"          // Unprofessional
description = "Might be malware"           // Low confidence = use SUSP_ prefix
```

### Optional Fields

```yara
meta:
    // Sample identification (hash field can repeat)
    hash = "abc123def456..."               // SHA256 of reference sample
    hash = "789xyz..."                     // Additional samples (repeat field)

    // Confidence scoring
    score = 75                             // 0-100, use thresholds

    // Versioning
    modified = "2025-01-30"                // Last update date
    version = "1.2"                        // Rule version
    old_rule_name = "Previous_Rule_Name"   // For renamed rules (searchability)

    // Classification
    tags = "apt, lazarus, loader"          // Comma-separated
    tlp = "WHITE"                          // Traffic Light Protocol

    // MITRE ATT&CK
    mitre_attack = "T1055"                 // Technique ID
```

### Score Thresholds

| Score | Meaning | Action |
|-------|---------|--------|
| 0-25 | Low confidence | Hunting only, expect FPs |
| 26-50 | Medium | Investigate, don't auto-quarantine |
| 51-75 | High | Alert SOC, likely malicious |
| 76-100 | Critical | Auto-quarantine appropriate |

## Common Naming Mistakes

| Bad Name | Problem | Corrected |
|----------|---------|-----------|
| `Emotet_Detector` | Missing category, platform, date | `MAL_Win_Emotet_Loader_Jan25` |
| `MAL_Suspicious_File` | "Suspicious" is vague | `MAL_Win_Lazarus_Downloader_Jan25` |
| `rule1` | No semantic meaning | `HKTL_Multi_Mimikatz_CredDump_Jan25` |
| `MALWARE_windows_trojan` | Wrong case, wrong order | `MAL_Win_Trojan_Generic_Jan25` |
| `emotet_loader` | All lowercase | `MAL_Win_Emotet_Loader_Jan25` |
| `EmoteTLoader` | CamelCase | `MAL_Win_Emotet_Loader_Jan25` |
| `MAL Win Emotet` | Spaces | `MAL_Win_Emotet_Loader_Jan25` |
| `CobaltStrike_Beacon` | Missing category and date | `HKTL_Win_CobaltStrike_Beacon_Jan25` |

## Linter Error Codes

The `yara_lint.py` script produces these codes:

| Code | Severity | Issue | Fix |
|------|----------|-------|-----|
| E000 | Error | YARA-X compilation error | Read the compiler's source location; it points at the exact token |
| E001 | Error | Missing required metadata field (description, author, date) | Add the missing field |
| E002 | Error | Text string shorter than 4 bytes | Use a longer string, or a hex pattern with surrounding context |
| E003 | Error | Hex string shorter than 4 bytes | Extend the pattern to 4+ fixed bytes |
| E006 | Error | base64 modifier on a string shorter than 3 characters | YARA-X requires 3+ chars; lengthen or drop the modifier |
| E008 | Error | Negative array indexing, unsupported in YARA-X | `@a[-1]` → `@a[#a - 1]` |
| W001 | Warning | Rule name does not follow CATEGORY_PLATFORM_FAMILY_DATE | Rename using a standard prefix |
| W002 | Warning | Description does not start with 'Detects' | Rewrite the description |
| W003 | Warning | Description shorter than 60 characters | Explain what it catches and how |
| W004 | Warning | Missing 'reference' metadata | Add a URL to the analysis or source |
| W005 | Warning | String contains an FP-prone substring | Replace with a family-specific indicator |
| W006 | Warning | Hex string starts with a wildcard | Move fixed bytes to the front for a better atom |
| W007 | Warning | Deprecated feature used in condition | Replace `entrypoint` with `pe.entry_point`; drop PEiD patterns |
| W008 | Warning | Unbounded regex quantifier (.* or .+) | Add length bounds: `.{0,100}` |
| W009 | Warning | Condition reaches pattern or module state before any cheap pre-filter | Lead with `filesize <` or a `uintNN` magic-byte check |
| I001 | Info | Unrecognized category prefix | Use a standard prefix or document the custom one |
| I002 | Info | Description longer than 400 characters | Trim to the distinguishing detail |
| I003 | Info | `nocase` on a string longer than 20 characters | Confirm case actually varies across samples |
| I004 | Info | `xor` without an explicit key range | Use `xor(0xNN)` once you know the key |

`scripts/test_yara_rules.py` asserts this table and the linter's code registry stay
in sync, so a check cannot be added or removed without updating both.

## PR Review Checklist

When reviewing YARA rules in PRs:

### Naming & Metadata
- [ ] Name matches `{CATEGORY}_{PLATFORM}_{FAMILY}_{DATE}` format
- [ ] Category prefix is from approved list (or justified)
- [ ] Description starts with "Detects" and is 60-400 chars
- [ ] Author includes contact (email or @handle)
- [ ] Reference URL is provided and accessible
- [ ] Date matches rule creation/modification date
- [ ] Hash field contains valid SHA256 of primary sample

### String Quality
- [ ] All strings ≥4 bytes
- [ ] No API names used as indicators
- [ ] No common paths or executables
- [ ] Regex patterns are bounded
- [ ] Base64 modifier only on 3+ char strings

### Condition Quality
- [ ] Starts with `filesize <` check
- [ ] Has magic bytes check before module use
- [ ] Uses `and` instead of implicit conjunction
- [ ] Expensive operations come last

### Testing Evidence
- [ ] Matches all target samples (list sample hashes)
- [ ] Zero matches on goodware corpus (state corpus tested)
- [ ] `yr check` passes
- [ ] `yr fmt --check` passes
- [ ] Linter passes

## Enforcing Style in CI

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: yara-lint
        name: YARA Lint
        entry: uv run yara_lint.py --strict
        language: system
        files: \.yar$
        types: [file]
```

### GitHub Actions

```yaml
- name: Lint YARA rules
  run: |
    uv run yara_lint.py --strict rules/
    yr check rules/
    yr fmt --check rules/
```

Block PRs that fail linting. No exceptions for "quick fixes."

## Anti-Patterns

### Naming

- All lowercase: `emotet_loader`
- CamelCase: `EmoteTLoader`
- No category: `Emotet_Jan25`
- Spaces or special chars: `MAL Win Emotet`
- Reserved words: `rule`, `strings`, `condition`

### Metadata

- Missing description
- Description doesn't start with "Detects"
- No author attribution
- No reference URL
- Outdated date (not updated when rule modified)
