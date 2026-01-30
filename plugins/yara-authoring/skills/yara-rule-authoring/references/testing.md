# YARA Rule Testing

Testing is non-negotiable. Untested rules cause alert fatigue (false positives) or missed detections (false negatives).

## Testing Philosophy

Every rule needs three validation stages:

1. **Positive validation** — Matches all target samples
2. **Negative validation** — Zero matches on goodware
3. **Edge case validation** — Handles variants, packed versions, fragments

## Validation Workflow

```
┌──────────────────────┐
│ Write initial rule   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Lint (syntax/style)  │──── Fix issues ────┐
└──────────┬───────────┘                    │
           │                                │
           ▼                                │
┌──────────────────────┐                    │
│ Test vs. samples     │──── Missing? ──────┤
└──────────┬───────────┘   (widen rule)     │
           │                                │
           ▼                                │
┌──────────────────────┐                    │
│ Test vs. goodware    │──── FPs? ──────────┤
└──────────┬───────────┘   (tighten rule)   │
           │                                │
           ▼                                │
┌──────────────────────┐                    │
│ Peer review          │──── Issues? ───────┘
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Deploy to production │
└──────────────────────┘
```

## Goodware Testing

### Platform-Specific Goodware

Test against legitimate software in your target ecosystem, not just Windows binaries:

| Platform | Goodware Corpus |
|----------|-----------------|
| **PE files** | VirusTotal goodware, clean Windows installs |
| **JavaScript/Node** | Popular npm packages (lodash, react, express, axios) |
| **VS Code extensions** | Top 100 marketplace extensions by installs |
| **Browser extensions** | Chrome Web Store popular extensions |
| **npm packages** | Download top 1000 packages by weekly downloads |
| **Python packages** | Top PyPI packages (requests, django, flask) |

**Critical:** A rule that fires on legitimate software in your target ecosystem is useless. VT's goodware corpus is PE-centric — supplement with ecosystem-appropriate files.

### VirusTotal Goodware Corpus (Recommended)

The gold standard. VirusTotal maintains a corpus of 1M+ clean files from major software vendors.

1. Upload your rule to [VirusTotal Intelligence](https://www.virustotal.com/gui/hunting)
2. Select "Goodware" corpus
3. Run retrohunt
4. Review any matches — each is a potential false positive

**Interpreting results:**

| Matches | Assessment | Action |
|---------|------------|--------|
| 0 | Excellent | Proceed to deployment |
| 1-5 | Investigate | Review matches, add exclusions or tighten strings |
| 6+ | Broken | Start over with different indicators |

### Local Testing

```bash
# Should return zero matches
yara -r rules/ /path/to/goodware/

# Count matches
yara -c rules/ /path/to/goodware/
```

### yarGen Database Lookup

Before deployment, check strings against yarGen's goodware database:

```bash
# Query strings against goodware database
python db-lookup.py -f strings.txt
```

Strings appearing in the database are likely to cause false positives.

### YARA-CI

[YARA-CI](https://yara-ci.cloud.virustotal.com/) provides cloud-based validation:

1. Connect GitHub repository
2. Each PR automatically tested
3. Reports syntax errors and performance issues
4. Integrates with VT goodware corpus

## Malware Sample Testing

### Positive Testing

```bash
# Rule should match all target samples
yara -r MAL_Win_Emotet.yar samples/emotet/

# Expected: all files listed
# If any missing: rule too narrow
```

### Variant Coverage

Test against:
- Multiple versions/builds
- Packed variants (UPX, custom packers)
- Different configurations
- Both 32-bit and 64-bit

## False Positive Investigation

When a rule matches goodware:

### 1. Identify the Match

```bash
yara -s rule.yar false_positive.exe
```

Shows which strings matched.

### 2. Analyze Why

Common causes:
- String too generic ("cmd.exe", API names)
- Shared library code
- Common development patterns
- Legitimate use of same techniques

### 3. Remediation Options

**Option A: Exclude the specific file**

```yara
strings:
    $fp_vendor = "Legitimate Software Inc"

condition:
    $malware_string and not $fp_vendor
```

**Option B: Add distinguishing string**

```yara
strings:
    $generic = "common_string"
    $specific = "unique_malware_marker"

condition:
    $generic and $specific  // Both required
```

**Option C: Tighten positional constraints**

```yara
condition:
    $marker in (0..1024) and  // Only in first 1KB
    filesize < 500KB          // Malware-typical size
```

**Option D: Replace the string**

Find a more unique indicator and remove the problematic string.

## Supply Chain Package Testing

For npm/PyPI/RubyGems rules, test against ecosystem-appropriate corpora:

### Recommended Test Corpora

| Corpus | Source | Purpose |
|--------|--------|---------|
| Top 1000 npm packages | `npm search --searchlimit=1000` | Avoid FPs on popular dependencies |
| Packages with postinstall scripts | Filter for `scripts.postinstall` in package.json | Common attack vector |
| Known malicious packages | [npm-shai-hulud-scanner](https://github.com/nickytonline/npm-shai-hulud-scanner) list | Positive validation |
| VS Code top extensions | Marketplace API | Extension-specific rules |

### Common Attack Pattern Testing

**Critical pattern:** `postinstall + network call + credential path` is the signature of supply chain attacks. Test that your rule catches this combo while ignoring legitimate build scripts.

```bash
# Build a test corpus from npm
mkdir -p test_corpus/legitimate test_corpus/suspicious

# Grab legitimate packages with postinstall (build tools)
npm pack webpack && tar -xzf webpack-*.tgz -C test_corpus/legitimate/
npm pack electron-builder && tar -xzf electron-builder-*.tgz -C test_corpus/legitimate/

# Your rule should NOT match legitimate postinstall scripts
yara -r supply_chain_rule.yar test_corpus/legitimate/
# Expected: zero matches
```

### Known Malicious Package Patterns

Rules targeting supply chain attacks should detect patterns from documented incidents:

| Incident | Key Indicators | Reference |
|----------|----------------|-----------|
| chalk/debug (Sept 2025) | `runmask`, `checkethereumw`, ERC-20 selectors | Stairwell |
| os-info-checker-es6 | Variation selectors, eval+atob | Veracode |
| event-stream | Flatmap dependency, Bitcoin wallet targeting | npm advisory |

**Positive validation:** Test your rule against recreated (defanged) versions of known malicious packages to ensure detection.

## Checklist

Before any rule goes to production:

- [ ] Syntax validates (`yara -v rule.yar`)
- [ ] Matches all target samples (positive testing)
- [ ] Zero matches on goodware corpus (negative testing)
- [ ] Tested against packed variants if applicable
- [ ] Performance acceptable (< 1s per file on average)
- [ ] Peer reviewed by second analyst
- [ ] Version and changelog updated

### Supply Chain Rule Additions

- [ ] Tested against top 100 packages in target ecosystem
- [ ] Does not match legitimate postinstall scripts (webpack, electron-builder, etc.)
- [ ] Validated against known malicious package patterns
