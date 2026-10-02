# YARA-X Authoring Plugin

A behavior-driven skill for authoring high-quality YARA-X detection rules, teaching you to think and act like an expert YARA author.

> **YARA-X Focus:** This skill targets [YARA-X](https://virustotal.github.io/yara-x/), the Rust-based successor to legacy YARA. YARA-X powers VirusTotal's Livehunt/Retrohunt production systems and is 5-10x faster for regex-heavy rules. Legacy YARA (C implementation) is in maintenance mode.

## Philosophy

This skill doesn't dump YARA syntax at you. Instead, it teaches:

- **Decision trees** for common judgment calls (Is this string good enough? When to abandon an approach?)
- **Expert heuristics** (mutex names are gold, API names are garbage)
- **Rationalizations to reject** (the shortcuts that cause production failures)

An expert uses 5 tools: yarGen, FLOSS, `yr` CLI, signature-base, YARA-CI. Everything else is noise.

## Installation

### YARA-X CLI

```bash
# macOS
brew install yara-x

# Or from source
cargo install yara-x

# Verify installation
yr --version
```

### Plugin

```
/plugin marketplace add trailofbits/skills
/plugin install yara-authoring
```

The scripts declare their dependencies with PEP 723 inline metadata, so `uv run`
resolves the `yara-x` Python package on first use. No separate install step.

## Skills

### yara-rule-authoring

Guides authoring of YARA-X rules for malware detection with expert judgment.

**Covers:**
- Decision trees for string quality, when to abandon approaches, debugging FPs
- Expert heuristics from experienced YARA authors
- Rationalizations to reject (common shortcuts that fail)
- Naming conventions (CATEGORY_PLATFORM_FAMILY_DATE format)
- Performance optimization (atom quality, short-circuit conditions)
- Testing workflow (goodware corpus validation)
- **YARA-X migration guide** for converting legacy rules
- **Chrome extension analysis** with `crx` module
- **Android DEX analysis** with `dex` module

**Triggers:** YARA, YARA-X, malware detection, threat hunting, IOC, signature

## Scripts

The Bash review helper runs the two Python checkers plus the YARA-X CLI. The
Python commands are documented separately below.

### review.sh

Run syntax, formatting, lint, and atom checks together without modifying the rules:

```bash
review_dir=$(mktemp -d)
printf 'Review output directory: %s\n' "$review_dir"
bash skills/yara-rule-authoring/scripts/review.sh rules/ > "$review_dir/review.json"
```

Run that checkout-relative command from the plugin root, or use the skill's
`{baseDir}`-qualified command. Pass a single rule file instead of `rules/` when needed.

The helper requires Bash and `jq` 1.6+ in addition to `uv` and the `yr` CLI. It checks
directories recursively and emits each command's exit status and complete combined
stdout/stderr in a JSON **string** per check, not a nested lint JSON object. Do not
parse an `output` string as JSON: it can include compiler errors or other diagnostics.
A failed check makes the helper exit non-zero after writing
the report; missing, unreadable or empty inputs give all four checks explicit not-run
statuses. Missing/old jq exits 2 before JSON can be produced. Directory recursion was
integration-tested with YARA-X 1.20.0; older versions must support `--recursive` on
both `check` and `fmt`. The individual commands below remain
available for focused checks and their existing options.

### yara_lint.py

The two Python scripts accept a file or directory and fail if no rules are inspected.
The linter compiles each rule with YARA-X, then checks style, metadata, and anti-patterns.
See [style-guide.md](skills/yara-rule-authoring/references/style-guide.md#linter-error-codes)
for the full code table.

```bash
uv run skills/yara-rule-authoring/scripts/yara_lint.py rule.yar
uv run skills/yara-rule-authoring/scripts/yara_lint.py --json rules/
uv run skills/yara-rule-authoring/scripts/yara_lint.py --strict rule.yar   # warnings fail too
```

### atom_analyzer.py

Evaluates string quality for efficient atom extraction:

```bash
uv run skills/yara-rule-authoring/scripts/atom_analyzer.py rule.yar
uv run skills/yara-rule-authoring/scripts/atom_analyzer.py --verbose rule.yar
uv run skills/yara-rule-authoring/scripts/atom_analyzer.py --no-color rule.yar
```

Both import `yara_rules.py`, a dependency-free module holding the parsing and
analysis logic. `test_yara_rules.py` covers it; `make python-tests` picks it up.
Redirected atom reports omit terminal color automatically; `--no-color` and
`NO_COLOR` also disable it. Historical bundled examples are not deployment-ready
templates; see [their current review notes](skills/yara-rule-authoring/references/example-review.md).

## Reference Documentation

| Document | Purpose |
|----------|---------|
| [style-guide.md](skills/yara-rule-authoring/references/style-guide.md) | Naming conventions, metadata requirements |
| [performance.md](skills/yara-rule-authoring/references/performance.md) | Atom theory, optimization techniques |
| [strings.md](skills/yara-rule-authoring/references/strings.md) | String selection judgment, good/bad patterns |
| [testing.md](skills/yara-rule-authoring/references/testing.md) | Validation workflow, FP investigation |

## Key Resources

- [YARA-X Documentation](https://virustotal.github.io/yara-x/) (official)
- [YARA-X GitHub](https://github.com/VirusTotal/yara-x)
- [Neo23x0 YARA Style Guide](https://github.com/Neo23x0/YARA-Style-Guide)
- [Neo23x0 Performance Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines)
- [signature-base Rule Collection](https://github.com/Neo23x0/signature-base)
- [YARA-CI](https://yara-ci.cloud.virustotal.com/)

## Requirements

- Python 3.11+
- Bash and jq 1.6+ for the combined review helper
- [uv](https://github.com/astral-sh/uv) for running scripts
- [YARA-X](https://virustotal.github.io/yara-x/) CLI (`yr`)

The real review integration tests require all these tools; missing prerequisites
are test failures, not silent skips. No malware download or execution is needed.

The scripts use PEP 723 inline metadata, so dependencies are resolved automatically by `uv run`.

## Migrating from Legacy YARA

If you have existing rules written for legacy YARA:

1. **Run validation:** `yr check --relaxed-re-syntax rules/`
2. **Fix issues identified** (see SKILL.md migration section)
3. **Validate without relaxed mode:** `yr check rules/`

> **Note:** Use `--relaxed-re-syntax` only as a temporary diagnostic tool.
> Fix all identified issues rather than relying on relaxed mode permanently.

Common migration issues:
- Unescaped `{` in regex patterns
- Invalid escape sequences (`\R` → `\\R`)
- Base64 patterns on strings < 3 characters
- Negative array indexing
