# YARA Authoring Plugin

A behavior-driven skill for authoring high-quality YARA detection rules, teaching you to think and act like an expert YARA author.

## Philosophy

This skill doesn't dump YARA syntax at you. Instead, it teaches:

- **Decision trees** for common judgment calls (Is this string good enough? When to abandon an approach?)
- **Expert heuristics** (mutex names are gold, API names are garbage)
- **Rationalizations to reject** (the shortcuts that cause production failures)

An expert uses 5 tools: yarGen, yara CLI, signature-base, YARA-CI, Binarly. Everything else is noise.

## Installation

Add this plugin to your Claude Code configuration:

```bash
claude mcp add-plugin /path/to/yara-authoring
```

## Skills

### yara-rule-authoring

Guides authoring of YARA rules for malware detection with expert judgment.

**Covers:**
- Decision trees for string quality, when to abandon approaches, debugging FPs
- Expert heuristics from experienced YARA authors
- Rationalizations to reject (common shortcuts that fail)
- Naming conventions (CATEGORY_PLATFORM_FAMILY_DATE format)
- Performance optimization (atom quality, short-circuit conditions)
- Testing workflow (goodware corpus validation)

**Triggers:** YARA, malware detection, threat hunting, IOC, signature

## Scripts

The skill includes two Python scripts that require `uv` to run:

### yara_lint.py

Validates YARA rules for style, metadata, and anti-patterns:

```bash
uv run yara_lint.py rule.yar
uv run yara_lint.py --json rules/
uv run yara_lint.py --strict rule.yar
```

### atom_analyzer.py

Evaluates string quality for efficient atom extraction:

```bash
uv run atom_analyzer.py rule.yar
uv run atom_analyzer.py --verbose rule.yar
```

## Reference Documentation

| Document | Purpose |
|----------|---------|
| [style-guide.md](skills/yara-rule-authoring/references/style-guide.md) | Naming conventions, metadata requirements |
| [performance.md](skills/yara-rule-authoring/references/performance.md) | Atom theory, optimization techniques |
| [strings.md](skills/yara-rule-authoring/references/strings.md) | String selection judgment, good/bad patterns |
| [testing.md](skills/yara-rule-authoring/references/testing.md) | Validation workflow, FP investigation |

## Key Resources

- [Neo23x0 YARA Style Guide](https://github.com/Neo23x0/YARA-Style-Guide)
- [Neo23x0 Performance Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines)
- [signature-base Rule Collection](https://github.com/Neo23x0/signature-base)
- [Official YARA Documentation](https://yara.readthedocs.io/)
- [YARA-CI](https://yara-ci.cloud.virustotal.com/)

## Requirements

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) for running scripts

The scripts use PEP 723 inline metadata, so dependencies are resolved automatically by `uv run`.
