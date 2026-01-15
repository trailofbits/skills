---
name: semgrep-rule-creator
description: Create custom Semgrep rules for detecting bug patterns and security vulnerabilities. This skill should be used when the user explicitly asks to "create a Semgrep rule", "write a Semgrep rule", "make a Semgrep rule", "build a Semgrep rule", or requests detection of a specific bug pattern, vulnerability, or insecure code pattern using Semgrep.
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - WebFetch
---

# Semgrep Rule Creator

Create production-quality Semgrep rules with proper testing and validation.

## When to Use

**Ideal scenarios:**
- Creating custom detection rules for specific bug patterns
- Building security vulnerability detectors for your codebase
- Writing taint-mode rules for data flow vulnerabilities
- Developing rules to enforce coding standards

## When NOT to Use

Do NOT use this skill for:
- Running existing Semgrep rulesets (use the `semgrep` skill instead)
- General static analysis without custom rules (use `static-analysis` plugin)
- One-off scans where existing rules suffice
- Non-Semgrep pattern matching needs

## Rationalizations to Reject

When creating Semgrep rules, reject these common shortcuts:

- **"The pattern looks complete"** → Still run `semgrep --test --config rule.yaml test-file` to verify. Untested rules have hidden false positives/negatives.
- **"It matches the vulnerable case"** → Matching vulnerabilities is half the job. Verify safe cases don't match (false positives break trust).
- **"Taint mode is overkill for this"** → If data flows from user input to a dangerous sink, taint mode gives better precision than pattern matching.
- **"One test case is enough"** → Include edge cases: different coding styles, sanitized inputs, safe alternatives, and boundary conditions.
- **"I'll optimize the patterns first"** → Write correct patterns first, optimize after all tests pass. Premature optimization causes regressions.
- **"The AST dump is too complex"** → The AST reveals exactly how Semgrep sees code. Skipping it leads to patterns that miss syntactic variations.

## Anti-Patterns

**Too broad** - matches everything, useless for detection:
```yaml
# BAD: Matches any function call
pattern: $FUNC(...)

# GOOD: Specific dangerous function
pattern: eval(...)
```

**Missing safe cases in tests** - leads to undetected false positives:
```python
# BAD: Only tests vulnerable case
# ruleid: my-rule
dangerous(user_input)

# GOOD: Include safe cases to verify no false positives
# ruleid: my-rule
dangerous(user_input)

# ok: my-rule
dangerous(sanitize(user_input))

# ok: my-rule
dangerous("hardcoded_safe_value")
```

**Overly specific patterns** - misses variations:
```yaml
# BAD: Only matches exact format
pattern: os.system("rm " + $VAR)

# GOOD: Matches all os.system calls with taint tracking
mode: taint
pattern-sinks:
  - pattern: os.system(...)
```

## Strictness Level

This workflow is **strict** - do not skip steps:
- **Test-first is mandatory**: Never write a rule without test cases
- **100% test pass is required**: "Most tests pass" is not acceptable
- **Optimization comes last**: Only simplify patterns after all tests pass
- **Documentation reading is required**: Fetch external docs before writing complex rules

## Overview

This skill guides creation of Semgrep rules that detect security vulnerabilities and bug patterns. Rules are created iteratively: write test cases first, analyze AST structure, write the rule, then iterate until all tests pass.

**Approach selection:**
- **Taint mode** (prioritize): Data flow issues where untrusted input reaches dangerous sinks
- **Pattern matching**: Simple syntactic patterns without data flow requirements

**Why prioritize taint mode?** Pattern matching finds syntax but misses context. A pattern `eval($X)` matches both `eval(user_input)` (vulnerable) and `eval("safe_literal")` (safe). Taint mode tracks data flow, so it only alerts when untrusted data actually reaches the sink—dramatically reducing false positives for injection vulnerabilities.

**Iterating between approaches:** It's okay to experiment. If you start with taint mode and it's not working well (e.g., taint doesn't propagate as expected, too many false positives/negatives), switch to pattern matching. Conversely, if pattern matching produces too many false positives on safe code, try taint mode instead. The goal is a working rule—not rigid adherence to one approach.

**Output structure** - exactly two files in a directory named after the rule ID:
```
<rule-id>/
├── <rule-id>.yaml     # Semgrep rule
└── <rule-id>.<ext>    # Test file with ruleid/ok annotations
```

## Quick Start

```yaml
rules:
  - id: insecure-eval
    languages: [python]
    severity: ERROR
    message: User input passed to eval() allows code execution
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
    pattern-sinks:
      - pattern: eval(...)
```

Test file (`insecure-eval.py`):
```python
# ruleid: insecure-eval
eval(request.args.get('code'))

# ok: insecure-eval
eval("print('safe')")
```

Run tests: `semgrep --test --config rule.yaml test-file`

## Quick Reference

| Task | Command |
|------|---------|
| Run tests | `semgrep --test --config rule.yaml test-file` |
| Validate YAML | `semgrep --validate --config rule.yaml` |
| Dump AST | `semgrep --dump-ast -l <lang> <file>` |
| Debug taint flow | `semgrep --dataflow-traces -f rule.yaml file` |
| Run single rule | `semgrep -f rule.yaml <file>` |

| Pattern Operator | Purpose |
|------------------|---------|
| `pattern` | Match single pattern |
| `patterns` | AND - all must match |
| `pattern-either` | OR - any can match |
| `pattern-not` | Exclude matches |
| `pattern-inside` | Must be inside scope |
| `metavariable-regex` | Filter by regex |
| `focus-metavariable` | Report on specific part |

| Taint Component | Purpose |
|-----------------|---------|
| `pattern-sources` | Where tainted data originates |
| `pattern-sinks` | Dangerous functions receiving taint |
| `pattern-sanitizers` | Functions that clean taint |
| `pattern-propagators` | Custom taint propagation |

## Workflow

### 1. Analyze the Problem

Understand the bug pattern, identify target language, determine if taint mode applies.

Before writing complex rules, see [Documentation](#documentation) for required reading.

### 2. Create Test Cases First

**Why test-first?** Writing tests before the rule forces you to think about both vulnerable AND safe patterns. Rules written without tests often have hidden false positives (matching safe code) or false negatives (missing vulnerable variants). Tests make these visible immediately.

Create directory and test file with annotations:
- `// ruleid: <id>` - Line BEFORE code that SHOULD match
- `// ok: <id>` - Line BEFORE code that should NOT match

### 3. Analyze AST Structure

**Why analyze AST?** Semgrep matches against the Abstract Syntax Tree, not raw text. Code that looks similar may parse differently (e.g., `foo.bar()` vs `foo().bar`). The AST dump shows exactly what Semgrep sees, preventing patterns that fail due to unexpected tree structure.

```bash
semgrep --dump-ast -l <language> <test-file>
```

### 4. Write the Rule

See [workflow.md]({baseDir}/references/workflow.md) for detailed patterns and examples.

### 5. Iterate Until Tests Pass

```bash
semgrep --test --config rule.yaml test-file
```

**Verification checkpoint**: Output MUST show `✓ All tests passed`. Do not proceed to optimization until this is achieved.

For debugging taint rules:
```bash
semgrep --dataflow-traces -f rule.yaml test-file
```

### 6. Optimize the Rule

**After all tests pass**, analyze the rule for redundant or unnecessary patterns:

**Common optimizations:**
- **Quote variants**: Semgrep treats `"` and `'` as equivalent - remove duplicate patterns
- **Subset patterns**: `func(...)` already matches `func()` - remove the more specific one
- **Redundant ellipsis**: `func($X, ...)` covers `func($X)` - keep only the general form

**Example - Before optimization:**
```yaml
pattern-either:
  - pattern: hashlib.md5(...)
  - pattern: md5(...)
  - pattern: hashlib.new("md5", ...)
  - pattern: hashlib.new('md5', ...)    # Redundant - quotes equivalent
  - pattern: hashlib.new("md5")         # Redundant - covered by ... variant
  - pattern: hashlib.new('md5')         # Redundant - quotes + covered
```

**After optimization:**
```yaml
pattern-either:
  - pattern: hashlib.md5(...)
  - pattern: md5(...)
  - pattern: hashlib.new("md5", ...)    # Covers all quote/argument variants
```

**Optimization checklist:**
1. Remove patterns differing only in quote style (`"` vs `'`)
2. Remove patterns that are subsets of more general patterns (with `...`)
3. Consolidate similar patterns using metavariables where possible
4. **Re-run tests after optimization** to ensure no regressions

```bash
semgrep --test --config rule.yaml test-file
```

**Final verification**: Output MUST show `✓ All tests passed` after optimization. If any test fails, revert the optimization that caused it.

**Task complete ONLY when**: All tests pass after optimization.

## Key Requirements

- **Read documentation first**: Fetch official Semgrep docs before creating rules
- **Tests must pass 100%**: Do not finish until all tests pass
- **`ruleid:` placement**: Comment goes on line IMMEDIATELY BEFORE the flagged code
- **Avoid generic patterns**: Rules must be specific, not match broad patterns
- **Prioritize taint mode**: For data flow vulnerabilities

## Documentation

**REQUIRED**: Before creating any rule, use WebFetch to read this Semgrep documentation:

- [Rule Syntax](https://semgrep.dev/docs/writing-rules/rule-syntax) - YAML structure, operators, and rule options
- [Pattern Syntax](https://semgrep.dev/docs/writing-rules/pattern-syntax) - Pattern matching, metavariables, and ellipsis usage
- [Testing Rules](https://semgrep.dev/docs/writing-rules/testing-rules) - Testing rules to properly catch code patterns and avoid false positives
- [Writing Rules Index](https://github.com/semgrep/semgrep-docs/tree/main/docs/writing-rules/) - Full documentation index (browse for taint mode, testing, etc.)
- [Trail of Bits Testing Handbook - Semgrep](https://appsec.guide/docs/static-analysis/semgrep/advanced/) - Advanced patterns, taint tracking, and practical examples

## Next Steps

- For detailed workflow and examples, see [workflow.md]({baseDir}/references/workflow.md)
- For pattern syntax quick reference, see [quick-reference.md]({baseDir}/references/quick-reference.md)
