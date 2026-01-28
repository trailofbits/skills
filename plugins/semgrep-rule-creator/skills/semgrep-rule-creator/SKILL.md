---
name: semgrep-rule-creator
description: Creates custom Semgrep rules for detecting security vulnerabilities, bug patterns, and code patterns. Use when writing Semgrep rules or building custom static analysis detections.
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
- Writing Semgrep rules for specific bug patterns
- Writing rules to detect security vulnerabilities in your codebase
- Writing taint mode rules for data flow vulnerabilities
- Writing rules to enforce coding standards

## When NOT to Use

Do NOT use this skill for:
- Running existing Semgrep rulesets
- General static analysis without custom rules (use `static-analysis` skill)

## Rationalizations to Reject

When writing Semgrep rules, reject these common shortcuts:

- **"The pattern looks complete"** → Still run `semgrep --test --config <rule-id>.yaml <rule-id>.<ext>` to verify. Untested rules have hidden false positives/negatives.
- **"It matches the vulnerable case"** → Matching vulnerabilities is half the job. Verify safe cases don't match (false positives break trust).
- **"Taint mode is overkill for this"** → If data flows from user input to a dangerous sink, taint mode gives better precision than pattern matching.
- **"One test is enough"** → Include edge cases: different coding styles, sanitized inputs, safe alternatives, and boundary conditions.
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
- **Read documentation first**: See [Documentation](#documentation) before writing Semgrep rules
- **Test-first is mandatory**: Never write a rule without tests
- **100% test pass is required**: "Most tests pass" is not acceptable
- **Optimization comes last**: Only simplify patterns after all tests pass
- **Avoid generic patterns**: Rules must be specific, not match broad patterns
- **Prioritize taint mode**: For data flow vulnerabilities

## Overview

This skill guides creation of Semgrep rules that detect security vulnerabilities and code patterns. Rules are created iteratively: analyze the problem, write tests first, analyze AST structure, write the rule, iterate until all tests pass, optimize the rule.

**Approach selection:**
- **Taint mode** (prioritize): Data flow issues where untrusted input reaches dangerous sinks
- **Pattern matching**: Simple syntactic patterns without data flow requirements

**Why prioritize taint mode?** Pattern matching finds syntax but misses context. A pattern `eval($X)` matches both `eval(user_input)` (vulnerable) and `eval("safe_literal")` (safe). Taint mode tracks data flow, so it only alerts when untrusted data actually reaches the sink—dramatically reducing false positives for injection vulnerabilities.

**Iterating between approaches:** It's okay to experiment. If you start with taint mode and it's not working well (e.g., taint doesn't propagate as expected, too many false positives/negatives), switch to pattern matching. Conversely, if pattern matching produces too many false positives on safe cases, try taint mode instead. The goal is a working rule—not rigid adherence to one approach.

**Output structure** - exactly 2 files in a directory named after the rule-id:
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
    severity: HIGH
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

Run tests (from rule directory): `semgrep --test --config <rule-id>.yaml <rule-id>.<ext>`

## Quick Reference

- For commands, pattern operators, and taint mode syntax, see [quick-reference.md]({baseDir}/references/quick-reference.md).
- For detailed workflow and examples, see [workflow.md]({baseDir}/references/workflow.md)

## Workflow

Copy this checklist and track progress:

```
Semgrep Rule Progress:
- [ ] Step 1: Analyze the problem (read documentation, determine approach)
- [ ] Step 2: Write tests first (create directory, add test annotations)
- [ ] Step 3: Analyze AST structure (semgrep --dump-ast)
- [ ] Step 4: Write the rule
- [ ] Step 5: Iterate until all tests pass (semgrep --test)
- [ ] Step 6: Optimize the rule (remove redundancies, re-test)
```

### 1. Analyze the Problem

Understand the bug pattern, identify the target language, determine if taint mode applies.

Before writing any rule, see [Documentation](#documentation) for required reading.

### 2. Write Tests First

**Why test-first?** Writing tests before the rule forces you to think about both vulnerable AND safe cases. Rules written without tests often have hidden false positives (matching safe cases) or false negatives (missing vulnerable variants). Tests make these visible immediately.

Create directory and test file with annotations (`# ruleid:`, `# ok:`, etc.). See [quick-reference.md]({baseDir}/references/quick-reference.md#test-file-annotations) for full syntax.

The annotation line must contain ONLY the comment marker and annotation (e.g., `# ruleid: my-rule`). No other text, comments, or code on the same line.

### 3. Analyze AST (Abstract Syntax Tree) Structure

**Why analyze AST?** Semgrep matches against the AST, not raw text. Code that looks similar may parse differently (e.g., `foo.bar()` vs `foo().bar`). The AST dump shows exactly what Semgrep sees, preventing patterns that fail due to unexpected tree structure.

```bash
semgrep --dump-ast -l <language> <rule-id>.<ext>
```

### 4. Write the Rule

See [workflow.md]({baseDir}/references/workflow.md) for detailed patterns and examples.

### 5. Iterate Until Tests Pass

```bash
semgrep --test --config <rule-id>.yaml <rule-id>.<ext>
```

For debugging taint mode rules:
```bash
semgrep --dataflow-traces -f <rule-id>.yaml <rule-id>.<ext>
```

**Verification checkpoint**: Output MUST show "All tests passed". **Only proceed when validation passes**.

### 6. Optimize the Rule

After all tests pass, remove redundant patterns (quote variants, ellipsis subsets). See [workflow.md]({baseDir}/references/workflow.md#step-6-optimize-the-rule) for detailed optimization examples and checklist.

**Task complete ONLY when**: All tests pass after optimization.


## Documentation

**REQUIRED**: Before writing any rule, use WebFetch to read **all** of these 4 links with Semgrep documentation:

1. [Rule Syntax](https://semgrep.dev/docs/writing-rules/rule-syntax) - YAML structure, operators, and rule options
2. [Pattern Syntax](https://semgrep.dev/docs/writing-rules/pattern-syntax) - Pattern matching, metavariables, and ellipsis usage
3. [ToB Testing Handbook - Semgrep](https://appsec.guide/docs/static-analysis/semgrep/advanced/) - Patterns, taint tracking, and practical examples
4. [Writing Rules Index](https://github.com/semgrep/semgrep-docs/tree/main/docs/writing-rules/) - Full documentation index (browse for taint mode, testing, etc.)
