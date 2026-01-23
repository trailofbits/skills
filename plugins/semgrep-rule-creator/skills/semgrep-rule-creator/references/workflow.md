# Semgrep Rule Creation Workflow

Detailed workflow for creating production-quality Semgrep rules.

## Step 1: Analyze the Problem

Before writing any code:

1. **Fetch external documentation** - See [Documentation](../SKILL.md#documentation) for required reading
2. **Understand the exact bug pattern** - What vulnerability or issue should be detected?
3. **Identify the target language** - Python, JavaScript, Java, Go, etc.
4. **Determine the approach**:
   - **Taint mode**: Data flows from untrusted source to dangerous sink
   - **Pattern matching**: Syntactic patterns without data flow

### When to Use Taint Mode

Taint mode is a powerful feature in Semgrep that can track the flow of data from one location to another. By using taint mode, you can:

- **Track data flow across multiple variables**: Trace how data moves across different variables, functions, components, and identify insecure flow paths (e.g., situations where a specific sanitizer is not used).
- **Find injection vulnerabilities**: Identify injection vulnerabilities such as SQL injection, command injection, and XSS attacks.
- **Write simple and resilient Semgrep rules**: Simplify rules that are resilient to code patterns nested in if statements, loops, and other structures.

### When to Use Pattern Matching

Use basic patterns when detecting:
- Use of deprecated/dangerous functions
- Hardcoded credentials
- Missing security headers
- Configuration issues
- Code style violations

## Step 2: Create Test Cases First

**Always write tests before the rule.**

### Directory Structure

```
<rule-id>/
├── <rule-id>.yaml
└── <rule-id>.<ext>
```

### Test Annotations

See [quick-reference.md](quick-reference.md#test-file-annotations) for annotation syntax (`ruleid:`, `ok:`, `todoruleid:`, `todook:`).

**CRITICAL**: The comment must be on the line IMMEDIATELY BEFORE the code. Semgrep reports findings on the line after the annotation.

### Test Case Design

Include test cases for:
- ✅ Clear vulnerable patterns (must match)
- ✅ Clear safe patterns (must not match)
- ✅ Edge cases and variations
- ✅ Different coding styles
- ✅ Sanitized/validated input (must not match)

## Step 3: Analyze AST Structure

Understanding how Semgrep parses code helps write precise patterns.

```bash
semgrep --dump-ast -l python test_file.py
```

Example output helps understand:
- How function calls are represented
- How variables are bound
- How control flow is structured

## Step 4: Write the Rule

Choose the appropriate pattern operators and write your rule.

For pattern operator syntax (basic matching, scope operators, metavariable filters, focus), see [quick-reference.md](quick-reference.md).

### Taint Rules

#### Basic Taint Structure

```yaml
rules:
  - id: sql-injection
    mode: taint
    languages: [python]
    severity: HIGH
    message: User input flows to SQL query
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form[...]
    pattern-sinks:
      - pattern: cursor.execute($QUERY, ...)
      - focus-metavariable: $QUERY
    pattern-sanitizers:
      - pattern: sanitize(...)
      - pattern: int(...)
```

#### Taint Source Options

```yaml
pattern-sources:
  - pattern: source(...)
    exact: true           # Only exact match is source
    by-side-effect: true  # Taints variable by side effect
```

#### Taint Sanitizer Options

```yaml
pattern-sanitizers:
  - patterns:
      - pattern: validate($X)
      - focus-metavariable: $X
    by-side-effect: true  # Sanitizes variable for subsequent use
```

#### Taint Sink with Focus

```yaml
# NOTE: Sinks default to exact: true (unlike sources/sanitizers which default to false)
pattern-sinks:
  - patterns:
      - pattern: query($SQL, $PARAMS)
      - focus-metavariable: $SQL
```

### Validate and Test

#### Validate YAML Syntax

```bash
semgrep --validate --config rule.yaml
```

#### Run Tests

```bash
cd <rule-directory>
semgrep --test --config rule.yaml test-file
```

#### Expected Output

```
1/1: ✓ All tests passed
```

#### Debug Failures

If tests fail, check:
1. **Missed lines**: Rule didn't match when it should
   - Pattern too specific
   - Missing pattern variant
2. **Incorrect lines**: Rule matched when it shouldn't
   - Pattern too broad
   - Need `pattern-not` exclusion

#### Debug Taint Rules

```bash
semgrep --dataflow-traces -f rule.yaml test_file.py
```

Shows:
- Source locations
- Sink locations
- Data flow path
- Why taint didn't propagate (if applicable)

## Step 5: Iterate Until Tests Pass

**Verification checkpoint - proceed to optimization when:**
- "All tests passed"
- No "missed lines" (false negatives)
- No "incorrect lines" (false positives)

### Common Fixes

| Problem | Solution |
|---------|----------|
| Too many matches | Add `pattern-not` exclusions |
| Missing matches | Add `pattern-either` variants |
| Wrong line matched | Adjust `focus-metavariable` |
| Taint not flowing | Check sanitizers aren't too broad |
| Taint false positive | Add sanitizer pattern |

## Example: Complete Taint Rule

**Rule** (`command-injection.yaml`):
```yaml
rules:
  - id: command-injection
    mode: taint
    languages: [python]
    severity: HIGH
    message: >-
      User input from $SOURCE flows to shell command.
      This allows command injection attacks.
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
      - pattern: request.data
    pattern-sinks:
      - pattern: os.system(...)
      - pattern: subprocess.call($CMD, shell=True, ...)
        focus-metavariable: $CMD
      - pattern: subprocess.Popen($CMD, shell=True, ...)
        focus-metavariable: $CMD
    pattern-sanitizers:
      - pattern: shlex.quote(...)
      - pattern: pipes.quote(...)
```

**Test** (`command-injection.py`):
```python
import os
import subprocess
import shlex
from flask import request

def vulnerable1():
    cmd = request.args.get('cmd')
    # ruleid: command-injection
    os.system(cmd)

def vulnerable2():
    user_input = request.form.get('input')
    # ruleid: command-injection
    subprocess.call(user_input, shell=True)

def safe_quoted():
    cmd = request.args.get('cmd')
    safe_cmd = shlex.quote(cmd)
    # ok: command-injection
    os.system(f"echo {safe_cmd}")

def safe_no_shell():
    cmd = request.args.get('cmd')
    # ok: command-injection
    subprocess.call(['echo', cmd])  # No shell=True

def safe_hardcoded():
    # ok: command-injection
    os.system("ls -la")
```

## Step 6: Optimize the Rule

After all tests pass, analyze and optimize the rule to remove redundant patterns.

### Semgrep Pattern Equivalences

Semgrep treats certain patterns as equivalent:

| Written | Also Matches | Reason |
|---------|--------------|--------|
| `"string"` | `'string'` | Quote style normalized (in languages where both are equivalent) |
| `func(...)` | `func()`, `func(a)`, `func(a,b)` | Ellipsis matches zero or more |
| `func($X, ...)` | `func($X)`, `func($X, a, b)` | Trailing ellipsis is optional |

### Common Redundancies to Remove

**1. Quote Variants**

Before:
```yaml
pattern-either:
  - pattern: hashlib.new("md5", ...)
  - pattern: hashlib.new('md5', ...)
```

After:
```yaml
pattern-either:
  - pattern: hashlib.new("md5", ...)
```

**2. Ellipsis Subsets**

Before:
```yaml
pattern-either:
  - pattern: dangerous($X, ...)
  - pattern: dangerous($X)
  - pattern: dangerous($X, $Y)
```

After:
```yaml
pattern: dangerous($X, ...)
```

**3. Consolidate with Metavariables**

Before:
```yaml
pattern-either:
  - pattern: md5($X)
  - pattern: sha1($X)
  - pattern: sha256($X)
```

After:
```yaml
patterns:
  - pattern: $FUNC($X)
  - metavariable-regex:
      metavariable: $FUNC
      regex: ^(md5|sha1|sha256)$
```

### Optimization Checklist

1. ✅ Remove patterns differing only in quote style
2. ✅ Remove patterns that are subsets of `...` patterns
3. ✅ Consolidate similar patterns using metavariable-regex
4. ✅ Remove duplicate patterns in pattern-either
5. ✅ Simplify nested pattern-either when possible
6. ✅ **Re-run tests after each optimization**

### Verify After Optimization

```bash
semgrep --test --config rule.yaml test-file
```

**Critical**: Always re-run tests after optimization. Some "redundant" patterns may actually be necessary due to AST structure differences. If any test fails, revert the optimization that caused it.

**Task complete ONLY when**: All tests pass after optimization.

## Troubleshooting

### Pattern Not Matching

1. Check AST structure: `semgrep --dump-ast -l <lang> file`
2. Verify metavariable binding
3. Check for whitespace/formatting differences
4. Try more general pattern first, then narrow down

### Taint Not Propagating

1. Use `--dataflow-traces` to see flow
2. Check if sanitizer is too broad
3. Verify source pattern matches
4. Check sink focus-metavariable

### Too Many False Positives

1. Add `pattern-not` for safe patterns
2. Add sanitizers for validation functions
3. Use `pattern-inside` to limit scope
4. Use `metavariable-regex` to filter
