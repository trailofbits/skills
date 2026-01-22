# Semgrep Rule Quick Reference

## Required Rule Fields

```yaml
rules:
  - id: rule-id-here          # Unique identifier (lowercase, hyphens)
    languages:                 # Target language(s)
      - python
    severity: HIGH            # LOW, MEDIUM, HIGH, CRITICAL (ERROR/WARNING/INFO are legacy)
    message: Description      # Shown when rule matches
    pattern: code(...)        # OR use patterns/pattern-either/mode:taint
```

## Language Keys

Common: `python`, `javascript`, `typescript`, `jsx`, `java`, `go`, `ruby`, `c`, `cpp`, `csharp`, `php`, `rust`, `kotlin`, `swift`, `scala`, `terraform`, `solidity`, `generic`, `json`, `yaml`, `html`, `bash`, `dockerfile`

## Pattern Operators

### Basic Matching
```yaml
pattern: foo(...)              # Match function call
patterns:                      # AND - all must match
  - pattern: $X
  - pattern-not: safe($X)
pattern-either:                # OR - any can match
  - pattern: foo(...)
  - pattern: bar(...)
pattern-regex: ^foo.*bar$      # PCRE2 regex matching (multiline mode)
```

### Metavariables
- `$VAR` - Match any single expression
  - **Must be uppercase**: `$X`, `$FUNC`, `$VAR_1` (NOT `$x`, `$var`)
- `$_` - Anonymous metavariable (matches but doesn't bind)
- `$...VAR` - Match zero or more arguments (ellipsis metavariable)
- `...` - Ellipsis, match anything in between

### Deep Expression Matching
```yaml
<... $EXPR ...>               # Recursively match pattern in nested expressions
```

### Scope Operators
```yaml
pattern-inside: |              # Must be inside this pattern
  def $FUNC(...):
    ...
pattern-not-inside: |          # Must NOT be inside this pattern
  with $CTX:
    ...
```

### Negation
```yaml
pattern-not: safe(...)         # Exclude this pattern
pattern-not-regex: ^test_      # Exclude by regex
```

### Metavariable Filters
```yaml
metavariable-regex:
  metavariable: $FUNC
  regex: (unsafe|dangerous).*

metavariable-pattern:
  metavariable: $ARG
  pattern: request.$X

metavariable-comparison:
  metavariable: $NUM
  comparison: $NUM > 1024
```

### Focus
```yaml
focus-metavariable: $TARGET    # Report finding on this metavariable only
```

## Taint Mode

```yaml
rules:
  - id: taint-rule
    mode: taint
    languages: [python]
    severity: HIGH
    message: Tainted data reaches sink
    pattern-sources:
      - pattern: user_input()
      - pattern: request.args.get(...)
    pattern-sinks:
      - pattern: eval(...)
      - pattern: os.system(...)
    pattern-sanitizers:           # Optional
      - pattern: sanitize(...)
      - pattern: escape(...)
    pattern-propagators:          # Pro feature - intraprocedural only
      - pattern: $DST.append($SRC)
        from: $SRC
        to: $DST
```

### Taint Options
```yaml
pattern-sources:
  - pattern: source(...)
    exact: true                   # Only exact match is source (default: false)
    by-side-effect: true          # Taints variable by side effect
    control: true                 # Pro: control flow source

pattern-sanitizers:
  - pattern: sanitize($X)
    exact: true                   # Only exact match (default: false)
    by-side-effect: true          # Sanitizes by side effect

pattern-sinks:
  - pattern: sink(...)
    exact: false                  # Subexpressions also sinks (default: true)
    at-exit: true                 # Pro: only match at function exit points
```

## Rule Options

```yaml
options:
  constant_propagation: true      # Default: true
  symbolic_propagation: true      # Track symbolic values
  taint_assume_safe_functions: false
  taint_assume_safe_indexes: false
  taint_assume_safe_booleans: false
  taint_assume_safe_numbers: false
```

## Test File Annotations

```python
# ruleid: my-rule-id
vulnerable_code()              # This line MUST match

# ok: my-rule-id
safe_code()                    # This line must NOT match

# todoruleid: my-rule-id
future_detection()             # Known limitation, should match later

# todook: my-rule-id
future_fp_fix()                # Known FP, should not match later
```

## Common Patterns by Language

### Python
```yaml
pattern: os.system($CMD)
pattern: subprocess.call($CMD, shell=True, ...)
pattern: eval($CODE)
pattern: pickle.loads($DATA)
pattern: $CURSOR.execute($QUERY, ...)
```

### JavaScript
```yaml
pattern: eval($CODE)
pattern: document.innerHTML = $DATA
pattern: $EL.innerHTML = $DATA
pattern: new Function($CODE)
pattern: $DB.query($SQL)
```

### Java
```yaml
pattern: Runtime.getRuntime().exec($CMD)
pattern: (Statement $S).executeQuery($SQL)
pattern: new ProcessBuilder($CMD, ...)
```

### Go
```yaml
pattern: exec.Command($CMD, ...)
pattern: template.HTML($DATA)
pattern: $DB.Query($SQL, ...)
```

## Debugging Commands

```bash
# Test rules
semgrep --test --config rule.yaml test-file

# Validate YAML syntax
semgrep --validate --config rule.yaml

# Run with dataflow traces (for taint rules)
semgrep --dataflow-traces -f rule.yaml test-file.py

# Dump AST to understand code structure
semgrep --dump-ast -l python test-file.py

# Run single rule
semgrep -f rule.yaml test-file.py
```

## Common Pitfalls

1. **Wrong annotation line**: `ruleid:` must be on the line IMMEDIATELY BEFORE the finding
2. **Too generic patterns**: Avoid `pattern: $X` without constraints
3. **Missing ellipsis**: Use `...` to match variable arguments
4. **Taint not flowing**: Check if sanitizer is too broad
5. **YAML syntax errors**: Validate with `semgrep --validate`
