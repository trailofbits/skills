# Semgrep Advanced Scanning

## Performance Optimization

### Parallel Execution

Run multiple rulesets in parallel:

```bash
# Background each ruleset, then wait
semgrep --metrics=off --config p/python --json -o results/python.json . &
semgrep --metrics=off --config p/security-audit --include="*.py" --json -o results/security.json . &
semgrep --metrics=off --config p/secrets --include="*.py" --json -o results/secrets.json . &
wait
```

### File Descriptor Limits

For large codebases:

```bash
ulimit -n 4096
```

### Timing Analysis

Identify slow rules:

```bash
semgrep --metrics=off --config p/security-audit --time .
```

### Scoping Scans

Limit scan to specific paths or file types:

```bash
# Only Python files
semgrep --metrics=off --config p/security-audit --include="*.py" .

# Exclude test directories
semgrep --metrics=off --config p/python --exclude="**/test/**" --exclude="**/tests/**" .

# Specific directory
semgrep --metrics=off --config p/python src/
```

## Output Formats

### JSON (for automation)

```bash
semgrep --metrics=off --config p/python --json -o results.json .
```

JSON structure:
```json
{
  "results": [...],
  "errors": [...],
  "paths": {
    "scanned": [...],
    "skipped": [...]
  }
}
```

### SARIF (for code review tools)

```bash
semgrep --metrics=off --config p/python --sarif -o results.sarif .
```

Compatible with:
- VS Code SARIF Explorer
- GitHub Code Scanning
- Azure DevOps

### Dataflow Traces

Show how tainted values flow to sinks:

```bash
semgrep --metrics=off --dataflow-traces --config p/python .
```

Output shows the path from source to sink:

```
Taint comes from:
  app.py
    12┆ user_input = request.args.get("id")

This is how taint reaches the sink:
  app.py
    15┆ cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
```

## Filtering Results

### By Severity

```bash
# Only errors
semgrep --metrics=off --config p/python --severity ERROR .

# Errors and warnings
semgrep --metrics=off --config p/python --severity ERROR --severity WARNING .
```

### By Rule ID

```bash
# Exclude specific rules
semgrep --metrics=off --config p/python --exclude-rule python.lang.security.audit.eval-detected .
```

## Handling Large Codebases

### Incremental Scanning

Scan only changed files (requires git):

```bash
# Files changed in last commit
git diff --name-only HEAD~1 | xargs semgrep --metrics=off --config p/python

# Files changed vs main branch
git diff --name-only main | xargs semgrep --metrics=off --config p/python
```

### Splitting by Directory

For very large repos, split scans:

```bash
# Scan each top-level directory in parallel
for dir in src lib app; do
  semgrep --metrics=off --config p/python --json -o "results/${dir}.json" "$dir" &
done
wait
```

## Suppression

### .semgrepignore

Create `.semgrepignore` in repo root:

```
# Directories
vendor/
node_modules/
**/testdata/
**/fixtures/

# File patterns
*.min.js
*.generated.go

# Include gitignore patterns
:include .gitignore
```

### Inline Comments

```python
# Suppress specific rule
password = get_from_vault()  # nosemgrep: hardcoded-password

# Suppress with reason
dangerous_call()  # nosemgrep: security-audit - validated upstream
```
