# Scanner Subagent Task Prompt

Use this prompt template when spawning scanner Tasks in Step 4. Use `subagent_type: static-analysis:semgrep-scanner`.

## Template

```
You are a Semgrep scanner for [LANGUAGE_CATEGORY].

## Task
Run Semgrep scans for [LANGUAGE] files and save results to [OUTPUT_DIR].

## Pro Engine Status: [PRO_AVAILABLE: true/false]

## APPROVED RULESETS (from user-confirmed plan)
[LIST EXACT RULESETS USER APPROVED - DO NOT SUBSTITUTE]

Example:
- p/python
- p/django
- p/security-audit
- p/secrets
- https://github.com/trailofbits/semgrep-rules

## Commands to Run (in parallel)

### Generate commands for EACH approved ruleset:
```bash
semgrep [--pro if available] --metrics=off --config [RULESET] --json -o [OUTPUT_DIR]/[lang]-[ruleset].json --sarif-output=[OUTPUT_DIR]/[lang]-[ruleset].sarif [TARGET] &
```

Wait for all to complete:
```bash
wait
```

## Critical Rules
- Use ONLY the rulesets listed above - do not add or remove any
- Always use --metrics=off (prevents sending telemetry to Semgrep servers)
- Use --pro when Pro is available (enables cross-file taint tracking)
- Run all rulesets in parallel with & and wait
- For GitHub URLs, clone the repo first if not cached locally

## Output
Report:
- Number of findings per ruleset
- Any scan errors
- File paths of JSON results
- [If Pro] Note any cross-file findings detected
```

## Variable Substitutions

| Variable | Description | Example |
|----------|-------------|---------|
| `[LANGUAGE_CATEGORY]` | Language group being scanned | Python, JavaScript, Docker |
| `[LANGUAGE]` | Specific language | Python, TypeScript, Go |
| `[OUTPUT_DIR]` | Results directory with run number | semgrep-results-001 |
| `[PRO_AVAILABLE]` | Whether Pro engine is available | true, false |
| `[RULESET]` | Semgrep ruleset identifier | p/python, https://github.com/... |
| `[TARGET]` | Directory to scan | . (current dir) |

## Example: Python Scanner Task

```
You are a Semgrep scanner for Python.

## Task
Run Semgrep scans for Python files and save results to semgrep-results-001.

## Pro Engine Status: true

## APPROVED RULESETS (from user-confirmed plan)
- p/python
- p/django
- p/security-audit
- p/secrets
- https://github.com/trailofbits/semgrep-rules

## Commands to Run (in parallel)
```bash
semgrep --pro --metrics=off --config p/python --json -o semgrep-results-001/python-python.json --sarif-output=semgrep-results-001/python-python.sarif . &
semgrep --pro --metrics=off --config p/django --json -o semgrep-results-001/python-django.json --sarif-output=semgrep-results-001/python-django.sarif . &
semgrep --pro --metrics=off --config p/security-audit --json -o semgrep-results-001/python-security-audit.json --sarif-output=semgrep-results-001/python-security-audit.sarif . &
semgrep --pro --metrics=off --config p/secrets --json -o semgrep-results-001/python-secrets.json --sarif-output=semgrep-results-001/python-secrets.sarif . &
semgrep --pro --metrics=off --config https://github.com/trailofbits/semgrep-rules --json -o semgrep-results-001/python-trailofbits.json --sarif-output=semgrep-results-001/python-trailofbits.sarif . &
wait
```

## Critical Rules
- Use ONLY the rulesets listed above - do not add or remove any
- Always use --metrics=off
- Use --pro when Pro is available
- Run all rulesets in parallel with & and wait

## Output
Report:
- Number of findings per ruleset
- Any scan errors
- File paths of JSON results
- Note any cross-file findings detected
```
