# Triage Subagent Task Prompt

Use this prompt template when spawning triage Tasks in Step 5. Use `subagent_type: static-analysis:semgrep-triager`.

## Template

```
You are a security finding triager for [LANGUAGE_CATEGORY].

## Input Files
[LIST OF JSON FILES TO TRIAGE]

## Output Directory
[OUTPUT_DIR]

## Task
For each finding:
1. Read the JSON finding
2. Read source code context (5 lines before/after)
3. Classify as TRUE_POSITIVE or FALSE_POSITIVE

## False Positive Criteria
- Test files (should add to .semgrepignore)
- Sanitized inputs (context shows validation)
- Dead code paths
- Example/documentation code
- Already has nosemgrep comment

## Output Format
Create: [OUTPUT_DIR]/[lang]-triage.json

```json
{
  "file": "[lang]-[ruleset].json",
  "total": 45,
  "true_positives": [
    {"rule": "...", "file": "...", "line": N, "reason": "..."}
  ],
  "false_positives": [
    {"rule": "...", "file": "...", "line": N, "reason": "..."}
  ]
}
```

## Report
Return summary:
- Total findings: N
- True positives: N
- False positives: N (with breakdown by reason)
```

## Variable Substitutions

| Variable | Description | Example |
|----------|-------------|---------|
| `[LANGUAGE_CATEGORY]` | Language group being triaged | Python, JavaScript, Docker |
| `[OUTPUT_DIR]` | Results directory with run number | semgrep-results-001 |

## Example: Python Triage Task

```
You are a security finding triager for Python.

## Input Files
- semgrep-results-001/python-python.json
- semgrep-results-001/python-django.json
- semgrep-results-001/python-security-audit.json
- semgrep-results-001/python-secrets.json
- semgrep-results-001/python-trailofbits.json

## Output Directory
semgrep-results-001

## Task
For each finding:
1. Read the JSON finding
2. Read source code context (5 lines before/after)
3. Classify as TRUE_POSITIVE or FALSE_POSITIVE

## False Positive Criteria
- Test files (should add to .semgrepignore)
- Sanitized inputs (context shows validation)
- Dead code paths
- Example/documentation code
- Already has nosemgrep comment

## Output Format
Create: semgrep-results-001/python-triage.json

```json
{
  "file": "python-django.json",
  "total": 45,
  "true_positives": [
    {"rule": "python.django.security.injection.sql-injection", "file": "views.py", "line": 42, "reason": "User input directly in raw SQL query"}
  ],
  "false_positives": [
    {"rule": "python.django.security.injection.sql-injection", "file": "tests/test_views.py", "line": 15, "reason": "Test file with mock data"}
  ]
}
```

## Report
Return summary:
- Total findings: 45
- True positives: 12
- False positives: 33 (18 test files, 10 sanitized inputs, 5 dead code)
```

## Triage Decision Tree

```
Finding
├── Is it in a test file? → FALSE_POSITIVE (add to .semgrepignore)
├── Is it in example/docs? → FALSE_POSITIVE
├── Does it have nosemgrep comment? → FALSE_POSITIVE (already acknowledged)
├── Is the input sanitized/validated upstream?
│   └── Check 10-20 lines before for validation → FALSE_POSITIVE if validated
├── Is the code path reachable?
│   └── Check if function is called/exported → FALSE_POSITIVE if dead code
└── None of the above → TRUE_POSITIVE
```
