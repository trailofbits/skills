---
max_turns: 60
timeout_seconds: 2400
allowed_tools: [Read, Write, Edit, Bash, Glob, Grep, Skill, Task]
---
Audit the Solidity codebase at `/tmp/dimensional-analysis-eval/contracts` for unit
and precision bugs: places where values carrying different units, or different
decimal scales, are combined, converted, or compared incorrectly.

Write your findings to `/tmp/dimensional-analysis-eval/findings.json` in this shape:

```json
{
  "findings": [
    {
      "id": "DIM-001",
      "severity": "CRITICAL",
      "type": "dimension_mismatch",
      "location": {"file": "MarginVault.sol", "line": 64, "function": "debtOf"},
      "description": "...",
      "impact": "...",
      "recommendation": "..."
    }
  ]
}
```

Populate `location.function` with the name of the enclosing function for every
finding.

In your final message, list every finding you wrote to `findings.json`, each with
a one-line explanation of the mismatch behind it.

This run is headless: do not stop to ask for confirmation.
