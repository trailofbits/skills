# Input Normalization

Normalize every request into one candidate record before graph analysis.

## Accepted Inputs

| Input | Required fields | Notes |
|---|---|---|
| File/line | `file`, `line` | Best starting point for direct graph binding |
| Function name | `function`, optional `file` | Ambiguous across files; ask for file if many nodes match |
| SARIF result | `artifactLocation.uri`, `region` | Prefer `audit-augmentation` matching when SARIF is available |
| weAudit annotation | file, line, severity, text | Convert 0-indexed lines to Trailmark's expected source lines when needed |
| Markdown finding | title, location or symbol | Extract the claimed impact but do not assume it is true |
| Manual claim | anchor plus suspected issue | Ask for a concrete anchor if none is provided |

## Candidate Record

Use this shape in notes and final output:

```json
{
  "title": "Unchecked balance update before transfer",
  "source_type": "manual|sarif|weaudit|report|function",
  "file": "src/Vault.sol",
  "line_range": [148, 168],
  "function_hint": "withdraw(uint256)",
  "suspected_source": "external caller",
  "suspected_sink": "value transfer",
  "claimed_impact": "withdrawal without balance decrement"
}
```

## Stop Conditions

Stop and request a concrete anchor when:

- only a vulnerability class is provided
- only a package or directory is provided
- the excerpt has no file, function, line, symbol, or SARIF/weAudit location
- all matching graph nodes are test, generated, or vendor code and the user did
  not say those are in scope

## Ambiguity Handling

If multiple graph nodes match:

1. Keep all matches in the evidence packet.
2. Prefer file/line overlap over name matching.
3. Prefer the narrowest enclosing node.
4. Mark confidence `Low` unless the candidate source unambiguously identifies
   the intended node.
