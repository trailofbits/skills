# Shared Instructions

## LSP Usage for Deep Analysis

- `goToDefinition` - Find where types/macros are defined, trace through abstractions
- `findReferences` - Find ALL uses of a variable/function to check each for issues
- `incomingCalls` - Find all callers of a vulnerable function to assess reachability
- `outgoingCalls` - Trace what functions are called, where data flows
- `hover` - Get type info, sizes, signedness

## Output Format

For each finding:
```
## Finding ID: [PREFIX]-[NNN]

**Title:** [Brief descriptive title]
**Location:** file.c:123
**Function:** function_name
**Confidence:** High/Medium/Low

### Vulnerable Code
```c
[code snippet]
```

### Analysis
[Why this is a vulnerability]

### Data Flow
- Source: [where data comes from]
- Sink: [where vulnerability manifests]
- Validation: [what checks exist or are missing]

### Impact
[What an attacker could achieve]
```

## Quality Standards

- Verify the issue actually exists (not theoretical)
- Trace data flow to confirm attacker influence
- Check for existing validation/mitigation
- Don't report if provably safe
- Include concrete code locations, not just patterns
