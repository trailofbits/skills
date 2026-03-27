# Shared Instructions

## LSP Usage for Deep Analysis

- `goToDefinition` - Find where types/macros are defined, trace through abstractions
- `findReferences` - Find ALL uses of a variable/function to check each for issues
- `incomingCalls` - Find all callers of a vulnerable function to assess reachability
- `outgoingCalls` - Trace what functions are called, where data flows
- `hover` - Get type info, sizes, signedness

## Output Format (TOON)

All findings are stored in task metadata using TOON format for token efficiency.

### Per-Finding TOON Structure

```toon
finding:
  id: [PREFIX]-[NNN]
  bug_class: [bug-class]
  title: [Brief descriptive title]
  location: file.c:123
  function: function_name
  confidence: High|Medium|Low
  description: |
    [Why this is a vulnerability - multi-line allowed]
  code_snippet: |
    [vulnerable code]
  impact: [What an attacker could achieve]
  data_flow:
    source: [where data comes from]
    sink: [where vulnerability manifests]
    validation: [what checks exist or are missing]
  recommendation: [How to fix]
```

### Storing in Task Metadata

When storing findings via TaskUpdate, use TOON array format:

```toon
findings[N]{id,bug_class,title,location,function,confidence}:
 BOF-001,buffer-overflow,Stack overflow in parse_header,file.c:123,parse_header,High
 [more rows...]

details[N]{id,description,code_snippet,impact,recommendation}:
 BOF-001,"Unchecked strcpy...","char buf[64]; strcpy(buf, input);","RCE","Use strncpy"
 [more rows...]

data_flows[N]{id,source,sink,validation}:
 BOF-001,"network recv()","strcpy overflow","No length check"
 [more rows...]
```

This split structure keeps the summary table scannable while preserving full details.

## Quality Standards

- Verify the issue actually exists (not theoretical)
- Trace data flow to confirm attacker influence
- Check for existing validation/mitigation
- Don't report if provably safe
- Include concrete code locations, not just patterns
