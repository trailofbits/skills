# TOON Format Reference

All inter-task finding data uses [TOON format](https://github.com/toon-format/toon) for token efficiency (~40% reduction vs JSON).

## TOON Basics

- YAML-like indentation for nested objects
- CSV-style rows for uniform arrays
- `[N]{field1,field2,...}:` declares array length and headers
- Rows are comma-separated values

## Finding Summary (tabular)

For passing finding lists between tasks:

```toon
findings[3]{id,bug_class,title,location,function,confidence}:
 BOF-001,buffer-overflow,Stack overflow in parse_header,file.c:123,parse_header,High
 UAF-001,use-after-free,UAF in conn_close,conn.c:456,conn_close,Medium
 INT-001,integer-overflow,Integer overflow in calc_size,alloc.c:78,calc_size,High
```

## Finding Details (nested)

For full finding data including descriptions:

```toon
finding:
  id: BOF-001
  bug_class: buffer-overflow
  title: Stack buffer overflow in parse_header
  location: file.c:123
  function: parse_header
  confidence: High
  description: |
    Unchecked strcpy from network input allows stack buffer overflow.
  code_snippet: |
    char buf[64]; strcpy(buf, input);
  impact: Remote code execution via controlled return address
  data_flow:
    source: network input via recv()
    sink: strcpy() buffer overflow
    validation: No length check
  recommendation: Use strncpy() with sizeof(buf)-1
```

## Field Ownership

| Stage | Fields Set |
|-------|------------|
| Bug finder | id, bug_class, title, location, function, confidence, description, code_snippet, impact, data_flow, recommendation |
| Dedup-judge | consolidated grouping, merged IDs, deduplicated list |

**Final report:** Coordinator formats dedup-judge output as markdown for human consumption. All prior stages use TOON.
