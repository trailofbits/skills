---
name: cluster-error-handling
kind: cluster
consolidated: false
covers:
  - result-discarded # RESDISC
  - drop-panic       # DROPPANIC
  - lossy-from-into  # LOSSYFROM
  - lossy-str-conversion # LOSSYSTR
---

# Cluster: Error handling flow

ID prefixes: `RESDISC`, `DROPPANIC`, `LOSSYFROM`, `LOSSYSTR`.

## Phase A

```
Grep: pattern="let\s+_\s*=\s"
Grep: pattern="impl\s+Drop\s+for"
Grep: pattern="impl\s+From<.*>\s+for|impl\s+Into<"
Grep: pattern="\bas\s+\w"
Grep: pattern="from_utf8_lossy|to_string_lossy|to_str\(\)\s*\.unwrap_or"
```

Run finders in declared order.
