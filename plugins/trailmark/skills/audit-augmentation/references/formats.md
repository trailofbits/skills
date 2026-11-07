# SARIF and weAudit Format Reference

## SARIF 2.1.0

SARIF (Static Analysis Results Interchange Format) is an OASIS standard for
encoding static analysis results as JSON.

### Structure Used by Trailmark

```
sarifLog
├── version: "2.1.0"
└── runs[]
    ├── tool.driver.name          → source field ("sarif:<name>")
    └── results[]
        ├── ruleId                → included in description
        ├── message.text          → included in description
        ├── level                 → "error" | "warning" | "note"
        └── locations[]
            └── physicalLocation
                ├── artifactLocation.uri   → matched to node file
                └── region
                    ├── startLine          → matched to node lines
                    └── endLine            → matched to node lines
```

### Level Values

| Level | Subgraph |
|-------|----------|
| `error` | `sarif:error` |
| `warning` (default) | `sarif:warning` |
| `note` | `sarif:note` |

### Example SARIF Result

```json
{
  "ruleId": "python.lang.security.audit.exec-detected",
  "level": "warning",
  "message": {"text": "Detected use of exec()"},
  "locations": [{
    "physicalLocation": {
      "artifactLocation": {"uri": "src/handler.py"},
      "region": {"startLine": 42, "endLine": 42}
    }
  }]
}
```

## weAudit

weAudit is a VSCode extension by Trail of Bits for collaborative security
auditing. Files are stored as `.vscode/<username>.weaudit`.

### Structure Used by Trailmark

```
root
├── clientRemote              → fallback author extraction
├── treeEntries[]             → active findings/notes
│   ├── label                 → included in description
│   ├── entryType             → 0=Finding, 1=Note
│   ├── author                → source field ("weaudit:<author>")
│   ├── details
│   │   ├── severity          → "High" | "Medium" | "Low" | "Informational"
│   │   ├── type              → finding category
│   │   └── description       → included in annotation
│   └── locations[]
│       ├── path              → relative to git root
│       ├── startLine         → 0-indexed (converted to 1-indexed)
│       └── endLine           → 0-indexed (converted to 1-indexed)
└── resolvedEntries[]         → same structure as treeEntries
```

### Entry Types

| entryType | AnnotationKind | Subgraph |
|-----------|---------------|----------|
| 0 (Finding) | `finding` | `weaudit:findings` |
| 1 (Note) | `audit_note` | `weaudit:notes` |

### Severity Values

| Severity | Subgraph |
|----------|----------|
| `High` | `weaudit:high` |
| `Medium` | `weaudit:medium` |
| `Low` | `weaudit:low` |
| `Informational` | `weaudit:informational` |

### Example weAudit Entry

```json
{
  "label": "SQL Injection in user input",
  "entryType": 0,
  "author": "alice",
  "details": {
    "severity": "High",
    "difficulty": "Low",
    "type": "Data Validation",
    "description": "User input not sanitized before SQL query.",
    "exploit": "Attacker injects malicious SQL.",
    "recommendation": "Use parameterized queries."
  },
  "locations": [{
    "path": "src/database/queries.py",
    "startLine": 41,
    "endLine": 44,
    "label": "executeQuery function",
    "description": ""
  }]
}
```

### Line Indexing

weAudit uses **0-indexed** line numbers. Trailmark uses **1-indexed** (from
tree-sitter). The augmentation module adds 1 to both `startLine` and `endLine`
during conversion.

## Paths and combining inputs

Use the same source root for every input. SARIF `artifactLocation.uri` and
weAudit `locations[].path` must identify files under that root; inspect unmatched
counts before interpreting missing intersections. URI bases and encoded paths
must be resolved using the producing tool's SARIF conventions, not by blindly
stripping prefixes.
Trailmark's normal matching supports relative paths, absolute paths and `file://`
URIs. It selects nodes by path and line overlap, preferring the tightest span.

To combine SARIF files, concatenate their complete `runs` arrays. Keep each run's
tool/rules/artifacts tables with its results so `ruleIndex` and artifact indices
remain valid. Do not concatenate results across different rule tables.

For weAudit, concatenate `treeEntries` and `resolvedEntries` only after reconciling
source roots. Preserve each entry's author (including authors previously inferred
from `clientRemote`) and all details and locations. Do not overwrite earlier entries.

For several binary graphs, call `engine.augment_binary(path)` for each on the same
engine after pre-analysis. The format has `artifact`, `functions`, and `calls`:

```json
{"artifact": {"name": "program"}, "functions": [{"symbol": "parse", "source": {"file": "src/parser.py", "line": 10}}], "calls": []}
```

Use `engine.findings()` and `engine.annotations_of(node_id)` on that same engine
to inspect full messages, severities, sources and locations. A compact intersection
is not a replacement for those annotations when writing an audit finding.
Annotations carry `kind` (`finding` or `audit_note`), a source such as
`sarif:<tool>` or `weaudit:<author>`, and a compact description such as
`[SEVERITY] rule-id: message (tool)`. Preserve the full description when reporting evidence.
