---
name: sloc-initial-sweep
description: Calculate logical or physical SLOC for codebase audits with detailed per-folder and per-language breakdowns
version: 1.0.0
category: code-analysis
tags: [audit, metrics, sloc, smart-contracts, complexity]
author: Cryptanu
requires: [python3]
---

# SLOC/NSLOC Initial Sweep

## Purpose

Perform an initial Source Lines of Code (SLOC) analysis for codebase audit preparation. This skill helps quickly understand codebase size, complexity, and distribution across modules.

Use this as the **first step** in any audit workflow to:
- Estimate audit scope and effort
- Identify largest modules for prioritized review
- Track codebase evolution over time
- Generate baseline metrics for reports

---

## When to Use
- You need audit scoping or effort estimates before deep review.
- You want to rank modules/files by size to set reading order.
- You need before/after deltas for upgrades or refactors.
- You’re comparing logical vs physical SLOC for reporting.

## When NOT to Use
- The repository is huge (>500 files) and scope is unconfirmed—confirm scope first.
- You need semantic complexity metrics (use static-analysis/linters instead).
- You want test coverage (run coverage tools, not SLOC).

## Rationalizations to Reject
- “Physical SLOC is enough for Solidity” → use logical SLOC for complexity.
- “Scanning everything is fine” → confirm scope and exclusions before large scans.
- “Mocks/tests always excluded” → decide explicitly; report if included/excluded.

---

## Prerequisites

- [ ] Python 3.8+ available in environment.
- [ ] Target repository accessible and readable.
- [ ] Confirmed scope with user (directories, languages, test inclusion).
- [ ] `baseDir` set to this plugin root (so scripts live at `{baseDir}/skills/sloc-initial-sweep/scripts/`).

---

## Instructions for Agent

### Step 1: Scope Selection

**Ask the user to clarify:**

1. **Which directories to scan?**
   - Common: `contracts/`, `src/`, `lib/`, `scripts/`
   - Exclude: `node_modules/`, `vendor/`, `build/`, `artifacts/`, `cache/`

2. **Should tests/mocks be included?**
   - Option A: **Exclude** (production code only)
   - Option B: **Include separately** (for transparency)
   - Option C: **Include all** (full codebase)

3. **Which file extensions?**
   - Solidity: `.sol`
   - TypeScript: `.ts`
   - JavaScript: `.js`
   - Python: `.py`
   - Rust: `.rs`
   - Go: `.go`
   - Vyper: `.vy`

4. **Any custom exclusions?**
   - Deployment files, migration scripts, generated code, etc.

**Default recommendation for smart contract audits:**
- Include: `contracts/` (excluding `contracts/mocks/` and `contracts/test/`)
- Extensions: `.sol` only
- Method: Logical SLOC

---

### Step 2: Choose Counting Method

**Present options:**

#### Option A: Logical SLOC (NCSS - Recommended)
- Counts executable/declarative **statements**, not physical lines
- Multi-line expressions count as **one** statement
- Better reflects code complexity
- **Use for:** Audit effort estimation, complexity assessment

**Counting rules:**
- Each `;`-terminated statement (excluding `for(;;)` header semicolons)
- Control structures: `if`, `else`, `for`, `while`, `do`, `switch`, `case`, `default`, `try`, `catch`, `assembly`, `unchecked`
- Declarations: `contract`, `interface`, `library`, `struct`, `enum`, `function`, `constructor`, `modifier`, `fallback`, `receive`

#### Option B: Physical SLOC (SLOCCount)
- Counts non-empty, non-comment **lines**
- Multi-line expressions count as N lines
- Simpler but less accurate for complexity
- **Use for:** Quick size estimates, line-based billing

**Ask the user:** "Logical or Physical SLOC? (Default: Logical)"

---

### Step 3: Execute Count

**Use the provided Python script:**

```bash
python3 {baseDir}/skills/sloc-initial-sweep/scripts/sloc_counter.py <repo_root> \
  --dirs contracts src scripts \
  --extensions .sol .ts .js \
  --method logical
```

**Example for contracts-only:**

```bash
python3 {baseDir}/skills/sloc-initial-sweep/scripts/sloc_counter.py /path/to/repo \
  --dirs contracts \
  --extensions .sol \
  --method logical
```

**Inline alternative (if script not available):**

```python
import os
from collections import defaultdict

ROOT = "<repo_root>"
INCLUDE_DIRS = ["contracts"]
EXTENSIONS = {".sol"}
METHOD = "logical"  # or "physical"

# [Insert strip_comments() and logical_sloc() functions from script]

# Scan and count
files = []
for rel in INCLUDE_DIRS:
    base = os.path.join(ROOT, rel)
    for dirpath, _, filenames in os.walk(base):
        for name in filenames:
            if os.path.splitext(name)[1] in EXTENSIONS:
                files.append(os.path.join(dirpath, name))

by_folder = defaultdict(int)
by_folder_files = defaultdict(int)

for path in files:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    sloc = logical_sloc(text)  # or physical_sloc(text)
    rel = os.path.relpath(path, ROOT)
    folder = rel.split(os.sep)[0]
    by_folder[folder] += sloc
    by_folder_files[folder] += 1

# Print results
print(f"Total: {sum(by_folder.values())} SLOC across {len(files)} files\n")
for folder in sorted(by_folder, key=by_folder.get, reverse=True):
    print(f"{folder}: {by_folder[folder]:,} SLOC ({by_folder_files[folder]} files)")
```

---

### Step 4: Present Results

**Format the output clearly:**

```
============================================================
SLOC Analysis - LOGICAL Method
============================================================

Total SLOC: 6,061
Files Scanned: 82

By Language:
----------------------------------------
  solidity         6,061 SLOC  (82 files)

By Directory:
----------------------------------------
  module-a         1,163 SLOC  (4 files)
  module-b           842 SLOC  (4 files)
  mocks              821 SLOC  (19 files)
  module-c           555 SLOC  (8 files)
  module-d           531 SLOC  (2 files)
  interfaces         473 SLOC  (20 files)
  adapters           380 SLOC  (2 files)
  vaults             293 SLOC  (2 files)
  errors             285 SLOC  (11 files)
  bundler            219 SLOC  (1 file)
  [... remaining folders ...]
```

**Include context:**
- Note any exclusions ("tests excluded", "mocks excluded")
- Mention counting method used
- Highlight any anomalies (e.g., single file with 50% of total SLOC)

---

### Step 5: Document Findings

**Automatically note:**

1. **Size classification:**
   - Small: < 2,000 SLOC
   - Medium: 2,000 - 10,000 SLOC
   - Large: 10,000 - 50,000 SLOC
   - Very Large: > 50,000 SLOC

2. **Risk indicators:**
   - Single file > 1,000 SLOC (refactoring candidate)
   - Mocks/tests > 50% of total (may indicate over-testing or bloat)
   - High concentration in one module (single point of failure risk)

3. **Audit effort estimate:**
   - Rule of thumb: ~100-200 SLOC per hour for detailed security audit
   - Adjust for complexity, external dependencies, novel patterns

**Example summary:**

> **SLOC Summary:** 6,061 logical SLOC across 82 Solidity files in `contracts/`.
> 
> **Size:** Medium codebase  
> **Largest modules:** module-a (1,163), module-b (842), mocks (821)  
> **Estimated effort:** 30-60 hours for comprehensive audit (excluding mocks)  
> **Notes:** Mocks excluded from audit scope, reducing focus area to ~5,240 SLOC

---

## Safety & Best Practices

- [ ] **Read-only operation:** Do not modify any files
- [ ] **No artifacts in repo:** Do not create SLOC reports inside the target repository
- [ ] **Handle encoding errors:** Use `encoding="utf-8", errors="ignore"` for file reads
- [ ] **Validate paths:** Check that directories exist before scanning
- [ ] **Confirm large scans:** If > 500 files, confirm with user before running

---

## Output Artifacts

**Optional:** If user requests persistent reports, create:

- `sloc_report.json` - Machine-readable metrics (outside repo)
- `sloc_summary.md` - Human-readable report for audit documentation

**JSON format:**
```json
{
  "timestamp": "2026-01-22T...",
  "method": "logical",
  "total_sloc": 6061,
  "total_files": 82,
  "by_language": {
    "solidity": 6061
  },
  "by_folder": {
    "module-a": 1163,
    "module-b": 842,
    ...
  }
}
```

---

## Integration with Other Skills

**After SLOC analysis, consider:**

- `audit-context` - Build full codebase context for review
- `variant-analysis` - Find similar code patterns across modules
- `static-analysis` - Run Slither, Mythril, or other static analyzers
- `differential-review` - Compare against previous version (for upgrades)

---

## Examples

### Example 1: Smart Contract Audit (Solidity only, exclude tests)

**User request:**
> "Calculate NSLOC for this smart contract repo, exclude tests"

**Agent response:**
1. Confirm scope: `contracts/` directory, `.sol` files only, exclude `test/` and `mocks/`
2. Method: Logical SLOC (default for contracts)
3. Run script with filters
4. Present results with folder breakdown
5. Note: "Tests and mocks excluded. Production contracts: 5,240 SLOC"

### Example 2: Full Stack Audit (Solidity + TypeScript)

**User request:**
> "Get SLOC for contracts and frontend"

**Agent response:**
1. Confirm scope: `contracts/` and `frontend/src/`, extensions `.sol` + `.ts` + `.tsx`
2. Method: Logical SLOC
3. Run script with both directories
4. Present results split by language and folder
5. Note: "Backend: 6,061 SLOC (Solidity), Frontend: 15,000 SLOC (TypeScript)"

### Example 3: Differential SLOC (Before/After Upgrade)

**User request:**
> "Compare SLOC before and after the upgrade"

**Agent response:**
1. Run SLOC on `main` branch
2. Run SLOC on `upgrade` branch
3. Present delta: "Added 1,200 SLOC (+19.8%), Removed 300 SLOC"
4. Identify changed modules: "module-a +500, vaults +400, New: module-d 300"

---

## Notes

- **Multi-line expressions:** In logical SLOC, a function definition spanning 10 lines = **1** statement
- **Comments:** Always excluded (both `//` line and `/* */` block comments)
- **Blank lines:** Always excluded
- **String literals:** Preserved during comment stripping to avoid false positives
- **Language-specific:** Keywords tuned for Solidity/TypeScript; adjust for other languages

---

## Troubleshooting

**Issue:** Script fails with encoding errors  
**Solution:** Use `errors="ignore"` in file reads, or manually specify encoding

**Issue:** Unexpected counts (too high/low)  
**Solution:** Verify comment stripping works correctly for target language, check for minified code

**Issue:** Directory not found  
**Solution:** Confirm relative paths are correct, use absolute paths if needed

---

## Quick Reference

| Method | Counts | Multi-line | Best For |
|--------|--------|-----------|----------|
| **Logical SLOC** | Statements | 1 statement | Complexity, audit effort |
| **Physical SLOC** | Lines | N lines | Quick sizing, LOC metrics |

**Default:** Logical SLOC for smart contract audits

---

## Checklist

**Before running:**
- [ ] Confirmed scope (directories, extensions)
- [ ] Confirmed method (logical vs physical)
- [ ] Confirmed test/mock inclusion policy
- [ ] Validated Python 3 available

**After running:**
- [ ] Reported total SLOC and file count
- [ ] Provided per-folder breakdown
- [ ] Provided per-language breakdown (if multi-language)
- [ ] Noted exclusions and caveats
- [ ] Documented size classification and effort estimate
