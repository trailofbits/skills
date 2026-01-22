# Sample SLOC Analysis Outputs

This document shows example outputs for various audit scenarios.

---

## Example 1: Solidity Smart Contract Audit (Contracts Only)

**Command:**
```bash
python3 scripts/sloc_counter.py /path/to/NettyWorthV2 \
  --dirs contracts \
  --extensions .sol \
  --method logical
```

**Output:**

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
  marketplace       1,163 SLOC  (4 files)
  core                842 SLOC  (4 files)
  mocks               821 SLOC  (19 files)
  polylend            555 SLOC  (8 files)
  earn                531 SLOC  (2 files)
  interfaces          473 SLOC  (20 files)
  oracles             380 SLOC  (2 files)
  vault               293 SLOC  (2 files)
  errors              285 SLOC  (11 files)
  bundler             219 SLOC  (1 file)
  supporting          191 SLOC  (2 files)
  libraries           158 SLOC  (2 files)
  helpers              93 SLOC  (1 file)
  events               28 SLOC  (2 files)
  validators           16 SLOC  (1 file)
  tokens               13 SLOC  (1 file)
```

**Analysis Notes:**
- **Size:** Medium codebase
- **Largest module:** Marketplace (1,163 SLOC = 19% of total)
- **Mocks:** 821 SLOC (14% of total) - can exclude from audit scope
- **Production SLOC:** ~5,240 (excluding mocks)
- **Estimated audit effort:** 26-52 hours (at 100-200 SLOC/hour)

---

## Example 2: Full-Stack Audit (Contracts + TypeScript Scripts)

**Command:**
```bash
python3 scripts/sloc_counter.py /path/to/NettyWorthV2 \
  --dirs contracts scripts test \
  --extensions .sol .ts \
  --method logical
```

**Output:**

```
============================================================
SLOC Analysis - LOGICAL Method
============================================================

Total SLOC: 34,570
Files Scanned: 134

By Language:
----------------------------------------
  typescript      21,362 SLOC  (52 files)
  solidity        13,208 SLOC  (82 files)

By Directory:
----------------------------------------
  test            15,247 SLOC  (28 files)
  contracts       13,208 SLOC  (82 files)
  scripts          6,014 SLOC  (23 files)
  root               101 SLOC  (1 file)
```

**Analysis Notes:**
- **Size:** Large codebase
- **Language split:** 62% TypeScript, 38% Solidity
- **Test coverage:** Tests are 44% of total SLOC (good coverage)
- **Scripts:** Deployment/utility scripts are 17% of total
- **Audit focus:** Contracts (13,208) + critical scripts (e.g., deployment)

---

## Example 3: Physical SLOC Comparison

**Command (Physical):**
```bash
python3 scripts/sloc_counter.py /path/to/NettyWorthV2 \
  --dirs contracts \
  --extensions .sol \
  --method physical
```

**Output:**

```
============================================================
SLOC Analysis - PHYSICAL Method
============================================================

Total SLOC: 13,208
Files Scanned: 82

By Language:
----------------------------------------
  solidity        13,208 SLOC  (82 files)

By Directory:
----------------------------------------
  marketplace       2,456 SLOC  (4 files)
  core              1,789 SLOC  (4 files)
  mocks             1,523 SLOC  (19 files)
  ...
```

**Comparison with Logical SLOC:**
- **Logical SLOC:** 6,061 statements
- **Physical SLOC:** 13,208 lines
- **Ratio:** ~2.18 physical lines per logical statement
- **Interpretation:** Code has moderate multi-line formatting (functions, structs, etc.)

---

## Example 4: Rust/Go Multi-Language Project

**Command:**
```bash
python3 scripts/sloc_counter.py /path/to/omni \
  --dirs src cmd pkg \
  --extensions .go .rs \
  --method logical
```

**Output:**

```
============================================================
SLOC Analysis - LOGICAL Method
============================================================

Total SLOC: 45,230
Files Scanned: 156

By Language:
----------------------------------------
  go              38,450 SLOC  (128 files)
  rust             6,780 SLOC  (28 files)

By Directory:
----------------------------------------
  src             20,340 SLOC  (85 files)
  pkg             18,110 SLOC  (43 files)
  cmd              6,780 SLOC  (28 files)
```

**Analysis Notes:**
- **Size:** Very Large codebase
- **Language split:** 85% Go, 15% Rust
- **Architecture:** `src/` (core), `pkg/` (packages), `cmd/` (entry points)

---

## Example 5: Differential SLOC (Before/After Upgrade)

**Scenario:** Comparing `v1.0` vs `v2.0` branches

**Commands:**
```bash
# Checkout v1.0
git checkout v1.0
python3 scripts/sloc_counter.py . --dirs contracts --extensions .sol --method logical > v1_sloc.txt

# Checkout v2.0
git checkout v2.0
python3 scripts/sloc_counter.py . --dirs contracts --extensions .sol --method logical > v2_sloc.txt

# Manual comparison
diff v1_sloc.txt v2_sloc.txt
```

**Comparison:**

| Metric | v1.0 | v2.0 | Delta |
|--------|------|------|-------|
| Total SLOC | 5,061 | 6,061 | +1,000 (+19.8%) |
| Files | 75 | 82 | +7 |
| Largest module | Marketplace (980) | Marketplace (1,163) | +183 |

**New modules in v2.0:**
- `earn/CollateralVault.sol` - 320 SLOC
- `earn/LendingVault.sol` - 211 SLOC
- `polylend/` (entire directory) - 555 SLOC

**Analysis Notes:**
- **Growth:** 20% increase in codebase size
- **New features:** Earn module (531 SLOC), Polylend integration (555 SLOC)
- **Audit delta:** Focus on new modules + modified contracts
- **Estimated delta audit:** 10-20 hours for new code

---

## Example 6: Python Smart Contract Project (Vyper)

**Command:**
```bash
python3 scripts/sloc_counter.py /path/to/yield-basis \
  --dirs contracts \
  --extensions .vy .vyi \
  --method logical
```

**Output:**

```
============================================================
SLOC Analysis - LOGICAL Method
============================================================

Total SLOC: 3,450
Files Scanned: 22

By Language:
----------------------------------------
  vy               3,380 SLOC  (21 files)
  vyi                 70 SLOC  (1 file)

By Directory:
----------------------------------------
  amm              1,850 SLOC  (8 files)
  dao              1,200 SLOC  (7 files)
  lt                 330 SLOC  (6 files)
  interfaces          70 SLOC  (1 file)
```

**Analysis Notes:**
- **Size:** Small-Medium codebase
- **Language:** Vyper (Python-based smart contract language)
- **Largest module:** AMM (54% of total SLOC)

---

## Example 7: JSON Export for Reporting

**Command:**
```bash
python3 scripts/sloc_counter.py /path/to/repo \
  --dirs contracts \
  --extensions .sol \
  --method logical \
  --output json > sloc_report.json
```

**Output (sloc_report.json):**

```json
{
  "timestamp": "2026-01-22T14:30:00Z",
  "repository": "/path/to/NettyWorthV2",
  "method": "logical",
  "total_sloc": 6061,
  "total_files": 82,
  "by_language": {
    "solidity": {
      "sloc": 6061,
      "files": 82,
      "percentage": 100.0
    }
  },
  "by_folder": {
    "marketplace": {"sloc": 1163, "files": 4},
    "core": {"sloc": 842, "files": 4},
    "mocks": {"sloc": 821, "files": 19},
    "polylend": {"sloc": 555, "files": 8},
    "earn": {"sloc": 531, "files": 2},
    "interfaces": {"sloc": 473, "files": 20},
    "oracles": {"sloc": 380, "files": 2},
    "vault": {"sloc": 293, "files": 2},
    "errors": {"sloc": 285, "files": 11},
    "bundler": {"sloc": 219, "files": 1},
    "supporting": {"sloc": 191, "files": 2},
    "libraries": {"sloc": 158, "files": 2},
    "helpers": {"sloc": 93, "files": 1},
    "events": {"sloc": 28, "files": 2},
    "validators": {"sloc": 16, "files": 1},
    "tokens": {"sloc": 13, "files": 1}
  },
  "size_classification": "medium",
  "estimated_audit_hours": {
    "min": 30,
    "max": 60,
    "note": "Based on 100-200 SLOC/hour for security audit"
  }
}
```

---

## Notes on Interpretation

### Size Classifications
- **Tiny:** < 500 SLOC (1-3 contracts)
- **Small:** 500 - 2,000 SLOC (simple protocol)
- **Medium:** 2,000 - 10,000 SLOC (moderate complexity)
- **Large:** 10,000 - 50,000 SLOC (complex system)
- **Very Large:** > 50,000 SLOC (ecosystem/platform)

### Audit Effort Estimates
- **Basic review:** 200-300 SLOC/hour
- **Standard audit:** 100-200 SLOC/hour
- **Deep audit:** 50-100 SLOC/hour
- **Critical systems:** 20-50 SLOC/hour

Adjust based on:
- Code complexity (DeFi, governance, novel crypto)
- Test coverage (better tests = faster audit)
- Documentation quality
- Team experience with codebase
- External dependencies (oracles, cross-chain, etc.)
