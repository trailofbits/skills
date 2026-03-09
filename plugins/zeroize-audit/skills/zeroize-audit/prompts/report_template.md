# Zeroize Audit Report

**Run ID:** `<run_id>`
**Timestamp:** `<ISO-8601>`
**Repository:** `<path>`
**Compile DB:** `<compile_db>`

**Configuration:**
| Setting | Value |
|---|---|
| Optimization levels | O0, O1, O2 |
| MCP mode | prefer |
| MCP available | yes / no |
| Assembly analysis | enabled / disabled |
| Semantic IR analysis | enabled / disabled |
| CFG analysis | enabled / disabled |
| Runtime tests | enabled / disabled |
| PoC validation | mandatory |

---

## Executive Summary

| Metric | Count |
|---|---|
| Files scanned | 0 |
| Translation units analyzed | 0 |
| **Total findings** | **0** |

### By Severity

| Severity | Count |
|---|---|
| High | 0 |
| Medium | 0 |

### By Confidence

| Confidence | Count |
|---|---|
| Confirmed | 0 |
| Likely | 0 |
| Needs review | 0 |

### PoC Validation

| Metric | Count |
|---|---|
| PoCs generated | 0 |
| PoCs validated | 0 |
| Exploitable (confirmed) | 0 |
| Not exploitable | 0 |
| Compile failures | 0 |
| No PoC generated | 0 |

### By Category

| Category | Count |
|---|---|
| MISSING_SOURCE_ZEROIZE | 0 |
| PARTIAL_WIPE | 0 |
| NOT_ON_ALL_PATHS | 0 |
| OPTIMIZED_AWAY_ZEROIZE | 0 |
| SECRET_COPY | 0 |
| INSECURE_HEAP_ALLOC | 0 |
| STACK_RETENTION | 0 |
| REGISTER_SPILL | 0 |
| MISSING_ON_ERROR_PATH | 0 |
| NOT_DOMINATING_EXITS | 0 |
| LOOP_UNROLLED_INCOMPLETE | 0 |

---

## Sensitive Objects Inventory

| ID | Name | Type | Location | Confidence | Heuristic | Has Wipe |
|---|---|---|---|---|---|---|
| SO-0001 | key | uint8_t[32] | path/to/file.c:45 | low | name pattern | no |
| SO-0002 | session_key | uint8_t[16] | path/to/file.c:89 | medium | type hint | yes |

---

## Findings

### High Severity

#### ZA-0002: STACK_RETENTION — high (confirmed)

**Location:** `path/to/file.c:89`
**Object:** `secret_function` (`stack_frame`, 192 bytes)

**Evidence:**
- [asm] Stack frame (192 bytes) allocated at function entry; no red-zone clearing before ret at line 112.
- [asm] `sub $0xc0, %rsp` at entry; no corresponding zeroing sequence before ret.

**Compiler Evidence:**
- Opt levels analyzed: O0, O2
- O2: Stack allocated 192 bytes; ret reached without clearing red-zone below %rsp.
- **Summary:** Stack frame persists with uncleared secret bytes after function return.

**Recommended Fix:**
Add `explicit_bzero()` across the full stack frame, or use a compiler barrier and volatile wipe loop covering the red-zone.

---

#### ZA-0003: REGISTER_SPILL — high (confirmed)

**Location:** `path/to/file.c:156`
**Object:** `encrypt` (`stack_slot`, 8 bytes)

**Evidence:**
- [asm] `movq %r12, -48(%rsp)` at line 156 spills key fragment to stack; no corresponding zero-store before ret.

**Compiler Evidence:**
- Opt levels analyzed: O0, O2
- O2: `movq %r12, -48(%rsp)` without corresponding cleanup of spill slot.
- **Summary:** Register spill at -48(%rsp) contains key fragment; slot not cleared before return.

**Recommended Fix:**
Use inline assembly with register constraints to prevent spilling, or add explicit zero-store covering the spill slot before return.

---

#### ZA-0005: INSECURE_HEAP_ALLOC — high (confirmed)

**Location:** `path/to/file.c:67`
**Object:** `private_key` (`uint8_t *`)

**Evidence:**
- [source] `malloc()` at line 67 allocates buffer for `private_key`. No `mlock()` or `madvise(MADV_DONTDUMP)` found for this allocation.

**Recommended Fix:**
Replace `malloc()` with `OPENSSL_secure_malloc()` or `sodium_malloc()`. Add `mlock()` and `madvise(MADV_DONTDUMP)` if using standard allocator.

---

### Medium Severity

#### ZA-0001: MISSING_SOURCE_ZEROIZE — medium (likely)

**Location:** `path/to/file.c:123`
**Object:** `key` (`uint8_t[32]`, 32 bytes)

**Evidence:**
- [source] Sensitive buffer `key` matches name pattern; no approved wipe call found before return at line 130.

**Recommended Fix:**
Use `explicit_bzero(key, sizeof(key))` on all exit paths.

---

#### ZA-0006: OPTIMIZED_AWAY_ZEROIZE — medium (confirmed)

**Location:** `path/to/file.c:88`
**Object:** `nonce` (`uint8_t[12]`, 12 bytes)

**Evidence:**
- [ir] O0 IR contains `llvm.memset` call zeroing `nonce` at line 88; absent in O1 IR — dead-store elimination.

**Compiler Evidence:**
- Opt levels analyzed: O0, O1, O2
- O0: `llvm.memset(nonce, 0, 12)` present at line 88.
- O1: `llvm.memset` call removed — dead store eliminated.
- O2: `llvm.memset` call absent.
- **Summary:** Wipe disappears at O1; cause: dead-store elimination of memset with no subsequent read.

**Recommended Fix:**
Replace `memset()` with `explicit_bzero()` or add a volatile compiler barrier after the wipe to prevent elimination.

---

### Needs Review

#### ZA-0004: SECRET_COPY — high (needs_review)

**Location:** `path/to/file.c:203`
**Object:** `session_key` (`uint8_t[16]`, 16 bytes)

**Evidence:**
- [source] `memcpy()` at line 203 copies `session_key` to `tmp_key` (line 199). No approved wipe tracked for destination `tmp_key` before it goes out of scope at line 218.

**Recommended Fix:**
Ensure both `session_key` and `tmp_key` are zeroized on all exit paths using `explicit_bzero()`.

---

## PoC Validation Results

| Finding | Category | PoC File | Exit Code | Result | Impact |
|---|---|---|---|---|---|
| ZA-0001 | MISSING_SOURCE_ZEROIZE | poc_za_0001_missing_source_zeroize.c | 0 | exploitable | Confirmed |
| ZA-0002 | STACK_RETENTION | poc_za_0002_stack_retention.c | 1 | not_exploitable | Downgraded to low (informational) |
| ZA-0003 | REGISTER_SPILL | poc_za_0003_register_spill.c | — | compile_failure | No change |

---

## Superseded Findings

_No findings were superseded in this run._

<!-- Example:
| Superseded | Superseded By | Reason |
|---|---|---|
| F-SRC-0005 (NOT_ON_ALL_PATHS) | ZA-0007 / F-CFG-a1b2-0003 (NOT_DOMINATING_EXITS) | CFG dominance analysis provides definitive result |
-->

---

## Confidence Gate Summary

| Finding | Action | Reason |
|---|---|---|
| ZA-0004 (SECRET_COPY) | Downgraded to needs_review | MCP unavailable; only 1 non-MCP signal (source pattern match) |

---

## Analysis Coverage

| Metric | Value |
|---|---|
| TUs in compile DB | 0 |
| TUs analyzed | 0 |
| TUs with sensitive objects | 0 |
| Agent 1 (MCP resolver) | success / skipped / failed |
| Agent 2 (source analyzer) | success / failed |
| Agent 3 (compiler analyzer) | N/N TUs succeeded |
| Agent 4 (report assembler) | success |
| Agent 5 (PoC generator) | success / failed |
| Agent 6 (test generator) | success / skipped / failed |

---

## Appendix: Evidence Files

| Finding | Evidence File | Description |
|---|---|---|
| ZA-0002 | `compiler-analysis/a1b2/asm-findings.json` | Assembly analysis output |
| ZA-0006 | `compiler-analysis/c3d4/ir-findings.json` | IR diff analysis output |
