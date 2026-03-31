# Optimization Strategies

Apply these strategies **before** running a campaign when Phase 3 of the configuration workflow requires optimization (estimated >16 hours or user requests).

---

## Priority 1: Verify Target Selection

**Most common issue:** Mutating non-source code.

**Diagnostic:**

```bash
mewt print config     # Check [targets] include/ignore
mewt print targets    # Check what was actually mutated
```

**Look for unintended files:**
- Mocks: `src/mocks/`, `__mocks__/`
- Tests: `*_test.rs`, `*.test.js`, `tests/`
- Dependencies: `vendor/`, `node_modules/`
- Generated: `proto/`, `generated/`

**Fix:** Update `[targets]` in `mewt.toml` to be more specific:

```toml
# Before (too broad)
[targets]
include = ["**/*.rs"]

# After (specific)
[targets]
include = ["src/**/*.rs", "lib/**/*.rs"]
ignore = ["test", "mock", "generated"]
```

Re-run `mewt mutate` and check new count.

---

## Priority 2: Analyze Project Structure

**Goal:** Understand mutant distribution and test organization to choose the right optimization.

**1. Get mutant counts per component:**

```bash
# Use single quotes to prevent shell glob expansion
mewt print mutants --target 'src/auth/**/*.rs' | wc -l
mewt print mutants --target 'src/core/**/*.rs' | wc -l
mewt print mutants --target 'src/utils/**/*.rs' | wc -l
```

Present breakdown to user:
```
Component breakdown:
- src/auth/: 200 mutants × 5s = ~17 min
- src/core/: 800 mutants × 8s = ~1.8 hrs
- src/utils/: 150 mutants × 3s = ~8 min
Total: 1150 mutants, ~2.3 hrs worst-case
```

**2. Count mutations by severity:**

```bash
# Check enabled mutation types
mewt print config | grep mutations

# Count by severity level
mewt print mutants --severity high | wc -l
mewt print mutants --severity medium | wc -l
mewt print mutants --severity low | wc -l

# Or count specific mutation types
mewt print mutants --mutation-types ER | wc -l
mewt print mutants --mutation-types CR | wc -l

# Compare to total
mewt print mutants | wc -l
```

Example output:
```
High/Medium severity: 450 mutants
Total mutants: 1200
Percentage: 37.5%
```

**Note:** The percentage varies drastically between codebases (15% to 50+ % is common).

---

## Priority 3: Choose Optimization Approach

Based on project structure analysis, present options to user with concrete time estimates:

### Option A: Run Full Campaign

- "Estimated ~X hours worst-case (likely faster in practice)"
- "Recommend starting Friday evening for weekend completion"
- **When to suggest:** Duration acceptable, comprehensive coverage desired

### Option B: Target Critical Components

- "Focus on specific components: src/auth/ (~17 min), src/crypto/ (~45 min)"
- "Start with one component and expand scope after review?"
- **When to suggest:** Clear component boundaries, user wants rapid iteration

**Implementation:**
```toml
[targets]
# Start with critical component
include = ["src/auth/**/*.rs"]

# After review, expand scope
# include = ["src/auth/**/*.rs", "src/core/**/*.rs"]
```

### Option C: High/Medium Severity Only

- "Limit to high/medium severity mutations (X mutants, ~Y hours)"
- "Low severity (operator shuffles) tests edge cases, less critical"
- **When to suggest:** Time-constrained, need actionable findings quickly

**Implementation (by severity level):**
```toml
[run]
mutations = ["ER", "CR", "IF", "IT"]  # Specific types (high/medium)
```

Or use severity filtering during analysis:
```bash
# Run all mutants but filter results by severity
mewt results --severity high,medium
mewt print mutants --severity high
```

**Trade-offs to explain:**
- High/med severity: ~30-40% of mutants (varies by codebase)
- Low severity: ~60-70% of mutants (operator shuffles, edge cases)
- Low severity still provides value, just lower priority
- Using severity filters during analysis allows flexibility without re-running campaign

### Option D: Two-Phase Campaign (Integration-Heavy Only)

- "Phase 1: Targeted tests (~6 hours), Phase 2: Re-test uncaught with full suite (~2 hours)"
- "Total: ~8 hours vs ~25 hours naive"
- **When to suggest:** Integration tests dominate, unit tests don't map cleanly to files

See Two-Phase Campaigns section below for detailed setup.

---

## Two-Phase Campaigns

**Use ONLY for integration-heavy test suites.** Not recommended for well-organized unit tests.

### When to Use

**Good fit:**
- Integration tests dominate runtime
- Unit tests provide broad coverage but don't map cleanly to specific files
- Targeted test commands significantly faster than full suite

**Not recommended:**
- Well-organized unit tests with clear file mappings
- Tests already fast and targeted

### Setup

**Phase 1 config (targeted tests):**

```toml
# TWO-PHASE CAMPAIGN
# Phase 1: Targeted tests (~6 hours)
# Phase 2: Re-test uncaught with full suite (~2 hours)

[test]
# PHASE 2: Uncomment after phase 1 completes
# cmd = "cargo test"
# timeout = 60

# PHASE 1: Targeted tests
[[test.per_target]]
glob = "src/auth/*.rs"
cmd = "cargo test auth::unit"
timeout = 10

[[test.per_target]]
glob = "src/core/*.rs"
cmd = "cargo test core::unit"
timeout = 15
```

**Rationale:** Phase 1 uses fast targeted tests. Phase 2 re-tests only the survivors with the comprehensive suite.

### Execution

**Phase 1:**
```bash
mewt run
```
Wait for completion.

**Phase 2 (after phase 1 completes):**

1. **Extract uncaught mutants:**
   ```bash
   mewt results --status Uncaught --format ids > uncaught_ids.txt
   ```

2. **Update mewt.toml:**
   - Comment out `[[test.per_target]]` sections
   - Uncomment Phase 2 `[test]` section

3. **Re-test with full suite:**
   ```bash
   mewt test --ids-file uncaught_ids.txt
   ```

4. **Review final results:**
   ```bash
   mewt results  # Remaining uncaught are true coverage gaps
   ```

**Example speedup:**
```
Naive approach:
  2,000 mutants × 45s = 25 hours

Two-phase approach:
  Phase 1: 2,000 mutants × 8s = 4.4 hours → 450 uncaught
  Phase 2: 450 mutants × 45s = 5.6 hours → 180 truly uncaught
  Total: 10 hours (2.5× speedup)
```

---

## Per-Target Test Configuration

**Use when:** Tests are well-organized by module/file, and running targeted tests is significantly faster than the full suite.

### Setup Pattern

```toml
# Test full suite for every mutant (slow but comprehensive)
[test]
cmd = "go test ./..."
timeout = 45

# ALTERNATIVE: Targeted tests per file (fast, may miss cross-module failures)
[[test.per_target]]
glob = "auth/*.go"
cmd = "go test ./auth"
timeout = 10

[[test.per_target]]
glob = "core/*.go"
cmd = "go test ./core"
timeout = 15

[[test.per_target]]
glob = "utils/*.go"
cmd = "go test ./utils"
timeout = 8

# Catch-all for unmatched files
[[test.per_target]]
glob = "*.go"
cmd = "go test ./..."
timeout = 45
```

**Ordering matters:** First match wins. Place most specific patterns first, catch-all last.

### Verify Speedup

```bash
time go test ./...      # Full suite: 45s
time go test ./auth     # Targeted: 8s
```

If targeted tests aren't significantly faster, this optimization won't help.

### Trade-offs

**Benefits:**
- Faster campaign execution
- Scales linearly with codebase size

**Risks:**
- May miss cross-module integration bugs
- Requires correct glob-to-test mapping

**Mitigation:**
- Use this for initial passes
- Consider two-phase approach for comprehensive validation
