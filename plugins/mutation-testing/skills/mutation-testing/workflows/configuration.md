# Configuration and Optimization Guide

Guide for configuring mewt and optimizing mutation testing performance **before** running a campaign.

## Goal

Configure mewt so the user can run `mewt run` with optimal settings that balance thoroughness and execution time.

---

## Configuration Workflow

### Phase 1: Initialize and Validate Targets

**Entry:** User has a codebase and wants to configure mutation testing.

**Actions:**

1. **Initialize mewt:**
   ```bash
   mewt init  # Creates mewt.toml and mewt.sqlite
   ```

   Note: If working with a config in a non-standard location, use `--config path/to/mewt.toml`. The parent directory of the config file becomes the working directory, and relative paths in the config resolve from there.

2. **Review auto-generated configuration:**
   ```bash
   mewt print config
   ```

3. **Verify target patterns:**
   - **Include patterns** should match only source code: `src/`, `lib/`, `contracts/`
   - **Ignore patterns** should exclude tests, dependencies, generated code
   - Note: Ignore patterns use substring matching (e.g., `"test"` matches `tests/`, `test_utils.py`)

4. **Edit `mewt.toml` if needed** to fix target patterns:
   ```toml
   [targets]
   include = ["src/**/*.rs"]      # Specific source directories only
   ignore = ["test", "mock"]      # Exclude test/mock files within src/
   ```

**Exit:** `mewt.toml` contains valid target patterns that match intended source files.

---

### Phase 2: Generate Mutants and Assess Scope

**Entry:** Phase 1 exit criteria met (valid `mewt.toml` exists).

**Actions:**

1. **Generate mutants:**
   ```bash
   mewt mutate src/
   ```
   Note: Output shows per-target summaries with severity breakdown (high/medium/low). Use `--verbose` to see individual mutants.

2. **Check mutant count and distribution:**
   ```bash
   mewt status           # View total mutant count
   mewt print targets    # Pretty table showing which files were mutated
   ```

3. **Time the test command:**
   ```bash
   time <test-command-from-config>  # e.g., time cargo test
   ```
   Note the baseline test duration.

4. **Calculate worst-case campaign duration:**
   - Formula: `mutant_count × test_duration`
   - Example: 500 mutants × 10s = ~1.4 hours
   - Actual runtime typically faster (tests catch mutants quickly, skipping reduces load)

**Exit:** Know the mutant count, test duration, and estimated campaign time.

---

### Phase 3: Decide on Optimization Strategy

**Entry:** Phase 2 exit criteria met (mutant count and time estimate known).

**Decision Tree:**

```
Estimated campaign duration?
|
+-- < 1 hour
|   └─> Proceed to Phase 4 (no optimization needed)
|
+-- 1-16 hours
|   └─> Consult user: Acceptable? Run overnight/end-of-day?
|       +-- User accepts --> Proceed to Phase 4
|       +-- User declines --> Apply optimization (see Optimization Strategies below)
|
+-- > 16 hours
    └─> Explore optimization options (see Optimization Strategies below)
```

**Actions (if optimization needed):**

Read `references/optimization-strategies.md` for detailed strategies and examples. Then:
1. Verify target selection (most common issue — check `mewt print targets` for unintended files)
2. Analyze project structure (`mewt print mutants --target 'src/component/**'` per component)
3. Present options to user with time estimates (full campaign / target critical components / high-severity only / two-phase)
4. Apply chosen optimization to `mewt.toml`

**Exit:** Either campaign duration is acceptable, or `mewt.toml` has been optimized to reduce duration.

---

### Phase 4: Validate Test Command and Timeout

**Entry:** Phase 3 exit criteria met (optimization applied if needed).

**Actions:**

1. **If test configuration was modified in Phase 3,** verify it works:
   ```bash
   <test-command-from-config>  # Should succeed without errors
   ```
   Skip this step if Phase 2's timing already validated the unmodified command.

2. **Check if timeout adjustment needed:**

   **Default:** Mewt auto-calculates timeout (baseline test time × 2), which accounts for incremental recompilation in most cases.

   **Exception:** For compiled languages where recompilation of dependents dominates test time (Solidity/Foundry, heavy C++ builds):

   ```bash
   # Test with warm cache
   time forge test  # e.g., 0.8s

   # Simulate mutation: touch source file to trigger dependent recompilation
   touch src/Contract.sol

   # Test again (includes recompilation)
   time forge test  # e.g., 5.2s

   # If drastically different, set manual timeout in mewt.toml
   ```

   If recompilation time >> test time:
   ```toml
   [test]
   cmd = "forge test"
   timeout = 11  # Based on: 5.2s × 2 = 10.4s, round up
   ```

   Otherwise, omit `timeout` and let mewt auto-calculate.

**Exit:** Test command verified working (if modified), timeout appropriately set (auto or manual).

---

### Phase 5: Final Validation

**Entry:** Phase 4 exit criteria met (test command works if modified, timeout set).

**Actions:**

Run through the validation checklist to verify all prior phases completed successfully:

- [ ] `mewt print config` — Configuration syntax valid, no errors
- [ ] `mewt status` — Mutant count matches expectations from Phase 2
- [ ] `mewt print targets` — Only intended files mutated (no tests, mocks, dependencies)
- [ ] Test command verified — Already validated in Phase 2 (and Phase 4 if modified)
- [ ] Timeout set — Auto-calculated or manually set for recompilation-heavy languages
- [ ] Scope acceptable — Duration estimate from Phase 2 acceptable to user

**Exit:** Ready to run `mewt run`.

---

## Configuration Reference

### File Structure

```toml
db = "mewt.sqlite"

[log]
level = "info"  # trace, debug, info, warn, error

[targets]
# BE SPECIFIC: Source code only, never tests/dependencies
include = ["src/**/*.js", "lib/**/*.js"]
ignore = ["test", "mock"]      # substring matches, not globs

[run]
# Optional: Restrict mutation types (omit to test all)
# mutations = ["ER", "CR", "IF", "IT"]

[test]
cmd = "npm test"
# timeout = 30  # Optional: auto-calculated if omitted (2× baseline)

# Per-target rules (first match wins)
[[test.per_target]]
glob = "src/core/*.js"
cmd = "npm test -- core"
timeout = 20
```

### Target Configuration Examples

**Important:** Restrictive `include` patterns exclude most unwanted files. Only add `ignore` patterns for items within included paths.

```toml
# Rust project
[targets]
include = ["src/**/*.rs"]
ignore = ["test", "mock", "generated"]

# Solidity project
[targets]
include = ["contracts/**/*.sol"]
ignore = ["test", "interfaces", "mocks"]

# Python project
[targets]
include = ["src/**/*.py", "lib/**/*.py"]
ignore = ["test", "conftest"]

# JavaScript/TypeScript
[targets]
include = ["src/**/*.ts", "lib/**/*.ts"]
ignore = ["test", "spec", "mock"]
```

### Test Configuration

**Timeout Calculation:**

Mutants trigger incremental recompilation (only mutated file + dependents). Mewt's auto-calculated timeout (2× baseline) usually accounts for this.

**Edge case:** In some compiled languages (Solidity/Foundry, heavy C++), recompiling dependent files takes much longer than running tests. Verify by timing tests, touching a file, and timing again. If drastically different, set manual timeout based on the slower measurement.

```toml
# Option 1: Auto-calculate (recommended for most languages)
[test]
cmd = "cargo test"
# Omit timeout — mewt measures baseline and applies 2× multiplier

# Option 2: Explicit timeout (for recompilation-heavy languages)
[test]
cmd = "forge test"
timeout = 11  # Based on: touch file, time test (5.2s), × 2
```

---

## Troubleshooting

### No Mutants Generated

**Check language support:**
```bash
mewt print mutations --language rust
```

**Verify patterns:**
```bash
mewt print config
ls src/**/*.rs  # Do files exist and match include patterns?
```

**Common causes:**
- Include pattern doesn't match files
- Ignore pattern too broad (e.g., `"test"` matches `test_utils.rs`)
- Unsupported language

---

### Test Command Fails

**Run command manually:**
```bash
pytest  # Should work from project directory without errors
```

**Find correct command:**
- Check: `Makefile`, `justfile`, `package.json`, `README.md`
- In monorepos, may need to run from workspace subdirectory

---

### Configuration Validation

Before running `mewt run`, complete Phase 5's validation checklist above. If any item fails, return to the relevant phase to fix it.

---

## Campaign Execution Timing

Recommend timing based on estimated duration:

- **< 1 hour:** Run anytime
- **1-16 hours:** Start end-of-day, results by morning
- **16-48 hours:** Start Friday evening, results Monday
- **Two-phase:** Phase 1 overnight, Phase 2 next day

---

## Configuration Principles

- **Configure via `mewt.toml`** — Not CLI flags (version control the config)
- **Target source code specifically** — Exclude tests, dependencies, generated code
- **Prefer limiting files over mutation types** — Better to assess critical code thoroughly
- **Verify test commands** — Run manually before campaign
- **Trust auto-calculated timeouts** — 2× baseline accounts for incremental recompilation in most cases
- **Measure before optimizing** — Profile actual test times before applying per-target config
- **Document decisions** — Commit `mewt.toml` with comments explaining configuration choices
