# Quality Standards

Design patterns and quality requirements for generated skills, extracted from 50+ production skills in the Trail of Bits marketplace.

## Core Principles

### 1. Behavioral Guidance Over Reference Dumps

**Wrong:** Pasting an entire API reference or specification into SKILL.md.

**Right:** Teaching Claude *when* and *how* to look things up, plus judgment about which approach is appropriate.

The DWARF skill doesn't include the DWARF spec. It teaches Claude how to use `dwarfdump`, `readelf`, and `pyelftools`, plus when each tool is appropriate. The Semgrep skill doesn't list every operator — it teaches the workflow of writing rules test-first.

### 2. Explain WHY, Not Just WHAT

Every instruction should include the reasoning behind it. Anti-patterns need explanations of what goes wrong, not just "don't do this."

**Wrong:**
```markdown
- Don't use `eval()`
```

**Right:**
```markdown
- Don't use `eval()` — it executes arbitrary code from user input,
  enabling remote code execution even when input appears sanitized
```

### 3. Prescriptiveness Matches Task Risk

| Task Risk | Skill Style |
|-----------|-------------|
| High (security audits, crypto, compliance) | Strict phased workflow, mandatory checklists, rationalizations to reject |
| Medium (testing, code review, tooling) | Structured workflow with decision points, quality gates |
| Low (exploration, documentation, refactoring) | Flexible guidance with options, judgment calls |

## Required Sections

Every generated skill MUST include:

### "When to Use"

Specific scenarios where this skill applies. Include trigger phrases that help Claude select this skill over alternatives.

```markdown
## When to Use

- Fuzzing C/C++ projects that compile with Clang
- Need multi-core parallel fuzzing for throughput
- libFuzzer has plateaued on coverage
```

### "When NOT to Use"

Equally important — prevents false activation and wasted effort.

```markdown
## When NOT to Use

- Binary-only targets without source code (use QEMU mode instead)
- Simple unit testing (use the project's test framework)
- The project doesn't compile with Clang or GCC
```

## Security Skill Requirements

Skills that involve security analysis, vulnerability detection, or audit work MUST also include:

### "Rationalizations to Reject"

Pre-emptive blocks against shortcuts Claude might take. Format as a table:

```markdown
## Rationalizations to Reject

| Rationalization | Why It's Wrong |
|----------------|----------------|
| "The docs warn about this already" | Documentation is not a safety mechanism — users don't read docs |
| "This is an edge case" | Attackers specifically target edge cases |
| "The tests pass" | Tests prove presence of tested behavior, not absence of bugs |
| "This pattern is common in the codebase" | Common doesn't mean safe — it means the bug is systemic |
| "The user validates input upstream" | Never trust upstream validation — verify at point of use |
```

This section is the single most distinctive pattern from Trail of Bits skills. It counteracts Claude's tendency to rationalize skipping work or accepting weak assumptions.

## Structural Patterns

### Decision Trees

For skills with branching logic, include ASCII decision trees that guide Claude through conditional reasoning:

```markdown
## Decision Tree

What kind of input are you fuzzing?

├─ Structured binary format (PNG, PDF, protobuf)?
│  └─ Use structure-aware fuzzing with custom mutators
│
├─ Text-based format (JSON, XML, SQL)?
│  └─ Use dictionary-guided fuzzing
│     See: fuzzing-dictionary skill
│
├─ Network protocol?
│  └─ Use protocol-aware fuzzing (boofuzz, AFLNet)
│
└─ Raw bytes / unknown format?
   └─ Start with coverage-guided fuzzing, analyze coverage gaps
```

Decision trees prevent Claude from taking the first approach it thinks of. They force evaluation of the situation before acting.

### Progressive Disclosure

Keep SKILL.md under 500 lines. Split detailed content into `references/`:

```
SKILL.md (< 400 lines)
├── Frontmatter
├── When to Use / NOT to Use
├── Quick Reference
├── Decision Tree (if applicable)
├── Core Workflow
├── Related Skills
└── Pointers to references/

references/
├── advanced-usage.md
├── troubleshooting.md
└── platform-specific.md
```

**Rule:** SKILL.md links to reference files. Reference files do NOT chain to more reference files. One level deep only.

### Cross-References Between Skills

Skills should reference each other explicitly:

```markdown
## Related Skills

### Tools That Use This Technique

| Skill | How It Applies |
|-------|----------------|
| **aflpp** | Uses persistent mode harnesses with `__AFL_LOOP` |
| **libfuzzer** | Uses `LLVMFuzzerTestOneInput` harness signature |

### Related Techniques

| Skill | Relationship |
|-------|--------------|
| **coverage-analysis** | Measure harness effectiveness |
| **address-sanitizer** | Detect bugs found by harness |
```

Use two categories:
- **Solid relationships** — skills that directly complement each other
- **Alternative suggestions** — skills that could be used instead

## Description Quality

The description field in frontmatter is how Claude selects skills. It must be precise.

### Rules

| Rule | Example |
|------|---------|
| Third-person voice | "Analyzes X" not "I help with X" |
| Include trigger phrases | "Use when auditing Solidity" not just "Smart contract tool" |
| Be specific | "Detects reentrancy vulnerabilities" not "Helps with security" |
| Include "Use when" or "Use for" | Required for activation matching |
| Max 1024 characters | Keep it focused |

### Good vs. Bad Descriptions

**Bad:** "Helps with fuzzing"

**Good:** "Multi-core coverage-guided fuzzing with AFL++ for C/C++ projects. Use when fuzzing production codebases that need parallel execution and diverse mutation strategies."

## Content Quality

### Examples Must Be Concrete

Every skill needs at least one concrete example showing input → action → output.

```markdown
### Example: Fuzzing libpng

**Input:** libpng 1.6.37 source code
**Harness:** `libpng_read_fuzzer.cc` (from OSS-Fuzz)
**Command:**
\```bash
afl-fuzz -i seeds -o out -- ./fuzz
\```
**Expected output:** Coverage report showing 85%+ edge coverage
```

### Tables Over Prose

Prefer tables for structured information. They're scannable and reduce ambiguity.

```markdown
| Flag | Purpose |
|------|---------|
| `-fsanitize=fuzzer` | Enable coverage instrumentation |
| `-fsanitize=address` | Detect memory errors |
| `-g` | Include debug symbols for stack traces |
```

### Anti-Pattern Tables

For skills that teach methodology, include what NOT to do:

```markdown
## Anti-Patterns

| Anti-Pattern | Problem | Correct Approach |
|--------------|---------|------------------|
| Skip validation | False confidence | Always verify findings |
| Global state in harness | Non-deterministic | Reset state each iteration |
```

## Quality Checklist

Before delivering any generated skill:

### Structure
- [ ] Valid YAML frontmatter with `name` and `description`
- [ ] Name is kebab-case, ≤ 64 characters, no reserved words
- [ ] Description includes "Use when" or "Use for"
- [ ] "When to Use" section present with specific triggers
- [ ] "When NOT to Use" section present with clear boundaries
- [ ] Total line count < 500

### Content
- [ ] Explains WHY, not just WHAT
- [ ] At least one concrete example (input → output)
- [ ] Code blocks have language specifiers
- [ ] No hardcoded paths (`/Users/...`, `/home/...`)
- [ ] All internal file links resolve
- [ ] Behavioral guidance, not reference dumps

### Security Skills (additional)
- [ ] "Rationalizations to Reject" section present
- [ ] Phased workflow with quality gates
- [ ] Severity or risk classification framework
- [ ] Verification steps that prevent false confidence

### Plugin
- [ ] `plugin.json` has name, version, description, author
- [ ] Plugin `README.md` exists with skill table
- [ ] All referenced files exist
