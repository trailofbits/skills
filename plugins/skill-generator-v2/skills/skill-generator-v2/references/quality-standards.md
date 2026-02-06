# Quality Standards

Design patterns and quality requirements for generated skills, combining proven patterns from 50+ Trail of Bits production skills with techniques from SkillForge, Superpowers, Panaversity, and other high-quality skill generators.

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

## Thinking Lenses

Before writing skill content, analyze the topic through at least 4 of these 6 lenses. This prevents shallow skills that miss edge cases, failure modes, and scope boundaries.

### The 6 Lenses

#### 1. First Principles

**Question:** What is the irreducible core of this topic? Strip away conventions, tools, and frameworks — what fundamental problem does this solve?

**How to apply:**
- Decompose the topic into its atomic components
- Ask "why?" at each level until you reach bedrock
- The irreducible core becomes the skill's central organizing principle

**Example:** For a fuzzing skill, the irreducible core is: "systematically exploring input space to find inputs that trigger unintended behavior." Everything else (AFL++, libFuzzer, harnesses) is implementation detail.

**What it produces:** Clear "When to Use" sections, focused scope, decision trees that decompose from first principles.

#### 2. Inversion

**Question:** What would a BAD skill for this topic look like? What would make someone worse at this topic after reading it?

**How to apply:**
- List everything that would make the skill harmful or misleading
- Flip each item — those become quality requirements
- Common bad-skill traits: too vague, false confidence, wrong mental model, missing caveats

**Example:** A bad Frida skill would teach hooking syntax without explaining when hooking is the wrong approach (use static analysis instead), give examples that only work on non-stripped binaries, and skip error handling.

**What it produces:** Strong "When NOT to Use" sections, caveats, anti-patterns.

#### 3. Pre-Mortem

**Question:** Assume the skill was deployed and failed — a user followed it and got bad results. Why did it fail?

**How to apply:**
- Imagine 3 failure scenarios with different root causes
- For each: what assumption was wrong? What step was missing? What edge case was hit?
- Build defenses against each failure into the skill

**Example failure scenarios:**
1. User followed the fuzzing skill but got zero coverage — skill didn't mention that the target needs to be compiled with instrumentation
2. User found a "vulnerability" that was actually a false positive — skill didn't include verification steps
3. User's harness crashed on startup — skill assumed library was already installed

**What it produces:** Prerequisites sections, verification steps, troubleshooting tables, quality checklists.

#### 4. Devil's Advocate

**Question:** What would a skeptic say about this skill's value? Why might someone argue it shouldn't exist?

**How to apply:**
- Argue against the skill's existence: "Claude already knows this," "the official docs are better," "this is too niche"
- If you can't rebut the objection, the skill needs strengthening
- Valid objections should be addressed in the skill itself

**Example objections:**
- "Claude already knows how to use git" → Skill must add judgment, workflow, and anti-patterns beyond basic commands
- "The Semgrep docs are comprehensive" → Skill must teach WHEN to use Semgrep vs. alternatives, not repeat the docs

**What it produces:** Value-add validation, unique content that justifies the skill's existence.

#### 5. Second-Order Thinking

**Question:** If Claude follows this skill perfectly, what side effects occur? What happens downstream?

**How to apply:**
- Trace the consequences of each instruction 2-3 steps forward
- Look for unintended outcomes: performance issues, maintenance burden, false sense of security
- Add warnings for second-order effects

**Example:** A skill that teaches "always add input validation" might cause Claude to add redundant validation layers throughout a codebase, degrading readability. Second-order fix: "Validate at system boundaries, trust internal code."

**What it produces:** Scope boundaries, caveats about overuse, nuanced guidance.

#### 6. Constraints Analysis

**Question:** What can't this skill cover? What are its hard limits?

**How to apply:**
- List what's explicitly out of scope
- Identify platform/language/environment limits
- Name the boundaries where this skill ends and another begins

**Example:** A YARA skill can't cover: malware analysis methodology (separate domain), incident response workflow (different skill), or binary reverse engineering (prerequisite knowledge assumed).

**What it produces:** "When NOT to Use" boundaries, related skill references, prerequisite lists.

### How to Apply Lenses

1. **Choose at least 4 lenses** (all 6 for audit/security skills)
2. **For each lens:** Write 2-3 bullet points answering the core question
3. **Probe deeper:** Continue until 2 consecutive rounds yield no new insights
4. **Record outputs** as internal notes (not included in the final skill)
5. **Feed insights** into specific sections:

| Lens | Feeds Into |
|------|-----------|
| First Principles | Decision trees, core workflow structure |
| Inversion | "When NOT to Use", anti-patterns |
| Pre-Mortem | Prerequisites, troubleshooting, verification steps |
| Devil's Advocate | Value-add content, unique guidance beyond reference docs |
| Second-Order Thinking | Caveats, scope boundaries, "don't overuse" warnings |
| Constraints Analysis | "When NOT to Use", related skills, out-of-scope declarations |

## Timelessness Scoring

Every generated skill must be evaluated for durability. Skills that pin to current tool versions or transient patterns become stale quickly.

### Scoring Rubric

| Question | Points |
|----------|--------|
| Does it reference specific version numbers without "or later"? | -1 per pinned version |
| Does it teach durable concepts vs. memorize current syntax? | +2 for conceptual, 0 for syntax-heavy |
| Would a tool upgrade break this skill's core guidance? | -2 if yes, +1 if resilient |
| Does it delegate version-specific details to official docs? | +1 for each delegation |
| Will the "When to Use" scenarios still exist in 2 years? | +2 if yes, -1 if trend-dependent |
| Does it explain the "why" behind tool choices? | +1 for reasoned choices, 0 for arbitrary |

**Baseline: 5/10.** Add/subtract based on the questions above.

**Target: >= 7/10.**

### How to Improve Timelessness

| Problem | Fix |
|---------|-----|
| Pinned version: "Use AFL++ 4.09c" | "Use the current AFL++ release (see [official repo])" |
| Syntax-dependent: "Run `afl-fuzz -i in -o out`" | Keep the command but explain each flag and why |
| Trend-dependent: "Use this for serverless functions" | Generalize to "event-driven architectures" |
| Hardcoded config | Show the pattern, link to docs for current defaults |

### Version Notes Pattern

For skills with version-specific content, use this pattern:

```markdown
## Version Notes

This skill was written against {tool} v{version}. Core concepts are
version-independent, but specific flags and configuration may change.
See [{tool} changelog]({url}) for breaking changes.

| Version | Notable Changes |
|---------|----------------|
| v{X} | {What changed and how it affects this skill} |
```

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

Equally important — prevents false activation and wasted effort. Thinking lenses (Inversion + Constraints) should feed directly into this section.

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
- [ ] Name is kebab-case, <= 64 characters, no reserved words
- [ ] Description includes "Use when" or "Use for"
- [ ] "When to Use" section present with specific triggers
- [ ] "When NOT to Use" section present with clear boundaries
- [ ] Total line count < 500

### Content
- [ ] Thinking lenses applied (at least 4 of 6)
- [ ] Explains WHY, not just WHAT
- [ ] At least one concrete example (input → output)
- [ ] Code blocks have language specifiers
- [ ] No hardcoded paths (`/Users/...`, `/home/...`)
- [ ] All internal file links resolve
- [ ] Behavioral guidance, not reference dumps

### Timelessness
- [ ] Timelessness score >= 7/10
- [ ] No pinned versions without "or later" or official docs link
- [ ] Core guidance survives tool upgrades
- [ ] "When to Use" scenarios are durable, not trend-dependent

### Security Skills (additional)
- [ ] "Rationalizations to Reject" section present
- [ ] Phased workflow with quality gates
- [ ] Severity or risk classification framework
- [ ] Verification steps that prevent false confidence

### Plugin
- [ ] `plugin.json` has name, version, description, author
- [ ] Plugin `README.md` exists with skill table
- [ ] All referenced files exist
- [ ] Duplicate detection was run before generation
