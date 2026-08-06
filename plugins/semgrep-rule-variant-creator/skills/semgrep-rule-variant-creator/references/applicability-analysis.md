# Applicability Analysis

Phase 1 of the variant creation workflow. Before porting a rule, analyze whether the vulnerability pattern applies to the target language.

## Analysis Process

For EACH target language, answer these questions:

### 1. Does the Vulnerability Class Exist?

**Determine if the vulnerability type is possible in the target language.**

Examples:
- Buffer overflow: Applies to C/C++, may apply to Rust (in unsafe blocks), does NOT apply to Python/Java
- SQL injection: Applies to any language with database access
- XSS: Applies to any language generating HTML output
- Memory leak: Relevant in C/C++, less relevant in garbage-collected languages
- Type confusion: Relevant in dynamically typed languages, less relevant in strongly typed

### 2. Does an Equivalent Construct Exist?

**Identify what the original rule detects and find equivalents.**

Parse the original rule to identify:
- **Sinks**: What dangerous functions/methods does it detect?
- **Sources**: Where does tainted data originate?
- **Pattern type**: Is it taint-mode or pattern-matching?

Then research the target language:
- What are the equivalent dangerous functions?
- What are the common source patterns?
- Are there language-specific idioms to consider?

### 3. Are the Semantics Similar Enough?

**Verify the pattern translates meaningfully.**

Consider:
- Does the vulnerability manifest the same way?
- Are there language-specific mitigations that change detection needs?
- Would the ported rule provide actual security value?

## Verdict Format

Document your analysis for each target language:

```
TARGET: <language>
VERDICT: APPLICABLE | APPLICABLE_WITH_ADAPTATION | NOT_APPLICABLE
REASONING: <specific analysis>
ADAPTATIONS_NEEDED: <if APPLICABLE_WITH_ADAPTATION>
EQUIVALENT_CONSTRUCTS:
  - Original: <function/pattern>
  - Target: <equivalent function/pattern>
```

## Verdict Definitions

### APPLICABLE

The pattern translates directly with minor syntax adjustments.

**Criteria:**
- Equivalent constructs exist with same semantics
- Vulnerability manifests identically
- Detection logic remains the same

**Example:**
```
Original: Python os.system(user_input)
Target: Go exec.Command(user_input)

VERDICT: APPLICABLE
REASONING: Both execute shell commands with user input. Vulnerability is
identical (command injection). Detection logic (taint from input to exec)
translates directly.
```

### APPLICABLE_WITH_ADAPTATION

The pattern can be ported but requires significant changes.

**Criteria:**
- Vulnerability class exists but manifests differently
- Equivalent constructs exist but with different APIs
- Additional patterns needed for target language idioms

**Example:**
```
Original: Python pickle.loads(untrusted)
Target: Java ObjectInputStream.readObject()

VERDICT: APPLICABLE_WITH_ADAPTATION
REASONING: Both detect deserialization vulnerabilities but the APIs differ
significantly. Java requires detection of ObjectInputStream creation and
readObject() calls, not a single function call.
ADAPTATIONS_NEEDED:
  - Different sink patterns (readObject vs loads)
  - May need pattern-inside for ObjectInputStream context
  - Consider readUnshared() variant
```

### NOT_APPLICABLE

The pattern should not be ported to this language.

**Criteria:**
- Vulnerability class doesn't exist in target language
- No equivalent construct exists
- Pattern would be meaningless or misleading

**Example:**
```
Original: C strcpy/strncpy detection (CWE-676, use of a dangerous function)
Target: Python

VERDICT: NOT_APPLICABLE
REASONING: The rule detects an unbounded/bounded pair where a safer
replacement exists — strcpy -> strcpy_s, strncpy -> a variant that
NUL-terminates. Python has neither half. str and bytes are immutable and
length-prefixed, bytearray slice assignment resizes or raises, and there is
no NUL-termination contract to omit, so the ported sink would match only
memory-safe code.
```

Note what that reasoning does **not** say. "Python is memory-safe, so buffer
overflows cannot happen" is false, and reaching for it will get a verdict
overturned: `ctypes.memmove(create_string_buffer(8), b"B"*64, 64)` writes 64
bytes into an 8-byte buffer from pure Python and segfaults the interpreter.
The verdict holds on the sink, not on the language's reputation — `memmove` is
the analogue of `memcpy`, there is no `memmove_s` to recommend, and telling a
Python developer to use `strcpy_s` misattributes the finding. A `ctypes` rule
is worth writing; it is a different rule, not this one ported.

Reach for a language's safety reputation and you will overshoot. Check the
specific construct the rule names.

## Can Semgrep Analyze the Target at All?

Separate from the verdict, and answered by running Semgrep rather than from
memory. The three questions above ask whether the *bug* exists in the target.
This one asks whether Semgrep can *see* it, and a "no" stops the port however
applicable the pattern is.

```sh
semgrep show supported-languages          # is there a key for this language?
semgrep --dump-ast -l <key> probe.<ext>   # does the parser actually run?
```

Two ways it fails, both silent:

- **No frontend.** Perl is not a Semgrep language. Command injection is if
  anything worse there than in Python — `system("cmd $x")`, backticks, `qx{}`,
  two-arg piped `open` all reach `/bin/sh` — and CGI.pm, Plack and Mojolicious
  supply genuinely attacker-controlled sources. None of that matters: the only
  ways to touch a `.pl` file are `generic` and `regex`, neither of which has an
  AST or a dataflow engine, so `mode: taint` no-ops and returns zero findings at
  ~100% "parsed".
- **A Pro-only parser.** Elixir left OSS Semgrep in 1.51.0. A rule declaring
  `languages: [elixir]` is *skipped* rather than run: "1 rule(s) were skipped
  because they require Pro". Under `--test` that does **not** surface as a
  failure — the run ends in "All tests passed" over zero graded tests, which is
  why nothing downstream catches it and why this question has to be settled here
  by running semgrep rather than inferred from a green. The tempting fix — an
  older Semgrep that still ships the parser — produces a green nobody can
  reproduce.

Report this as `semgrepCanAnalyze`, and say which of the two questions is
failing. Folding "Semgrep cannot read this language" into `NOT_APPLICABLE`
claims the bug class is absent, which is a different and often false statement.

## Common Applicability Patterns

### Always Translate (Language-Agnostic Vulnerabilities)

These vulnerability classes exist across most languages:
- SQL injection (any language with DB access)
- Command injection (any language with shell execution)
- Path traversal (any language with file operations)
- SSRF (any language with HTTP clients)
- XSS (any language generating HTML)

### Sometimes Translate (Context-Dependent)

These require careful analysis:
- Deserialization: Different mechanisms per language
- Cryptographic weaknesses: Language-specific crypto libraries
- Race conditions: Depends on concurrency model
- Integer overflow: Depends on type system

### Rarely Translate (Language-Specific)

These are often NOT_APPLICABLE for other languages:
- Memory corruption (C/C++ specific)
- Type juggling (PHP specific)
- Prototype pollution (JavaScript specific)
- GIL-related issues (Python specific)

## Library-Specific Rules

When the original rule targets a third-party library:

### Step 1: Identify the Library's Purpose

What functionality does the library provide?
- ORM / Database access
- HTTP client/server
- Serialization
- Templating
- etc.

### Step 2: Research Target Language Ecosystem

For the target language, identify:
- Standard library equivalents
- Popular third-party libraries with same functionality
- Language-specific idioms for this functionality

### Step 3: Decide on Scope

Options:
- **Native constructs only**: Port to standard library equivalents
- **Popular library**: Port to the most common library in target ecosystem
- **Multiple variants**: Create separate rules for multiple libraries

**Recommendation**: Start with standard library or most popular option. Additional library variants can be created separately if needed.

## Analysis Checklist

Before proceeding past Phase 1:

- [ ] Parsed original rule and identified pattern type
- [ ] Identified sinks, sources, and sanitizers (if taint mode)
- [ ] Researched equivalent constructs in target language
- [ ] Documented verdict with specific reasoning
- [ ] If APPLICABLE_WITH_ADAPTATION, listed required changes
- [ ] If NOT_APPLICABLE, documented clear explanation

## Example Analysis

**Original Rule**: Python command injection via subprocess

```yaml
rules:
  - id: python-command-injection
    mode: taint
    languages: [python]
    pattern-sources:
      - pattern: request.args.get(...)
    pattern-sinks:
      - pattern: subprocess.call($CMD, shell=True, ...)
```

**Target**: Go

```
TARGET: Go
VERDICT: APPLICABLE_WITH_ADAPTATION

REASONING:
- Command injection exists in Go (vulnerability class present)
- Go uses exec.Command() and exec.CommandContext() for command execution
- Go doesn't have shell=True equivalent; commands run directly by default
- Shell execution in Go requires explicit bash -c wrapping

EQUIVALENT_CONSTRUCTS:
  - Original sink: subprocess.call(cmd, shell=True)
  - Target sinks:
    - exec.Command("bash", "-c", cmd)
    - exec.Command("sh", "-c", cmd)
    - exec.Command(cmd) when cmd comes from user input

ADAPTATIONS_NEEDED:
1. Different sink patterns for Go's exec package
2. Source patterns need Go HTTP handler equivalents (r.URL.Query(), r.FormValue())
3. Consider both direct exec.Command and shell-wrapped variants
```

**Target**: Java

```
TARGET: Java
VERDICT: APPLICABLE

REASONING:
- Command injection exists in Java (vulnerability class present)
- Java uses Runtime.exec() and ProcessBuilder for command execution
- Direct equivalent functionality available

EQUIVALENT_CONSTRUCTS:
  - Original sink: subprocess.call(cmd, shell=True)
  - Target sinks:
    - Runtime.getRuntime().exec(cmd)
    - new ProcessBuilder(cmd).start()

ADAPTATIONS_NEEDED:
- Source patterns need Java servlet equivalents (request.getParameter())
- Consider both Runtime.exec and ProcessBuilder patterns
```
