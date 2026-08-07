# Searching: The Abstraction Ladder

Strategy for the sweep stage. You have a root cause and one axis to search. The job is to
climb from a pattern that matches only the known bug to one that matches its variants,
without climbing so far that the results become noise.

## Tool Selection

| Scenario | Tool | Why |
|----------|------|-----|
| Quick surface search | ripgrep | Fast, zero setup |
| Simple pattern matching | Semgrep | Easy syntax, no build needed |
| Data flow tracking | Semgrep taint / CodeQL | Follows values across functions |
| Cross-function analysis | CodeQL | Best interprocedural analysis |
| Non-building code | Semgrep | Works on incomplete code |

Use ripgrep for recon, Semgrep for iteration, CodeQL for precision. Tool loyalty is an
anti-pattern: "I only use CodeQL" costs you the fast passes that tell you where to aim it.

## The Ladder

### Level 0: Exact match

Match the literal vulnerable code.

```python
# Original vulnerable code
query = "SELECT * FROM users WHERE id=" + request.args.get('id')
```

```bash
rg 'SELECT \* FROM users WHERE id=" \+ request\.args\.get'
```

Matches 1, zero false positives. This is not a search, it is the calibration point that proves your understanding of the bug is correct.

### Level 1: Variable abstraction

Replace variable names with metavariables.

```yaml
pattern: $QUERY = "SELECT * FROM users WHERE id=" + $INPUT
```

Matches 3-5, low FP. Finds copy-paste variants.

### Level 2: Structural abstraction

Generalize the surrounding structure.

```yaml
patterns:
  - pattern: $Q = "..." + $INPUT
  - pattern-inside: |
      def $FUNC(...):
        ...
        cursor.execute($Q)
```

Matches 10-30, medium FP. Finds pattern variants.

### Level 3: Semantic abstraction

Abstract to the security property itself.

```yaml
mode: taint
pattern-sources:
  - pattern: request.args.get(...)
  - pattern: request.form.get(...)
pattern-sinks:
  - pattern: cursor.execute(...)
```

Matches 50-100+, high FP. Comprehensive coverage, requires real triage.

### Choosing your level

| Goal | Level |
|------|-------|
| Verify a specific fix | 0 |
| Find copy-paste bugs | 1 |
| Audit a component | 2 |
| Full security assessment | 3 |

## One Change at a Time

Never generalize multiple elements at once.

```
BAD:  exact code -> fully abstract pattern
GOOD: exact code -> abstract var1 -> abstract var2 -> abstract operation
```

Each step: make ONE change, run it, read ALL new matches, decide whether the FP rate is
still acceptable, then continue or revert. Jumping straight to Level 3 produces a pile of
results with no way to tell which abstraction introduced the noise.

### Decision points

**Abstract this variable name?** Yes if different names could carry the same bug. No if the
name itself is the semantic constraint you are relying on.

**Abstract this literal?** Yes if any value triggers the bug. No if only specific values are
dangerous.

**Use `...` wildcards?** Yes if argument position doesn't matter. No if only a specific
position is a sink.

**Add taint tracking?** Yes if you need to prove data actually flows from source to sink. No
if the presence of the pattern is already sufficient evidence.

## Search Scope

Run every search against the **entire codebase root**, not the directory the original bug
lived in. A bug found in `api/handlers/` with a variant in `utils/auth.py` is the normal
case, not the exotic one. Narrow scope is the single most common reason a hunt finds nothing.

## False Positive Management

### Acceptable rates by context

| Context | Acceptable FP rate |
|---------|-------------------|
| Automated CI blocking | <5% |
| Developer warning | <20% |
| Security audit triage | <50% |
| Research/exploration | <80% |

For a variant hunt, stop generalizing when more than roughly half the matches are noise.
That is the signal you climbed one level too far: revert and take a different abstraction
rather than pushing further up the same one.

### Common FP sources and filters

**Test code** — exclude test trees:
```bash
rg "pattern" --glob '!**/test*' --glob '!**/*_test.*'
```

**Already sanitized** — subtract the safe form:
```yaml
pattern-not: dangerous_func(sanitize($X))
```

**Literal values** — not attacker-controlled:
```yaml
pattern-not: dangerous_func("...")
```

**Dead code** — add reachability constraints:
```yaml
pattern-not-inside: |
  if False:
    ...
```

Analyze false positives as you go rather than deferring them. They tell you which
abstraction was too aggressive, which is information you lose if you triage in a batch at the end.
