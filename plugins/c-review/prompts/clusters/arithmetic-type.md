---
name: cluster-arithmetic-type
kind: cluster
consolidated: false
covers:
  - integer-overflow       # INT
  - type-confusion         # TYPE
  - operator-precedence    # PREC
  - oob-comparison         # OOBCMP
  - null-zero              # NULLZERO
  - undefined-behavior     # UB
  - compiler-bugs          # COMP
---

# Cluster: Arithmetic & type

Seven bug classes that share a common investigative task: resolve widths, signedness, and type identities with `Grep`, `Read`, and nearby typedef/macro/struct definitions. The shared work is the type/width inventory at each expression of interest.

ID prefixes: `INT`, `TYPE`, `PREC`, `OOBCMP`, `NULLZERO`, `UB`, `COMP`.

---

## Phase A — Seed expressions of interest

Run once:

```
Grep: pattern="\\*\\s*\\w+\\s*[+\\-]|\\w+\\s*\\+\\s*\\w+\\s*\\*"  # multiplication near addition (classic overflow)
Grep: pattern="sizeof\\s*\\(\\s*\\w+\\s*\\)\\s*\\*|\\*\\s*sizeof"  # size*count allocations
Grep: pattern="\\b(int|long|short|ssize_t|off_t|int[0-9]+_t)\\b.*=.*[-+*]"  # signed arithmetic producing sizes
Grep: pattern="\\b(uint|ulong|ushort|size_t|uint[0-9]+_t)\\b.*=.*-"         # unsigned subtraction (wrap candidates)
Grep: pattern="\\((void\\s*\\*|char\\s*\\*|unsigned\\s+char\\s*\\*)\\)\\s*\\w"   # pointer casts
Grep: pattern="\\b(union)\\b"                                # tag-less unions
Grep: pattern="==\\s*NULL|!=\\s*NULL|==\\s*0|!=\\s*0"        # NULL-vs-zero comparison sites
Grep: pattern="!=\\s*-1|==\\s*-1|<\\s*0"                     # error-return comparisons
```

Keep results as `expr_sites`. For each site, note `path:line` and the surrounding expression text; resolve type details by reading definitions only when a pass demands them.

---

## Phase B — Passes in order (reuse `expr_sites`)

Read and apply each sub-prompt in turn. Use focused `Read`/`Grep` follow-ups only on expressions already in `expr_sites`.

1. **`PREC` — Operator precedence**
   Cheap, syntactic; run first to filter "this expression parses as you thought."

2. **`INT` — Integer overflow**
   Focus on allocation-size math and loop bounds drawn from `expr_sites`.

3. **`OOBCMP` — Out-of-bounds / signed-vs-unsigned comparisons**
   Resolve both sides of comparisons flagged in `expr_sites`.

4. **`NULLZERO` — NULL / zero confusion**
   Use the `==NULL`/`==0` subset of `expr_sites`.

5. **`TYPE` — Type confusion**
   Use the cast and union subsets of `expr_sites`.

6. **`UB` — Undefined behavior**
   Catches the long tail: sequence points, strict aliasing, signed shifts, etc.

7. **`COMP` — Compiler-bug-exposed issues**
   Run last — relies on UB/type/int findings for context.

---

## Deconfliction

Priority (higher wins):

1. `INT` > `PREC` (if the precedence issue is only interesting because it causes an overflow, file `INT`).
2. `OOBCMP` > `INT` (if the comparison is the bug, even though the operands overflow in theory).
3. `TYPE` > `UB` (if strict-aliasing UB, but the root cause is a bad cast, file `TYPE`).
4. `UB` > `COMP` (UB is the root cause; compiler bug is the amplifier).
5. `NULLZERO` is independent — doesn't collapse.

---

## Token-economy reminder

Collect each expression's type info in a short working table (`expr -> width x signedness`) and reuse it across passes instead of re-reading the same typedefs, macros, and struct definitions.

---

## Coverage gate (mandatory before `worker-N complete:`)

A previous run silently skipped `NULLZERO` and `TYPE` because their Phase-A seed greps either weren't issued or returned hits that were never followed up on. Before emitting the complete line, verify each pass below has a recorded outcome — either at least one finding filed, or one explicit "cleared because <reason grounded in code reads>" line in your run notes. **Saying "no candidates in `expr_sites`" is only a valid clearance if the corresponding Phase-A grep actually ran and returned empty.**

| Pass | Required Phase-A grep | Minimum outcome |
|---|---|---|
| `PREC` | multiplication-near-addition | finding OR explicit clear |
| `INT` | `sizeof(...)*` / `*sizeof` and signed/unsigned arithmetic | finding OR explicit clear |
| `OOBCMP` | `!=-1` / `==-1` / `<0` | finding OR explicit clear |
| `NULLZERO` | `==NULL` / `!=NULL` / `==0` / `!=0` — **MUST run** | finding OR explicit clear citing at least 2 inspected sites |
| `TYPE` | pointer casts AND `\b(union)\b` — **both MUST run** | finding OR explicit clear citing at least 2 inspected sites |
| `UB` | shift expressions, signed arithmetic | finding OR explicit clear |
| `COMP` | (no Phase-A seed; runs on prior findings) | finding OR explicit "no UB/INT/TYPE findings to amplify" |

If `NULLZERO` or `TYPE` would otherwise have *zero* recorded activity (no grep, no read, no clearance note), do **not** emit `complete:` — instead run the missing grep, inspect the top hits, and only then close out. The orchestrator counts a zero-finding worker as success only when the cluster was honestly exercised; silent skips of these two sub-prompts have produced false-negative runs in the past.
