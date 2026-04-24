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

Seven bug classes that share a common investigative tool: **LSP `hover` / `goToDefinition` on expressions** to resolve widths, signedness, and type identities. The shared work is the type/width inventory at each expression of interest.

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

Keep results as `expr_sites`. For each site, note `path:line` and the surrounding expression text — you will `hover` on specific tokens only when a pass demands it.

---

## Phase B — Passes in order (reuse `expr_sites`)

Read and apply each sub-prompt in turn. Use `LSP hover` sparingly and only on expressions already in `expr_sites`.

1. **`PREC` — Operator precedence**
   Cheap, syntactic; run first to filter "this expression parses as you thought."

2. **`INT` — Integer overflow**
   Focus on allocation-size math and loop bounds drawn from `expr_sites`.

3. **`OOBCMP` — Out-of-bounds / signed-vs-unsigned comparisons**
   `hover` on both sides of comparisons flagged in `expr_sites`.

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

`hover`/`goToDefinition` results are cached by the LSP server but **not** by the model. Collect each expression's type info in a short working table (`expr → width × signedness`) and reuse across passes instead of re-hovering.
