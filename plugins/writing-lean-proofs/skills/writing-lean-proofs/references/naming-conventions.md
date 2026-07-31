# Naming conventions

Mathlib names are computable from statements. This matters doubly for LLMs:
a predictable scheme lets you *guess* the name of the lemma you need
(`add_le_add_left`, `mul_pos`, `isOpen_iUnion`) instead of searching, and
lets you name your own lemmas so others can guess them. Source: the official
[naming guide](https://leanprover-community.github.io/contribute/naming.html).

## Build the name from the conclusion

Translate the symbols of the conclusion via the standard dictionary:

| Symbol / concept | Name fragment |
|------------------|---------------|
| `+` | `add` |
| `*` | `mul` |
| `⁻¹` | `inv` |
| `≤` / `<` | `le` / `lt` |
| `=` / `≠` | `eq` / `ne` |
| `∘` | `comp` |
| `→` (in conclusion structure) | `of` (see below) |
| `↔` | `iff` |
| `¬` | `not` |
| `0` / `1` | `zero` / `one` |

So `a + b = b + a` is `add_comm`; `a * b = b * a` is `mul_comm`;
`a ≤ b → c + a ≤ c + b` involves `add_le_add_left`.

## Hypotheses come after `of`, in statement order

`of` separates the conclusion from the hypotheses; hypotheses are listed in
the order they appear, *not* reversed. `A → B → C` is named `C_of_A_of_B`:

```lean
theorem lt_of_le_of_lt : a ≤ b → b < c → a < c
--      ^conclusion  ^hyp1   ^hyp2
```

## Casing

| Kind | Case | Example |
|------|------|---------|
| Proofs / theorem names | `snake_case` | `add_comm`, `lt_of_le_of_lt` |
| `Prop`s, `Type`s, structures, classes, inductives | `UpperCamelCase` | `Monoid`, `IsOpen`, `Continuous` |
| Other terms of types (functions, instances, fields) | `lowerCamelCase` | `toFun`, `instAddNat` |

When an `UpperCamelCase` name is embedded in a `snake_case` theorem name, it
is referenced in `lowerCamelCase`: a lemma about `IsOpen` is
`isOpen_compl_iff`, a lemma about `IsCompact` is `isCompact_iUnion`.

## Practical guidance

- Name the lemma *after* its statement is final. A renamed hypothesis or
  reordered implication changes the correct name.
- If you cannot derive a name from the statement, the statement is probably
  not in canonical form — check the simp-normal-form conventions first
  (e.g., state with `<` rather than `>`, `x ≠ 0` rather than `¬x = 0` per
  local convention).
- The guide documents exceptions (interval lemmas, historically established
  names, associativity ambiguity); when extending an existing file, imitate
  its local naming before inventing.
- Namespaces carry part of the name: `Nat.add_comm`, `List.map_map`. State
  lemmas about type `T` in namespace `T` so dot-notation (`h.symm`,
  `hf.comp hg`) works.
