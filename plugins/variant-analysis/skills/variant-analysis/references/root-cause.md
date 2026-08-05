# Root Cause and Expansion Axes

Strategy for the first stage of a variant hunt: turning one known bug into the set of
independent directions worth searching. Everything downstream is calibrated against what
you produce here, so a shallow root cause caps the quality of the entire hunt.

## Why Variants Exist

Vulnerabilities cluster because developers make consistent mistakes:

1. **Developer habits**: the same person writes similar code and makes similar errors
2. **Copy-paste propagation**: boilerplate spreads a bug across the codebase
3. **API misuse patterns**: complex APIs invite consistent misunderstandings
4. **Framework idioms**: framework patterns create predictable vulnerability shapes
5. **Incomplete fixes**: the original bug was fixed in one place and missed elsewhere

Understanding WHY a variant exists predicts WHERE to find it. A copy-paste bug clusters in
sibling files; an API misuse bug clusters at every call site of that API, anywhere.

## Extracting the Root Cause

Ask these four questions before writing anything:

1. **What operation is dangerous?** (`eval()`, `system()`, raw SQL, an authorization check)
2. **What data makes it dangerous?** (user-controlled input, a null, an attacker-chosen size)
3. **What's missing?** (sanitization, validation, a bounds check, a null guard)
4. **What context enables it?** (authentication state, an error path, a specific caller)

Then formulate a statement:

> "This vulnerability exists because [UNTRUSTED DATA] reaches [DANGEROUS OPERATION]
> without [REQUIRED PROTECTION]."

Examples:
- "User input reaches `eval()` without sanitization"
- "Attacker-controlled size reaches `malloc()` without an overflow check"
- "Untrusted path reaches `open()` without canonicalization"

For logic bugs that have no data flow, state the violated invariant instead: "this function
must return False for unauthenticated callers, and it returns True when both IDs are null."

That statement IS the search pattern. Everything below expands it.

## The Expansion Checklist

A single root cause manifests in several ways. Enumerate all of them before searching.

### 1. Semantically related identifiers

If the bug involves one name, every name that plays the same role is in scope:

- `isAuthenticated`: also `isActive`, `isAdmin`, `isVerified`, `isLoggedIn`
- `userId`: also `ownerId`, `creatorId`, `authorId`

Ground these in the codebase. Grep for the names before claiming them: a list of plausible
identifiers that don't exist wastes an entire search axis.

### 2. Other boolean-logic errors

The same mistake in a different shape:

- Inverted conditions (`if not x` where `if x` was meant)
- Wrong default return (`return True` on the fall-through path)
- Short-circuit evaluation errors (`or` where `and` was meant)

### 3. Data-type edge cases

- Null/None/undefined comparisons, especially where *both* sides can be null
- Empty string vs null
- Zero vs null
- Empty arrays and collections

### 4. Documentation/code mismatches

A function whose behavior contradicts its own name or docstring. Search for functions named
with `deny`, `restrict`, `block`, `forbid`, `check`, `validate` and confirm the return value
means what the name says.

## What Makes a Good Axis

Each axis is handed to a separate agent that knows nothing about the others. So an axis must be:

- **Independently searchable** — it names concrete identifiers or code constructs to look for,
  not a theme like "authorization problems"
- **Non-overlapping** — two axes that find the same code waste an agent
- **Grounded** — its leads exist in this codebase

## Pitfalls at This Stage

**Pattern too specific.** Using only the exact attribute from the original bug misses
variants built on related constructs. Enumerate the whole family, not the one instance.

**Single vulnerability class.** Focusing on one manifestation misses the others. A
"returns allow when the condition is false" bug also hides as a null-equality bypass, a
docs/code mismatch, and an inverted conditional. List every manifestation before searching.

**Ungrounded axes.** Plausible-sounding identifiers that don't appear in the codebase
produce an agent that searches hard and finds nothing.
