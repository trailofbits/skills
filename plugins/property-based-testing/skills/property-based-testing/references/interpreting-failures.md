# Interpreting Property-Based Test Failures

A property test that fails has told you one of three things, and they need different
responses:

- **The property is wrong** — you asserted something the code never promised.
- **The spec is ambiguous** — behaviour at this edge was never decided.
- **The code is wrong** — a documented guarantee is violated.

Most of the work is telling them apart. Skipping that step is how PBT gets a
reputation for noise.

## Ground the property before you trust the failure

Shrunk input in hand, check what the code actually promises. In descending order of
authority:

| Source | What it settles |
|---|---|
| External spec (RFC, format definition) | The real contract, when one exists |
| Type annotations | Return type, nullability, domain |
| Docstrings | Explicit guarantees and preconditions |
| Existing tests | The contract maintainers believe they have |
| Function name | Weak, but `sort` really does imply ordering |

The name is the weakest signal and the one most likely to mislead you — plenty of
functions called `normalize` do something narrower than the word suggests.

Worked example. Hypothesis reports `test_normalize(s='\x00')` failing idempotence:

```python
def normalize(s: str) -> str:
    """Normalize a string to NFC form.

    Args:
        s: Input string (any unicode)
    Returns:
        NFC-normalized string
    """
```

"Any unicode" includes null bytes, so the input is in-domain and the property is
grounded. This one is a real bug.

Change the docstring to "ASCII printable only" and the same failure becomes a
strategy bug — the fix is `st.text(alphabet=...)`, not a bug report.

## Classification

| Symptom | Cause | Action |
|---|---|---|
| Violates a documented guarantee | Code bug | Report with the shrunk input and a quote from the doc |
| Input violates a documented precondition | Over-broad strategy | Constrain the strategy |
| Property contradicts the docstring or type | Wrong property | Fix the property |
| Edge case the spec never addresses | Ambiguous spec | Ask the maintainer; a discussion, not a bug report |
| Disappears under realistic constraints | Test artifact | Fix the strategy |
| Behaviour differs from a sibling function | Possible inconsistency | Worth raising, flag the uncertainty |

Precondition violations and explicitly-undefined behaviour are not bugs. Passing `-1`
to a function documented as taking positive integers tells you nothing.

Report what you find with the classification attached, including the cases you are
unsure about — say "ambiguous spec, needs a maintainer decision" rather than staying
quiet. A suppressed finding cannot be triaged by anyone else.

## Failure patterns that recur

**Lone surrogates break text roundtrips.** `decode(encode(s)) == s` fails on
`'\uD800'`. Whether that is a bug turns entirely on whether the format claims to
accept arbitrary `str` or only valid UTF-8.

**Denormals break numeric invariants.** A probability function returning a negative
value for `x=1e-320` is a genuine bug against a documented `[0, 1]` range, and it is
exactly the input no human writes by hand.

**Hash/equality divergence violates a language contract**, not just a docstring —
`a == b` must imply `hash(a) == hash(b)` in Python. No grounding required; report it.

**Off-by-one in custom iterators** shows up as `list(it(xs)) == xs` dropping the last
element. Almost always real.
