# Reviewing Property-Based Tests

A property test can pass for years while asserting nothing. These are the ways that
happens, worst first.

Report every issue you find with its severity attached. Do not decide on the author's
behalf that a MEDIUM is not worth mentioning.

| Issue | Severity | How it shows up |
|---|---|---|
| Tautological | CRITICAL | Assertion is true regardless of the implementation |
| Vacuous | CRITICAL | `assume()` filters out nearly everything, or contradicts itself |
| No assertion | HIGH | Body calls the function and stops |
| Reimplementation | HIGH | Assertion recomputes the function's own logic |
| Weaker property available | MEDIUM | Length checked, ordering not |
| Over-filtered | MEDIUM | Stacked `assume()` where a strategy constraint belongs |
| Settings | LOW | `max_examples=5`, or no deadline on an expensive strategy |

## Tautological

```python
@given(st.integers())
def test_useless(x):
    result = compute(x)
    assert result == result
```

Nothing about `compute` can make this fail.

**But `f(x) == f(x)` is not automatically tautological.** It is a real determinism
property whenever `f` is not obviously pure — serializers over dicts or sets, anything
touching iteration order, hashing, or time. `pickle.dumps(obj) == pickle.dumps(obj)`
genuinely fails for objects with a nondeterministic `__reduce__`. Ask whether a broken
implementation could falsify it. If yes, it is a property; if no, it is noise.

## Vacuous

```python
@given(st.integers())
def test_vacuous(x):
    assume(x > 100)
    assume(x < 50)
    assert compute(x) > 0
```

Hypothesis reports this as passing before it eventually errors on exhausted filters —
and in CI nobody reads the warning. `assume(x == 42)` is the subtler version: it runs,
it passes, and it is an example test wearing a `@given` decorator.

## Reimplementation

```python
@given(st.integers(), st.integers())
def test_reimplements(a, b):
    assert add(a, b) == a + b
```

If `add` is `a + b`, this asserts `a + b == a + b`. The test survives any bug the two
expressions share. Reach for an algebraic property instead — commutativity, identity,
associativity — which constrains the function without restating it.

## Finding the tests

```bash
rg "@given\(|from hypothesis import" --type py
rg "fc\.(assert|property)" --type ts --type js
rg "proptest!|#\[quickcheck\]" --type rust
```

## What to push for

Compare each test against the property catalog in SKILL.md and name the strongest
property the code supports but the suite does not assert. A suite that checks
`len(sort(xs)) == len(xs)` and never checks ordering is the common case.

Also worth flagging: floating-point equality without a tolerance, assertions on
dict/set iteration order, and anything reading the clock — these produce flakes that
get blamed on Hypothesis and then get deleted.
