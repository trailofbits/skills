# Structured Input with FuzzedDataProvider

A target that takes several typed arguments — a string, a length, a flag — wastes most of
the fuzzer's inputs if the harness slices `data` by hand, because every mutation shifts the
byte offsets of everything after it. `atheris.FuzzedDataProvider` splits one `bytes` input
into typed values while keeping each draw stable under mutation.

## Basic Usage

```python
@atheris.instrument_func
def TestOneInput(data: bytes):
    fdp = atheris.FuzzedDataProvider(data)
    name = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 64))
    count = fdp.ConsumeIntInRange(1, 1000)
    strict = fdp.ConsumeBool()
    your_target_function(name, count, strict=strict)
```

Draw in a fixed order. Each call consumes from where the last one left off, so inserting or
reordering a call reinterprets every byte after it and devalues the corpus already built.

Ask for a size before the content it bounds, as above: an unbounded string lets the fuzzer
spend the whole buffer on one field and starve every draw after it.

## Method Reference

| Need | Call |
|------|------|
| Raw bytes | `ConsumeBytes(count)` |
| Text | `ConsumeUnicodeNoSurrogates(count)` |
| Text, including unpaired surrogates | `ConsumeUnicode(count)` |
| Bounded integer | `ConsumeIntInRange(min, max)` |
| Sized integer | `ConsumeInt(size)` (signed), `ConsumeUInt(size)` |
| Float | `ConsumeFloat()`, `ConsumeRegularFloat()` (no `NaN`/`Inf`), `ConsumeProbability()` |
| Flag | `ConsumeBool()` |
| Choice from a fixed set | `PickValueInList(values)` |
| Everything not yet consumed | `ConsumeBytes(fdp.remaining_bytes())` |

`remaining_bytes()` is an accessor, not a draw — it returns the count of unconsumed bytes and
consumes nothing. It is the one method here that is not named `Consume*`, and the only one
whose return value is a length rather than a value. Pass it to `ConsumeBytes` to drain the
buffer; using it directly hands your target an `int` where it expects `bytes`.

Prefer `ConsumeUnicodeNoSurrogates` unless you are specifically testing surrogate handling.
`ConsumeUnicode` may emit unpaired surrogates (U+D800–U+DFFF), which are legal in a Python
`str` but raise `UnicodeEncodeError` the moment the target encodes them — so a target that
encodes anywhere reports a crash on its own input handling rather than on your target's logic.

List variants take the element count first:

| Call | Produces |
|------|----------|
| `ConsumeIntList(count, bytes)` | `count` integers of `bytes` size each |
| `ConsumeIntListInRange(count, min, max)` | `count` integers in `[min, max]` |
| `ConsumeFloatList(count)` | `count` arbitrary floats, `NaN` and `Inf` included |
| `ConsumeRegularFloatList(count)` | `count` floats, never `NaN` or `Inf` |
| `ConsumeProbabilityList(count)` | `count` floats in `[0, 1]` |
| `ConsumeFloatListInRange(count, min, max)` | `count` floats in `[min, max]` |

## Running Out of Input

Every method degrades rather than raising when the buffer empties: consumers return empty
values, and `ConsumeIntInRange` returns `min`. A harness that draws more than the fuzzer
supplies will not error — it will quietly test the same degenerate case over and over, which
looks like a healthy campaign that has stopped finding anything. Check `remaining_bytes()`
and return early if your harness needs a minimum amount of input.
