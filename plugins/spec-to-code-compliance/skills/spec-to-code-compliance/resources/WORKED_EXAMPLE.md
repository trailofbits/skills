# Worked Examples

Three requirements against real code shapes, one per verdict that is easy to get wrong. Read these for
calibration on how far to chase a requirement before deciding, not as a template to fill in.

---

## `implemented` — arithmetic that satisfies a requirement it does not resemble

> "The protocol charges a fixed 0.3% fee on the input amount for every swap."
> — Whitepaper §4.2

```solidity
// Router.sol:L108
uint256 amountInWithFee = amountIn * 997;
// Router.sol:L110-L111
amountOut = (amountInWithFee * reserveOut) / (reserveIn * 1000 + amountInWithFee);
```

Nothing here contains `fee`, `0.3`, or `30`. Searching the document's vocabulary finds the comment and stops.

The verdict rests on the arithmetic: the input is scaled by 997 and the denominator by 1000, so the fee is
`3/1000 = 0.3%`. Then three things decide whether it is `implemented` rather than `partial`. It is applied
before the output is computed, so it cannot be bypassed by the caller. It is a literal rather than a storage
read, so no admin path changes it. And there is no branch around it — every swap path passes through L108.

Record the equivalence in the analysis. The next reader should not have to rederive that 997/1000 is 0.3%, and
a divergence found later in the same formula will be checked against this note.

**The mistake to avoid:** reporting this as `undecidable` or `absent` because the fee is not named. Verify
arithmetic as arithmetic.

---

## `absent` — the searches are the finding

> "All swap operations MUST enforce a maximum slippage of 1% between expected and actual output."
> — Whitepaper §4.1

```solidity
// RouterV1.sol:L45
function swap(address tokenIn, address tokenOut, uint256 amountIn) external
```

The signature carries no `minAmountOut`, so there is nothing for the caller to express a tolerance with. That
observation alone is suggestive, not conclusive — enforcement could compute the bound internally from an oracle.

What makes the verdict credible is the record:

- `slippage` → 0 hits in `RouterV1.sol`
- `minAmount`, `minOut`, `limitPrice`, `maxDelta` → 0 hits (the document's word is not the code's word, so the
  synonyms are checked too)
- `require`, `revert` in `swap` → 2 hits, both at L47-L48 on `amountIn > 0` and `tokenIn != tokenOut`
- modifiers on `swap` → `nonReentrant` only
- oracle or TWAP reads → none in the file
- `calculateSwapOutput` (the one callee) → read in full; computes output, enforces nothing
- callers of `swap` → none in scope; it is an entrypoint

Six places it could have been, none of them holding it. That is an absence. Without the list it is a guess in
citation format.

**The mistake to avoid:** concluding `absent` after searching only the document's own vocabulary.

---

## `partial` — enforcement that exists on the path nobody tested

> "The parser MUST reject any frame whose declared length exceeds the remaining buffer."
> — RFC §4.3

```c
/* proto.c:L112-L124 */
int parse_frame(const uint8_t *buf, size_t len, frame_t *out) {
    if (len < HDR) return -1;
    uint32_t declared = read_u32(buf);
    if (buf[4] & FLAG_CONT) {
        out->len = declared;          /* L118 — no comparison against len */
        return 0;
    }
    if (declared > len - HDR) return -1;
    out->len = declared;
    return 0;
}
```

The bound is enforced at L121, so a reader who finds that check marks the requirement satisfied and moves on.
The continuation branch returns success at L119 having written `out->len` from attacker-controlled bytes without
comparing it to anything.

Two paths, one enforcing and one not, is `partial` — and the analysis has to name which. `contradicted` would
overstate it, because the requirement does hold for the common case; `implemented` would miss the finding
entirely. Then check the callers, because a caller that validates before calling would close it, and one that
trusts `out->len` after a zero return confirms it.

Also check the other build configurations. If `FLAG_CONT` handling is behind `#ifdef`, say which configuration
was read.

**The mistake to avoid:** stopping at the first check that matches the requirement. The first check is usually
the one on the path everyone tests.
