# Fixture Answer Key

Ground truth for `fixtures/src/`. **Never copy this file into the directory under
analysis** — a run would read it instead of deriving the dimensions. An earlier
revision leaked a "this contract is dimensionally correct" NatSpec tag into
`StakingRewards.sol` and a run cleared the contract by quoting it, voiding the
precision measurement. Keep every claim here out of `src/`.

## The protocol

Cross-margin borrowing against a multi-asset collateral basket.

| Layer | Scale | File |
|---|---|---|
| Internal accounting | WAD, 1e18 | `libraries/FixedPointMath.sol` |
| Prices and the borrow index | RAY, 1e27 | `libraries/PriceLib.sol`, `InterestIndex.sol` |
| Raw token amounts | each asset's own decimals | `AssetRegistry.sol` |
| Uniswap v3 encoding | Q64.96, squares to Q192 | `UniV3Oracle.sol` |

**Two fixed-point scales coexist on purpose.** WAD accounting and RAY prices are
both correct in isolation; three of the five bugs live at the boundary between
them. Nothing in a single file is enough to see them.

## Planted bugs (5)

**Load-bearing design property: each planted bug lives in its own function, and no
two share one.** `validate_findings.py` matches by enclosing function name because
the annotation pass shifts line numbers. New bugs need a fresh function and an
entry in `PLANTED`.

### DIM-A — RAY borrow index consumed as WAD
`MarginVault.sol` :: `debtOf` · **CRITICAL** · cross-file

```solidity
uint256 index = interestIndex.currentIndex();
return principal.mulWadDown(index) / entryIndex[account];
```

`currentIndex()` returns RAY (`InterestIndex.borrowIndex` is initialised to
`PriceLib.RAY`). `mulWadDown` divides by 1e18, so the product is RAY-scaled and the
subsequent division by a RAY `entryIndex` collapses the result to a bare integer.
Correct form is `principal.mulDiv(index, entryIndex[account])`.

**Requires reading `InterestIndex.sol`** to learn the index is RAY, not WAD. There
is no local hint in `MarginVault`.

### DIM-B — repayment denominated in the wrong asset's decimals
`MarginVault.sol` :: `repaymentAmount` · **CRITICAL** · cross-file

```solidity
return registry.fromWad(collateralTokens[0], owedWad);
```

The debt is owed in `debtToken`, so the conversion must use that asset's decimals.
Using the first collateral asset's decimals scales by the wrong power of ten
whenever the two differ — an 18-decimal collateral against a 6-decimal debt asset
under-converts by 1e12.

**Requires the AssetRegistry model** plus noticing which asset the debt is in.
`borrow()` does the same conversion correctly with `debtToken`, so the contrast is
available to a careful reader but is not adjacent.

### DIM-C — Q192 value shifted as if Q96
`UniV3Oracle.sol` :: `priceOf` · **CRITICAL**

```solidity
uint256 ratio = uint256(sqrtPriceX96) * uint256(sqrtPriceX96);
return FixedPointMath.mulDiv(ratio, PriceLib.RAY, Q96);
```

Squaring a Q64.96 number yields Q128.192. Removing only one 96-bit shift leaves the
result larger than the true price by 2^96. Must divide by `1 << 192`.

Reads as textbook Uniswap v3 integration; the `Q96` constant name looks right.

### DIM-D — WAD fraction divided by a basis-point denominator
`MarginVault.sol` :: `protocolFee` · **HIGH**

```solidity
uint256 public borrowFee = 0.003e18;   // 0.3%
return amountWad.mulDiv(borrowFee, BPS_DENOMINATOR);
```

`borrowFee` is an 18-decimal fraction, so the divisor must be `WAD`. Dividing by
10,000 overstates the fee by 1e14. Both operands are plausible fee-shaped values
and `BPS_DENOMINATOR` reads correctly beside the word "fee".

### DIM-E — raw balances of different assets summed
`MarginVault.sol` :: `totalCollateralRaw` · **HIGH**

```solidity
for (uint256 i = 0; i < collateralTokens.length; i++) {
    total += IERC20(collateralTokens[i]).balanceOf(address(this));
}
```

Each balance is in its own asset's units and decimals, so the sum has no
dimension: adding 8-decimal WBTC to 18-decimal WETH is meaningless before both are
normalised via `registry.toWad` and priced. The loop looks like ordinary
book-keeping.

## False-positive controls

Correct code that superficially resembles a bug. Reporting these at CRITICAL or
HIGH is a precision failure.

| Site | Why it is correct |
|---|---|
| `PriceLib.valueOf` | `D18{tok} * D27{usd/tok} / RAY` = `D18{usd}`. Correct. |
| `PriceLib.mulRayDown` / `divRayDown` | Correct RAY algebra; the D54 intermediate is rescaled. |
| `FixedPointMath.mulWadDown` / `divWadDown` | Correct WAD algebra. The bugs are at call sites, not here. |
| `AssetRegistry.toWad` / `fromWad` | `10 ** (18 - decimalsOf(token))` is the correct normalisation both ways. |
| `InterestIndex.accrue` / `currentIndex` | Consistently RAY throughout; `mulRayDown` rescales correctly. |
| `MarginVault.collateralValue` | Normalises each asset with `toWad` and prices it per token. Correct. |
| `MarginVault.marginRatio` | `D18{usd} / D18{usd}` via `divWadDown` = `D18{1}`. Correct given its inputs. |
| `StakingRewards.sol` (whole file) | Dimensionally correct throughout; D36 intermediates rescaled by `PRECISION` on the same line. |

`InterestIndex.ratePerSecondRay = aprRay / SECONDS_PER_YEAR` is a correct
`RAY{1/year} / {s/year}` → `RAY{1/s}` conversion. Truncation dust there is a
rounding matter, not a dimensional one.

## Scoring

| Metric | Target |
|--------|--------|
| Recall on planted bugs | 5/5 — hard gate |
| CRITICAL/HIGH findings in `StakingRewards.sol` | 0 — hard gate |
| LOW/MEDIUM findings in `StakingRewards.sol` | counted, tolerated |
| Files annotated | reported only, never gated |

**The precision gate is asymmetric on purpose.** A missed dimensional bug ships to
a client; a spurious LOW costs a reviewer a moment. False negatives always fail,
low-severity noise on correct code is recorded and allowed, and only a false
CRITICAL or HIGH fails — that is the severity that derails an audit.

## Why this fixture replaced the previous one

The first fixture put every bug in one contract, each with a local tell: an unused
`SECONDS_PER_YEAR`, a correct `latestPriceWad()` sitting beside the wrong getter, a
`_wadToUsdc` byte-identical to its inverse. Baseline Sonnet found 5/5 without the
plugin in three isolated rounds, so the eval could not discriminate.

This fixture removes the tells and puts three of five bugs behind a cross-file
dimension chain — the RAY/WAD boundary, the registry's per-asset decimals, and the
Q96 encoding. The prompt was tightened in step: it no longer names the assets,
fixes the file scope, or prescribes annotation, so the vocabulary and scoping work
is no longer handed to the baseline.
