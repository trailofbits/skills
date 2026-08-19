# PBT Libraries by Language

Match the project's existing choice. Introducing a second PBT library into a codebase
that already has one is not worth the property you wanted to write.

| Language | Default | Also in use |
|---|---|---|
| Python | Hypothesis | — |
| TypeScript / JavaScript | fast-check | — |
| Rust | proptest | quickcheck (simpler API, per-type shrinking) |
| Go | rapid | gopter (ScalaCheck-style, more explicit) |
| Java | jqwik | — |
| Scala | ScalaCheck | — |
| C# | FsCheck | — |
| Elixir | StreamData | — |
| Haskell | QuickCheck | Hedgehog (integrated shrinking, no type classes) |
| Clojure | test.check | — |
| Ruby | PropCheck | — |
| Kotlin | Kotest | — |
| C++ | RapidCheck | — |
| Swift | SwiftCheck | unmaintained — check before recommending |

Detect what a repo already uses before proposing anything:

```bash
rg "from hypothesis import|fast-check|use proptest|pgregory.net/rapid|net.jqwik|echidna_|invariant_"
```

## Smart contracts (EVM / Solidity)

This is where PBT earns the most, because contract state is adversarial and the input
domain is every possible call sequence. Trail of Bits maintains both tools:

- **Echidna** — property fuzzer, mature, the default choice.
- **Medusa** — parallel execution, coverage-guided; faster on large contract suites.

Two testing modes, and picking the wrong one is the usual mistake:

**Property mode** — a function returning `bool` that must never become false.

```solidity
// Echidna calls this after every transaction sequence.
function echidna_total_matches_sum() public view returns (bool) {
    return token.totalSupply() == trackedSum;
}
```

**Assertion mode** — an `assert` inside a function the fuzzer is allowed to call
directly, for properties about a specific operation rather than global state.

```solidity
function testDepositIncreasesBalance(uint256 amount) public {
    uint256 before = vault.balanceOf(address(this));
    vault.deposit(amount);
    assert(vault.balanceOf(address(this)) >= before);
}
```

### Contract invariants worth asserting

Solvency (`sum(balances) <= totalAssets`), supply conservation, access control (a
non-owner call sequence never reaches an owner-only state change), monotonic
counters, and round-trip on share/asset conversion (`convertToShares` then
`convertToAssets` never returns more than you put in).

### Tautologies specific to Solidity

Type bounds are not properties. `uint256 x >= 0` is always true, and so is
`address(this).balance >= 0` — the compiler guarantees it. Likewise a property that
only reads state the fuzzer cannot reach is vacuous: if no call sequence can enter
the branch, the invariant is never exercised. Check Echidna's coverage output rather
than assuming.

`echidna_` functions must be `view`/`pure` and take no arguments — a property that
mutates state silently changes what it is testing.

Tutorials: [secure-contracts.com](https://secure-contracts.com).
