# Blockchain-Specific Patterns

Blockchain-specific mutation testing patterns for Solidity, FunC/Tolk, Move, and Solana Rust codebases. These patterns extend the general equivalence catalog and severity criteria; where they disagree with the general guidance, the blockchain-specific rule wins for blockchain code.

---

## Blockchain-Specific Equivalent Mutants

Additional equivalence patterns beyond the general catalog.

### Revert String Mutations

**Pattern:** `require(condition, "error A")` mutated to `require(condition, "error B")`
**Observable difference:** The transaction reverts on the same inputs, but its returned error data changes. Treat this as a testing gap when callers or the documented interface depend on that data.
**Applies to:** Solidity `require`, `revert` with custom error messages

**Scope:** A property concerned only with whether the call reverts can ignore the message. State that restricted property explicitly. The absence of an assertion on error data does not make two different error messages semantically identical.

### Gas-Only Differences

**Pattern:** Mutation in a `view` or `pure` function that changes gas consumption but not the return value or state
**Scope:** Identical return values can establish equivalence for a property that explicitly excludes gas consumption, provided neither version runs out of gas. They do not establish identical behavior in every calling context.
**Applies to:** Solidity `view`/`pure` functions

**Not equivalent when:** The gas difference causes an out-of-gas revert that changes observable behavior, or the function is called in a state-changing context where gas matters.

### Modifier Ordering

**Pattern:** Swapping the order of two independent modifiers on a function
**When equivalent:** Both guards must be independent, and their order must preserve all relevant observable behavior. Check the error returned when both guards fail, as well as state effects and callbacks.
**Applies to:** Solidity function modifiers

**Not equivalent when:** The modifiers interact (e.g., one sets a flag that the other reads, or one can revert based on state the other modifies).

### Storage Packing

**Pattern:** Mutation to a type within the same storage slot that does not change the packed representation
**What to check:** An unchanged storage layout is insufficient. A type change can alter arithmetic, comparisons, or accepted values even when the stored bits match. Trace reads and writes before deciding whether behavior is equivalent.
**Caution:** This is very rare. Only classify as equivalent with concrete evidence of packing behavior.

---

## Blockchain Severity Examples

Concrete tier assignments for common on-chain constructs, using the same four tiers as the general severity criteria.

### Tier 1: Critical — Security-Sensitive

**Solidity:**
- `require(msg.sender == owner)` — ownership check
- `onlyRole(ADMIN_ROLE)` — role-based access control modifier
- `nonReentrant` modifier — reentrancy guard
- `ecrecover(hash, v, r, s)` — signature verification
- `require(deadline >= block.timestamp)` — time-based access control

**FunC/Tolk:**
- `throw_unless(ERR_UNAUTHORIZED, equal_slices(sender, owner))` — ownership check
- Bounce handler validation — message authentication

**Solana Rust:**
- `if !ctx.accounts.authority.is_signer` — signer check

### Tier 2: High — Financial/State Integrity

**Solidity:**
- `balances[to] += amount` — balance update
- `fee = amount * feeRate / DENOMINATOR` — fee calculation
- `require(ratio > MIN_COLLATERAL_RATIO)` — liquidation threshold
- `IERC20(token).safeTransfer(to, amount)` — token transfer
- `require(amountOut >= minAmountOut)` — slippage check

**FunC/Tolk:**
- `send_raw_message(msg, mode)` — value transfer via message
- Jetton transfer handler — token movement logic

**Solana Rust:**
- `account.lamports -= amount` — lamport transfer
- `pool.total_shares += new_shares` — share accounting

### Tier 3: Medium — Business Logic

**Solidity:**
- `require(proposalId < proposals.length)` — bounds check in governance
- `rewards[user] += calculateReward(...)` — non-critical reward distribution
- `if (queue.length > MAX_QUEUE_SIZE) revert()` — queue management

### Tier 4: Low — Observability

**Solidity:**
- `emit Transfer(from, to, amount)` — event emission
- `function balanceOf(...) view returns (uint256)` — view getter
- Error message string in `require(cond, "message")`

---

## Blockchain-Specific Ambiguous Cases

### Protocol Standard Compliance

If event emission is required by an ERC or similar blockchain standard (e.g., `Transfer` in ERC-20) and downstream contracts or indexers depend on it, consider **Tier 3** instead of Tier 4. This is stricter than the general case because on-chain protocol compliance is enforced by tooling and integrations.
